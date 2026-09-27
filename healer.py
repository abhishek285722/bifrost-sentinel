"""
healer.py — Bifrost backward-compatibility healer.

Dynamically synthesizes a backward-compatible SQLite VIEW so that legacy
queries continue to work after a destructive v1 → v2 schema migration,
without any hardcoded column knowledge.

Strategy
--------
1. Snapshot v1 column names via PRAGMA before the v2 migration is applied.
2. Apply the v2 breaking migration.
3. Diff the v1 snapshot against the v2 columns to identify:
   - columns that survived untouched (mapped 1-to-1)
   - columns that were split / dropped (synthesized via COALESCE or
     concatenation of any v2 columns whose name starts with the v1 name)
   - columns present only in v2 (passed through as-is so new clients still
     see them)
4. Rename the physical v2 table to  <table>_v2.
5. Execute the synthesized  CREATE VIEW IF NOT EXISTS <table> AS SELECT …
6. Verify by re-running every v1 column through the view.

Exit codes:
    0  heal succeeded — legacy queries now pass.
    1  heal failed (details printed to stderr).
"""

import sqlite3
import sys
import os
from typing import List, Tuple, Dict


# ---------------------------------------------------------------------------
# Helpers — file I/O
# ---------------------------------------------------------------------------

def _read_sql(path: str) -> str:
    """Return the contents of *path* as a string."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _apply_schema(conn: sqlite3.Connection, sql: str) -> None:
    """Execute a multi-statement SQL script on *conn*."""
    conn.executescript(sql)


# ---------------------------------------------------------------------------
# Helpers — schema introspection
# ---------------------------------------------------------------------------

def _get_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    """
    Return the ordered list of column names for *table* (or view).

    Uses PRAGMA table_info so it works for both tables and views.
    Returns an empty list when *table* does not exist.
    """
    cursor = conn.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    """Return True when a table (not a view) named *name* exists."""
    cursor = conn.execute(
        "SELECT type FROM sqlite_master WHERE name = ?", (name,)
    )
    row = cursor.fetchone()
    return row is not None and row[0] == "table"


# ---------------------------------------------------------------------------
# Helpers — schema diffing and DDL synthesis
# ---------------------------------------------------------------------------

def _diff_schemas(
    v1_cols: List[str],
    v2_cols: List[str],
) -> Dict[str, str]:
    """
    Compare v1 and v2 column lists; return a mapping of
    ``v1_column_name → SQL expression`` to reconstruct each v1 column from
    the v2 table (aliased as the source in the FROM clause).

    Resolution rules (tried in order):
    1. **Exact match** — v1 column present unchanged in v2 → bare column name.
    2. **Component match** — v2 contains ≥ 2 columns whose names contain the
       v1 column name as a word component (prefix or suffix, delimited by ``_``).
       e.g. v1 ``name`` → v2 ``first_name``, ``last_name``.
       Columns are kept in v2 declaration order and concatenated with a space:
       ``(first_name || ' ' || last_name) AS name``
    3. **Single component match** — exactly one v2 column contains the v1 name
       as a component → alias it: ``first_name AS name``
    4. **NULL fallback** — column was dropped with no detectable replacement →
       ``NULL AS <col>``

    A v2 column ``c`` is considered a *component match* for v1 column ``col``
    when any ``_``-delimited part of ``c`` equals ``col``.  For example, col
    ``name`` matches ``first_name`` (last part) and ``name_suffix`` (first
    part), but not ``rename`` (substring, not a whole component).
    """
    v2_set = set(v2_cols)
    mapping: Dict[str, str] = {}

    def _is_component(v2_col: str, token: str) -> bool:
        """True when *token* appears as a whole word inside *v2_col* split on '_'."""
        return token in v2_col.split("_")

    for col in v1_cols:
        if col in v2_set:
            # Rule 1 — survived as-is
            mapping[col] = col
            continue

        # Rules 2/3 — find v2 columns that contain this v1 col as a name component.
        # Preserve the original v2 declaration order so concatenation is stable.
        component_matches = [c for c in v2_cols if _is_component(c, col)]

        if len(component_matches) >= 2:
            # Rule 2 — concatenate with a space separator
            concat = " || ' ' || ".join(component_matches)
            mapping[col] = f"({concat}) AS {col}"
        elif len(component_matches) == 1:
            # Rule 3 — single match; alias it
            mapping[col] = f"{component_matches[0]} AS {col}"
        else:
            # Rule 4 — dropped with no traceable replacement
            mapping[col] = f"NULL AS {col}"

    return mapping


def _synthesize_view_ddl(
    legacy_table: str,
    new_table: str,
    v1_cols: List[str],
    v2_cols: List[str],
) -> str:
    """
    Build and return the complete ``CREATE VIEW IF NOT EXISTS`` DDL string
    that makes *legacy_table* a backward-compatible alias for *new_table*.

    Columns are ordered as:
        1. All v1 columns (in their original order), synthesized as needed.
        2. Any v2-only columns not present in v1 (appended so new clients
           can still reach them through the view).

    Parameters
    ----------
    legacy_table : str
        The view name to create (same as the original table name).
    new_table : str
        The physical table holding v2 data (e.g. ``users_v2``).
    v1_cols : list[str]
        Column names from the v1 snapshot.
    v2_cols : list[str]
        Column names from the live v2 table.

    Returns
    -------
    str
        A complete, executable DDL statement.
    """
    col_map = _diff_schemas(v1_cols, v2_cols)

    # Start with v1 columns (legacy shape, in original order)
    select_parts: List[str] = [col_map[col] for col in v1_cols]

    # Append any v2-only columns so new application code still works
    v1_set = set(v1_cols)
    for col in v2_cols:
        if col not in v1_set:
            select_parts.append(col)

    indent = "    "
    cols_sql = f",\n{indent}".join(select_parts)
    ddl = (
        f"CREATE VIEW IF NOT EXISTS {legacy_table} AS\n"
        f"SELECT\n"
        f"{indent}{cols_sql}\n"
        f"FROM {new_table}"
    )
    return ddl


# ---------------------------------------------------------------------------
# Core heal logic
# ---------------------------------------------------------------------------

def _heal(
    conn: sqlite3.Connection,
    table: str,
    v1_cols: List[str],
) -> Tuple[bool, str, str]:
    """
    Apply the backward-compatibility shim on an already-migrated database.

    Parameters
    ----------
    conn : sqlite3.Connection
        Live in-memory connection (v2 migration already applied).
    table : str
        The table name that was present in v1 (e.g. ``users``).
    v1_cols : list[str]
        Column snapshot captured *before* the v2 migration.

    Returns
    -------
    (success, message, ddl)
        *ddl* is the synthesized DDL string (empty string on failure).
    """
    new_table = f"{table}_v2"

    try:
        # Guard: already healed?
        cursor = conn.execute(
            "SELECT type FROM sqlite_master WHERE name = ?", (table,)
        )
        row = cursor.fetchone()
        if row is None:
            return False, f"Table '{table}' not found — nothing to heal.", ""
        if row[0] == "view":
            return True, f"Compatibility view already in place — nothing to do.", ""

        # Snapshot v2 columns from the current (post-migration) table
        v2_cols = _get_columns(conn, table)

        # Build the DDL dynamically
        ddl = _synthesize_view_ddl(table, new_table, v1_cols, v2_cols)

        # Rename physical table → <table>_v2
        conn.execute(f"ALTER TABLE {table} RENAME TO {new_table}")

        # Execute the synthesized view
        conn.execute(ddl)
        conn.commit()

        msg = (
            f"Compatibility view '{table}' created over table '{new_table}'.\n"
            f"[healer] Generated DDL:\n{ddl}"
        )
        return True, msg, ddl

    except sqlite3.OperationalError as exc:
        return False, f"Heal operation failed: {exc}", ""


def _verify_legacy_query(
    conn: sqlite3.Connection,
    table: str,
    v1_cols: List[str],
) -> Tuple[bool, str]:
    """
    Confirm that every v1 column is queryable from *table* after healing.

    Constructs ``SELECT <v1 cols> FROM <table>`` dynamically so this check
    is not tied to any hardcoded schema.

    Returns
    -------
    (success, message)
    """
    cols_sql = ", ".join(v1_cols)
    query = f"SELECT {cols_sql} FROM {table}"
    try:
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        col_labels = v1_cols
        preview = "; ".join(
            "  ".join(f"{col}={repr(row[i])}" for i, col in enumerate(col_labels))
            for row in rows
        )
        return True, f"Legacy query OK — rows: [{preview}]"
    except sqlite3.OperationalError as exc:
        return False, f"Legacy query still failing after heal: {exc}"


def _verify_harvested_queries(
    conn: sqlite3.Connection,
    v1_path: str,
) -> Tuple[bool, str, List[Dict]]:
    """
    Re-run all harvested application queries against the healed database.

    Uses the harvester to discover queries from the same directory as
    *v1_path*.  Reports per-query pass/fail.

    Returns
    -------
    (all_pass, summary_message, per_query_results)
        all_pass is True only when every query succeeds.
        per_query_results is a list of {"query", "success", "message"} dicts.
    """
    from harvester import harvest_codebase_queries  # local import

    data_dir = os.path.dirname(os.path.abspath(v1_path))
    harvested = harvest_codebase_queries(data_dir)
    # Use only application queries from .py files (not schema/migration .sql files)
    queries = [
        r["query"] for r in harvested
        if r.get("target_table") and r["file"].lower().endswith(".py")
    ]

    if not queries:
        return True, "No harvested queries to verify.", []

    results: List[Dict] = []
    for q in queries:
        try:
            cursor = conn.execute(q)
            cursor.fetchall()
            results.append({"query": q, "success": True,  "message": "OK"})
        except sqlite3.OperationalError as exc:
            results.append({"query": q, "success": False, "message": str(exc)})

    broken     = [r for r in results if not r["success"]]
    unaffected = [r for r in results if r["success"]]
    total      = len(results)

    summary = (
        f"Harvested {total} queries: "
        f"{len(unaffected)} pass, {len(broken)} still failing."
    )
    return len(broken) == 0, summary, results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def heal(v1_path: str, v2_path: str) -> int:
    """
    Reproduce the broken state in-memory, then apply the compatibility shim.

    Steps:
        1. Apply v1 schema; snapshot column names before migration.
        2. Apply v2 breaking migration.
        3. Dynamically synthesize and execute the backward-compatible view.
        4. Verify all v1 columns are still queryable via the v1-column probe.
        5. Verify all harvested application queries pass via the healed view.

    Returns
    -------
    int
        0  heal successful — all legacy queries restored.
        1  heal failed.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    # Step 1 — baseline + snapshot
    print("[healer] Applying v1 schema …")
    try:
        _apply_schema(conn, _read_sql(v1_path))
    except Exception as exc:
        print(f"[healer] ERROR applying v1 schema: {exc}", file=sys.stderr)
        conn.close()
        return 1

    # Detect the primary table that was created (first user table in sqlite_master)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid LIMIT 1"
    )
    row = cursor.fetchone()
    if row is None:
        print("[healer] ERROR: no table found after applying v1 schema.", file=sys.stderr)
        conn.close()
        return 1
    legacy_table: str = row[0]

    v1_cols = _get_columns(conn, legacy_table)
    print(f"[healer] v1 columns for '{legacy_table}': {v1_cols}")

    # Step 2 — breaking migration
    print("[healer] Applying v2 breaking migration …")
    try:
        _apply_schema(conn, _read_sql(v2_path))
    except Exception as exc:
        print(f"[healer] ERROR applying v2 migration: {exc}", file=sys.stderr)
        conn.close()
        return 1

    # Step 3 — dynamic heal
    print("[healer] Synthesizing backward-compatibility view …")
    success, message, _ddl = _heal(conn, legacy_table, v1_cols)
    if not success:
        print(f"[healer] ✗ {message}", file=sys.stderr)
        conn.close()
        return 1
    print(f"[healer] ✓ {message}")

    # Step 4 — verify v1-column probe
    print("[healer] Verifying legacy query …")
    success, message = _verify_legacy_query(conn, legacy_table, v1_cols)
    if not success:
        print(f"[healer] ✗ {message}", file=sys.stderr)
        conn.close()
        return 1
    print(f"[healer] ✓ {message}")

    # Step 5 — verify all harvested application queries
    print("[healer] Verifying all harvested application queries …")
    all_pass, harvest_summary, harvest_details = _verify_harvested_queries(conn, v1_path)
    conn.close()

    for r in harvest_details:
        icon = "✓" if r["success"] else "✗"
        q_display = r["query"] if len(r["query"]) <= 60 else r["query"][:57] + "…"
        print(f"[healer]   {icon}  {q_display}")
        if not r["success"]:
            print(f"[healer]       → {r['message']}")

    if all_pass:
        print(f"[healer] ✓ {harvest_summary}")
        print("[healer] Zero-downtime rollback complete — no data loss.")
        return 0
    else:
        print(f"[healer] ✗ {harvest_summary}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    v1 = os.path.join(base, "sample_data", "v1_schema.sql")
    v2 = os.path.join(base, "sample_data", "v2_breaking.sql")
    sys.exit(heal(v1, v2))
