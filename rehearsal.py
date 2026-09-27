"""
rehearsal.py — Bifrost sandbox migration rehearsal.

Executes the v1 → v2 migration in an isolated in-memory SQLite database,
then simulates application queries against the migrated schema.

By default the harvester discovers every SQL query in the sample_data/
directory.  Callers may also supply an explicit list of query strings.

Exit codes:
    0  migration succeeded AND all queries still work (no breaking change)
    1  migration revealed at least one breaking query (expected for v2_breaking.sql)
"""

import sqlite3
import sys
import os
from typing import Tuple, List, Dict, Optional


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
# Helpers — query execution
# ---------------------------------------------------------------------------

def _run_query(
    conn: sqlite3.Connection, query: str
) -> Tuple[bool, str]:
    """
    Execute a single *query* on *conn*.

    Returns
    -------
    (success, message)
        success is False when the query raises sqlite3.OperationalError.
    """
    try:
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        return True, f"OK — {len(rows)} row(s) returned."
    except sqlite3.OperationalError as exc:
        return False, f"FAILED: {exc}"


def _run_legacy_query(conn: sqlite3.Connection) -> Tuple[bool, str]:
    """
    Simulate the single hard-coded legacy application query:
    SELECT id, name, email FROM users.

    Kept for backward compatibility with tests and callers that do not pass
    a query list.

    Returns
    -------
    (success, message)
    """
    return _run_query(conn, "SELECT id, name, email FROM users")


def _run_queries(
    conn: sqlite3.Connection,
    queries: List[str],
) -> List[Dict]:
    """
    Execute every query in *queries* against *conn*.

    Returns
    -------
    list[dict]
        One record per query:
            {
                "query":   str,    # the original SQL text
                "success": bool,
                "message": str,
            }
    """
    results = []
    for q in queries:
        success, message = _run_query(conn, q)
        results.append({"query": q, "success": success, "message": message})
    return results


# ---------------------------------------------------------------------------
# Main rehearsal logic
# ---------------------------------------------------------------------------

def rehearse(
    v1_path: str,
    v2_path: str,
    queries: Optional[List[str]] = None,
) -> int:
    """
    Run the full rehearsal in an isolated in-memory database.

    Parameters
    ----------
    v1_path : str
        Path to the v1 schema SQL file.
    v2_path : str
        Path to the v2 migration SQL file.
    queries : list[str] | None
        SQL queries to test against the migrated schema.  When *None*,
        the harvester auto-discovers queries from the sample_data/ directory
        that lives next to *v1_path*.

    Steps
    -----
    1. Apply v1 schema (creates table + seed data).
    2. Apply v2 migration.
    3. Execute every discovered/provided query; report pass/fail per query.

    Returns
    -------
    int
        0  all queries still pass — no breaking change.
        1  at least one query broke — breaking change detected.
    """
    # Resolve auto-discovery directory relative to v1_path
    if queries is None:
        from harvester import harvest_codebase_queries  # local import
        data_dir = os.path.dirname(os.path.abspath(v1_path))
        harvested = harvest_codebase_queries(data_dir)
        # Use only application queries from .py files (not schema/migration .sql files)
        queries = [
            r["query"] for r in harvested
            if r.get("target_table") and r["file"].lower().endswith(".py")
        ]
        if not queries:
            # Fallback to the original single hard-coded probe
            queries = ["SELECT id, name, email FROM users"]

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    # Step 1 — baseline schema
    print("[rehearsal] Applying v1 schema …")
    try:
        _apply_schema(conn, _read_sql(v1_path))
    except Exception as exc:
        print(f"[rehearsal] ERROR applying v1 schema: {exc}", file=sys.stderr)
        conn.close()
        return 1

    # Step 2 — migration
    print("[rehearsal] Applying v2 migration …")
    try:
        _apply_schema(conn, _read_sql(v2_path))
    except Exception as exc:
        print(f"[rehearsal] ERROR applying v2 migration: {exc}", file=sys.stderr)
        conn.close()
        return 1

    # Step 3 — test every query
    print(f"[rehearsal] Testing {len(queries)} harvested query(ies) …")
    query_results = _run_queries(conn, queries)
    conn.close()

    broken    = [r for r in query_results if not r["success"]]
    unaffected = [r for r in query_results if r["success"]]

    for r in query_results:
        icon = "✓" if r["success"] else "✗"
        # Truncate long queries for display
        q_display = r["query"] if len(r["query"]) <= 60 else r["query"][:57] + "…"
        print(f"[rehearsal]   {icon}  {q_display}")
        if not r["success"]:
            print(f"[rehearsal]       → {r['message']}")

    total = len(query_results)
    print(
        f"[rehearsal] Results: {total} total — "
        f"{len(broken)} broken, {len(unaffected)} unaffected."
    )

    if broken:
        print("[rehearsal] ✗ Breaking change detected — healing required.")
        return 1
    else:
        print("[rehearsal] ✓ No breaking queries detected.")
        return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    v1 = os.path.join(base, "sample_data", "v1_schema.sql")
    v2 = os.path.join(base, "sample_data", "v2_breaking.sql")
    sys.exit(rehearse(v1, v2))
