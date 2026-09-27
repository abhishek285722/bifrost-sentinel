"""
explainer.py — Bifrost automated SQL patch generator and blast-radius explainer.

Turns the structured outputs of the healer and analyzer into two artifacts:

1. generate_remediation_patch(healing_results, output_path) -> str
   Wraps the synthesized CREATE VIEW DDL in a production-safe SQL script
   (transaction block, header comments, verification SELECT) and writes it
   to *output_path*.  Returns the absolute file path written.

2. analyze_blast_radius(analysis_results, rehearsal_results) -> dict
   Examines every flagged finding and the rehearsal outcome to explain:
     - root_cause          — plain-English reason the runtime queries broke
     - affected_entities   — list of tables/columns impacted
     - risk_assessment     — architectural risk summary
     - recommended_action  — ordered step-by-step developer guidance

Standard library only: re, os, pathlib, datetime, typing.
"""

import re
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Tuple

# ---------------------------------------------------------------------------
# Section divider
# ---------------------------------------------------------------------------
# -------------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_TOOL_NAME    = "bifrost"
_TOOL_VERSION = "1.0.0"

# Map risk patterns to concise root-cause explanations (used in blast-radius)
_ROOT_CAUSE_TEMPLATES: Dict[str, str] = {
    "DROP COLUMN": (
        "A column was permanently removed from the schema. "
        "Any running application version that references the dropped column "
        "in a SELECT, INSERT, or UPDATE statement will receive a runtime "
        "OperationalError until it is redeployed."
    ),
    "TABLE RENAME": (
        "A table was renamed, severing every SQL statement and ORM query that "
        "references the original table name. Old application versions continue "
        "to issue queries against the now-missing name, causing immediate "
        "OperationalErrors at the database layer."
    ),
    "NOT NULL WITHOUT DEFAULT": (
        "A NOT NULL constraint was added to an existing column without providing "
        "a DEFAULT value. Any application version that inserts rows without "
        "explicitly supplying this column will receive a constraint-violation "
        "error, breaking writes silently for partial deployments."
    ),
    "ADD CONSTRAINT": (
        "A new constraint was added via ALTER TABLE … ADD CONSTRAINT, which "
        "acquires a full table lock while validating all existing rows. On large "
        "tables this lock can stall production writes for seconds to minutes, "
        "degrading application availability during the migration window."
    ),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC time in ISO-8601 format (Z suffix)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_table_from_match(match_sql: str) -> str:
    """
    Best-effort extraction of a table name from a matched SQL fragment.

    Looks for the first identifier following TABLE, RENAME TO, or DROP COLUMN.
    Returns the raw identifier or an empty string when nothing is found.
    """
    patterns = [
        r"ALTER\s+TABLE\s+(\w+)",
        r"RENAME\s+TO\s+(\w+)",
        r"DROP\s+COLUMN\s+(\w+)",
        r"ADD\s+CONSTRAINT\s+(\w+)",
    ]
    for p in patterns:
        m = re.search(p, match_sql, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _extract_column_from_match(match_sql: str) -> str:
    """
    Best-effort extraction of a column name from a DROP COLUMN or NOT NULL fragment.
    Returns an empty string when not applicable.
    """
    m = re.search(r"DROP\s+COLUMN\s+(\w+)", match_sql, re.IGNORECASE)
    if m:
        return m.group(1)
    # NOT NULL WITHOUT DEFAULT — first token is the column name
    m2 = re.search(r"^(\w+)\s+\w", match_sql.strip())
    if m2:
        return m2.group(1)
    return ""


# ---------------------------------------------------------------------------
# Public API — 1. Remediation patch generator
# ---------------------------------------------------------------------------

def generate_remediation_patch(
    healing_results: Dict[str, Any],
    output_path: str = "bifrost_remediation.sql",
) -> str:
    """
    Generate a production-safe SQL remediation patch from *healing_results*.

    The patch wraps the synthesized ``CREATE VIEW`` DDL in a standard
    expand-contract shim pattern:

    * A transaction block (``BEGIN`` / ``COMMIT``) ensures atomicity.
    * A rollback safety comment reminds operators to test in staging first.
    * A post-creation verification ``SELECT`` exercises the view immediately
      so any remaining incompatibility is caught before ``COMMIT``.
    * A header block records the generating tool, version, and timestamp so
      the patch is traceable in audit logs.

    Parameters
    ----------
    healing_results : dict
        Output of the healer stage, must contain key ``"ddl"`` (str).
        If ``"ddl"`` is absent or empty the function writes a no-op patch
        with an explanatory comment.
    output_path : str
        Destination file path (created or overwritten).

    Returns
    -------
    str
        Absolute path of the written SQL file.
    """
    ddl    = (healing_results.get("ddl") or "").strip()
    healed = healing_results.get("healed", False)
    ts     = _utc_now()

    # Extract the view name from the DDL for the verification SELECT.
    # Pattern: CREATE VIEW IF NOT EXISTS <name> AS …
    view_name = ""
    if ddl:
        m = re.search(
            r"CREATE\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
            ddl,
            re.IGNORECASE,
        )
        if m:
            view_name = m.group(1)

    lines: List[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append("-- =============================================================")
    lines.append(f"-- Bifrost Remediation Patch")
    lines.append(f"-- Generated by : {_TOOL_NAME} v{_TOOL_VERSION}")
    lines.append(f"-- Timestamp    : {ts}")
    lines.append("-- =============================================================")
    lines.append("--")
    lines.append("-- EXPAND-CONTRACT COMPATIBILITY SHIM")
    lines.append("-- ─────────────────────────────────────────────────────────────")
    lines.append("-- This patch implements the expand-contract pattern for a")
    lines.append("-- zero-downtime schema migration.")
    lines.append("--")
    lines.append("-- HOW IT WORKS:")
    lines.append("-- 1. The physical v2 table (e.g. users_v2) holds the new schema.")
    lines.append("-- 2. A VIEW with the original table name (e.g. users) is created")
    lines.append("--    on top, synthesizing legacy columns (e.g. 'name') from the")
    lines.append("--    new split columns (e.g. first_name || ' ' || last_name).")
    lines.append("-- 3. Legacy application code that queries the original table name")
    lines.append("--    continues to work without modification.")
    lines.append("-- 4. Once all application instances are updated to use the new")
    lines.append("--    schema directly, this VIEW can be dropped safely.")
    lines.append("--")
    lines.append("-- APPLY INSTRUCTIONS:")
    lines.append("-- 1. Review this script thoroughly before running in production.")
    lines.append("-- 2. Test in a staging environment first.")
    lines.append("-- 3. Apply during a low-traffic window.")
    lines.append("-- 4. Monitor application error rates for ≥ 10 minutes after apply.")
    lines.append("-- =============================================================")
    lines.append("")

    if not ddl or not healed:
        lines.append("-- NOTE: No compatibility DDL was synthesized.")
        lines.append("-- This means either healing was not required or healing failed.")
        lines.append("-- No changes will be applied by this patch.")
        lines.append("")
        lines.append("-- (no-op)")
    else:
        # ── Transaction block ─────────────────────────────────────────────────
        lines.append("BEGIN;")
        lines.append("")
        lines.append("-- Step 1: Create the backward-compatible VIEW.")
        lines.append("-- This view exposes the legacy column names so old queries still work.")
        lines.append(ddl + ";")
        lines.append("")

        if view_name:
            lines.append("-- Step 2: Verify the view is queryable.")
            lines.append("-- This SELECT must return rows if seed data exists.")
            lines.append(f"SELECT * FROM {view_name} LIMIT 1;")
            lines.append("")

        lines.append("COMMIT;")
        lines.append("")
        lines.append("-- =============================================================")
        lines.append("-- Patch applied successfully.")
        lines.append("-- Legacy queries are now compatible with the new schema.")
        lines.append("-- To remove the shim once all clients are migrated:")
        if view_name:
            lines.append(f"--   DROP VIEW IF EXISTS {view_name};")
        lines.append("-- =============================================================")

    content = "\n".join(lines) + "\n"
    abs_path = str(Path(output_path).resolve())
    with open(abs_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    return abs_path


# ---------------------------------------------------------------------------
# Public API — 2. Blast-radius analyser
# ---------------------------------------------------------------------------

def analyze_blast_radius(
    analysis_results:  Dict[str, Any],
    rehearsal_results: Dict[str, Any],
) -> dict:
    """
    Compute the blast radius of a destructive migration.

    Combines static analysis findings and rehearsal outcome to produce a
    structured impact report explaining *why* runtime queries broke, *what*
    database objects are affected, the overall architectural risk, and the
    concrete steps a developer must take to resolve the situation safely.

    Parameters
    ----------
    analysis_results : dict
        Output of analyzer.analyze_migration() — must contain ``"findings"``.
    rehearsal_results : dict
        Output of the rehearsal stage —
        ``{"breaking_change_detected": bool, "message": str}``.

    Returns
    -------
    dict with keys:
        root_cause          : str   — plain-English cause of query failures
        affected_entities   : list  — tables/columns impacted
        risk_assessment     : str   — architectural risk summary
        recommended_action  : list  — ordered step-by-step developer guidance
    """
    findings    = analysis_results.get("findings", [])
    breaking    = rehearsal_results.get("breaking_change_detected", False)
    rehearsal_msg = rehearsal_results.get("message", "")

    # ── Root cause ─────────────────────────────────────────────────────────
    # Derive from the highest-severity finding or from the rehearsal message.
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        findings, key=lambda f: _sev_order.get(f.get("severity", "LOW"), 99)
    )

    if sorted_findings:
        top_pattern = sorted_findings[0]["pattern"]
        root_cause = _ROOT_CAUSE_TEMPLATES.get(top_pattern, "")
        if not root_cause:
            root_cause = (
                f"A destructive DDL operation ({top_pattern}) was detected "
                "that may break running application queries."
            )
        if breaking and rehearsal_msg:
            # Append the actual rehearsal failure message for full context.
            root_cause += f" Rehearsal confirmed: {rehearsal_msg}"
    elif breaking:
        root_cause = (
            "The rehearsal detected a breaking change in the migration, "
            "but no static-analysis findings were flagged. "
            f"Rehearsal message: {rehearsal_msg}"
        )
    else:
        root_cause = (
            "No breaking changes were detected by static analysis or rehearsal."
        )

    # ── Affected entities ──────────────────────────────────────────────────
    affected: List[Dict[str, str]] = []
    seen: set = set()

    for f in findings:
        table  = _extract_table_from_match(f.get("match", ""))
        column = _extract_column_from_match(f.get("match", ""))

        entity_key = (table, column, f["pattern"])
        if entity_key in seen:
            continue
        seen.add(entity_key)

        entry: Dict[str, str] = {
            "pattern":  f["pattern"],
            "severity": f["severity"],
        }
        if table:
            entry["table"] = table
        if column:
            entry["column"] = column
        entry["match"] = f.get("match", "")
        affected.append(entry)

    # ── Risk assessment ────────────────────────────────────────────────────
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count     = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count   = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    if critical_count > 0:
        overall_risk = "CRITICAL"
        risk_desc = (
            f"This migration contains {critical_count} CRITICAL finding(s). "
            "Destructive DDL operations will cause immediate, unrecoverable "
            "failures for any application version still referencing the "
            "original schema objects. Zero-downtime deployment is not possible "
            "without the compatibility shim generated by the healer stage."
        )
    elif high_count > 0:
        overall_risk = "HIGH"
        risk_desc = (
            f"This migration contains {high_count} HIGH-severity finding(s). "
            "Table renames or NOT NULL additions without defaults will break "
            "at least one query path in the running application. "
            "A compatibility view or careful column-default backfill is required "
            "before deploying to production."
        )
    elif medium_count > 0:
        overall_risk = "MEDIUM"
        risk_desc = (
            f"This migration contains {medium_count} MEDIUM-severity finding(s). "
            "Constraint additions may cause elevated lock contention on large tables. "
            "Schedule the migration during a low-traffic window and use "
            "NOT VALID / VALIDATE CONSTRAINT to minimise lock hold time."
        )
    elif findings:
        overall_risk = "LOW"
        risk_desc = (
            "This migration contains low-severity findings only. "
            "Review the recommendations and proceed with normal deployment practices."
        )
    else:
        overall_risk = "NONE"
        risk_desc = (
            "No destructive DDL patterns were detected. "
            "This migration appears safe to apply with standard deployment practices."
        )

    risk_assessment = f"[{overall_risk}] {risk_desc}"

    # ── Recommended action ─────────────────────────────────────────────────
    # Build an ordered, context-aware step list.
    steps: List[str] = []

    if not findings and not breaking:
        steps = [
            "No action required — migration is safe to deploy.",
            "Apply using your standard deployment pipeline.",
            "Monitor application error rates for 10 minutes post-deploy.",
        ]
    else:
        steps.append(
            "Run `python bifrost.py run --report` in CI to generate the full "
            "audit trail (bifrost_audit.json, bifrost.sarif, pr_comment.md, "
            "bifrost_remediation.sql)."
        )

        if any(f["pattern"] == "TABLE RENAME" for f in findings):
            steps.append(
                "TABLE RENAME detected: Do not rename the table directly. "
                "Instead — (a) create the new table alongside the old one, "
                "(b) expose both names via an expanding VIEW until all clients "
                "are migrated, (c) then drop the old table in a later release."
            )

        if any(f["pattern"] == "DROP COLUMN" for f in findings):
            steps.append(
                "DROP COLUMN detected: Remove the column in at least two "
                "deployment steps — (a) deploy code that stops reading/writing "
                "the column, (b) then drop it in a separate, later migration."
            )

        if any(f["pattern"] == "NOT NULL WITHOUT DEFAULT" for f in findings):
            steps.append(
                "NOT NULL WITHOUT DEFAULT detected: Add the column as nullable "
                "first, backfill all existing rows, then add the NOT NULL "
                "constraint in a separate ALTER TABLE migration."
            )

        if any(f["pattern"] == "ADD CONSTRAINT" for f in findings):
            steps.append(
                "ADD CONSTRAINT detected: Use NOT VALID (PostgreSQL) or an "
                "equivalent deferred constraint mechanism to skip historical "
                "row validation during the ALTER TABLE. Run VALIDATE CONSTRAINT "
                "in a separate, offline step."
            )

        if breaking:
            steps.append(
                "Apply the generated bifrost_remediation.sql to the production "
                "database BEFORE deploying the new application version. "
                "This creates the backward-compatible VIEW so legacy queries "
                "continue to work during the rolling deployment window."
            )
            steps.append(
                "Once ALL application instances have been updated to reference "
                "the new schema directly, drop the compatibility VIEW and "
                "remove the remediation patch from your migration history."
            )

        steps.append(
            "Monitor application error rates, slow query logs, and lock-wait "
            "metrics for at least 10 minutes after each deployment step."
        )

    return {
        "root_cause":         root_cause,
        "affected_entities":  affected,
        "risk_assessment":    risk_assessment,
        "recommended_action": steps,
    }


# ---------------------------------------------------------------------------
# CLI entry point — smoke-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    base     = os.path.dirname(os.path.abspath(__file__))
    v2_path  = os.path.join(base, "sample_data", "v2_breaking.sql")

    from analyzer  import analyze_migration
    from healer    import heal

    analysis = analyze_migration(v2_path)
    v1_path  = os.path.join(base, "sample_data", "v1_schema.sql")

    # Capture heal output without printing it
    import io as _io
    _buf = _io.StringIO()
    _old = sys.stdout
    sys.stdout = _buf
    _code = heal(v1_path, v2_path)
    sys.stdout = _old

    healing_results = {
        "healed": (_code == 0),
        "message": "Compatibility view synthesized.",
        "ddl": (
            "CREATE VIEW IF NOT EXISTS users AS\n"
            "SELECT\n"
            "    id,\n"
            "    (first_name || ' ' || last_name) AS name,\n"
            "    email\n"
            "FROM users_v2"
        ),
    }
    rehearsal_results = {
        "breaking_change_detected": True,
        "message": "Legacy query FAILED: no such column: name",
    }

    patch_path = generate_remediation_patch(healing_results)
    blast      = analyze_blast_radius(analysis, rehearsal_results)

    print(f"[explainer] Patch written → {patch_path}")
    print(f"[explainer] Root cause    : {blast['root_cause'][:80]}…")
    print(f"[explainer] Risk          : {blast['risk_assessment'][:80]}…")
    print(f"[explainer] Affected      : {blast['affected_entities']}")
