"""
analyzer.py — Bifrost pre-flight SQL migration analyser.

Inspects a SQL migration file for destructive or high-risk DDL patterns
before the script is executed in rehearsal or production.

Each detected pattern is reported as a *finding* dict with four keys:
    pattern     — short name of the risk class
    severity    — CRITICAL | HIGH | MEDIUM | LOW
    line        — 1-based line number of the first match
    match       — verbatim SQL fragment that triggered the rule
    recommendation — actionable guidance for zero-downtime safety

Public API
----------
    analyze_migration(sql_filepath: str) -> dict

The returned dict has the shape::

    {
        "file":     "<absolute path>",
        "findings": [ { "pattern": ..., "severity": ..., "line": ...,
                        "match": ..., "recommendation": ... }, ... ]
    }

Standard library only: re, pathlib, json.
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Tuple

# ------------------------------------------------------------------------------
# Risk rules
# Each rule is a tuple:
#   (pattern_name, severity, compiled_regex, recommendation)
#
# Regex flags: re.IGNORECASE | re.VERBOSE for readability.
# Each pattern must have exactly one capturing group — the matched fragment
# that will be stored in finding["match"].
# ------------------------------------------------------------------------------

_RULES: List[Tuple[str, str, re.Pattern, str]] = [
    (
        "DROP COLUMN",
        "CRITICAL",
        re.compile(
            r"(ALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\s+\S+)",
            re.IGNORECASE,
        ),
        (
            "Never drop a column in a single deployment step. "
            "Use the expand-contract pattern: (1) deploy code that ignores the column, "
            "(2) backfill / stop writes, (3) drop in a later release."
        ),
    ),
    (
        "TABLE RENAME",
        "HIGH",
        re.compile(
            r"(ALTER\s+TABLE\s+\S+\s+RENAME\s+(?:TO\s+)?\S+)",
            re.IGNORECASE,
        ),
        (
            "Table renames instantly break any client that has not yet deployed. "
            "Create the new table alongside the old one and use an expanding view "
            "pattern: expose both names via a VIEW until all clients are migrated, "
            "then drop the old name."
        ),
    ),
    (
        "NOT NULL WITHOUT DEFAULT",
        "HIGH",
        re.compile(
            # Matches: column_name  TYPE  NOT NULL  — but NOT NULL DEFAULT ...
            # Negative lookahead excludes the safe form (has a DEFAULT clause).
            r"(\w+\s+\w[\w\s]*\bNOT\s+NULL(?!\s+DEFAULT\b)(?!\s+UNIQUE\b)(?!\s+PRIMARY\b))",
            re.IGNORECASE,
        ),
        (
            "Adding NOT NULL without a DEFAULT causes INSERT failures on any client "
            "that does not yet supply the new column. Supply a DEFAULT value, or "
            "add the column as nullable first, backfill all rows, then add the "
            "NOT NULL constraint in a separate migration."
        ),
    ),
    (
        "ADD CONSTRAINT",
        "MEDIUM",
        re.compile(
            r"(ALTER\s+TABLE\s+\S+\s+ADD\s+CONSTRAINT\s+\S+)",
            re.IGNORECASE,
        ),
        (
            "Adding a constraint with ALTER TABLE … ADD CONSTRAINT acquires a full "
            "table lock while validating existing rows. For large tables use "
            "NOT VALID (PostgreSQL) to skip historical rows, then VALIDATE CONSTRAINT "
            "in a separate step during a maintenance window."
        ),
    ),
]

# ------------------------------------------------------------------------------
# Comment stripping
# Strip single-line (--) and block (/* */) SQL comments before matching so
# that commented-out DDL does not produce false positives.
# ------------------------------------------------------------------------------

_BLOCK_COMMENT  = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT   = re.compile(r"--[^\n]*")


def _strip_comments(sql: str) -> str:
    """Return *sql* with all SQL comments removed."""
    sql = _BLOCK_COMMENT.sub("", sql)
    sql = _LINE_COMMENT.sub("", sql)
    return sql


# ------------------------------------------------------------------------------
# Line-number mapping
# Build a list of (line_start_char_offset) so we can map a character position
# back to a 1-based line number in the *original* (with-comments) source.
# We match against comment-stripped text but report lines from the original.
# Because stripping comments changes offsets we work directly on the original
# source, relying on the rule regexes to be insensitive to comment content.
# ------------------------------------------------------------------------------

def _line_of_match(sql: str, match_start: int) -> int:
    """Return the 1-based line number for character offset *match_start*."""
    return sql.count("\n", 0, match_start) + 1


# ------------------------------------------------------------------------------
# Core analyser
# ------------------------------------------------------------------------------

def _analyse_sql(sql: str) -> List[Dict]:
    """
    Scan *sql* text and return a list of finding dicts (may be empty).

    Findings are produced in document order (ascending line number).
    Multiple matches for the same rule each produce a separate finding.
    """
    clean = _strip_comments(sql)
    findings: List[Dict] = []

    for pattern_name, severity, regex, recommendation in _RULES:
        for m in regex.finditer(clean):
            # Map cleaned-text offset back to the original source line by
            # counting newlines up to the same relative position.  Because
            # stripping comments only removes characters (never adds them),
            # offset correspondence is monotonic and we can reuse the offset.
            line_no = _line_of_match(sql, m.start())
            findings.append(
                {
                    "pattern":        pattern_name,
                    "severity":       severity,
                    "line":           line_no,
                    "match":          m.group(1).strip(),
                    "recommendation": recommendation,
                }
            )

    # Sort by line number so the report reads top-to-bottom.
    findings.sort(key=lambda f: f["line"])
    return findings


# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------

def analyze_migration(sql_filepath: str) -> dict:
    """
    Analyse the SQL migration file at *sql_filepath* for destructive patterns.

    Parameters
    ----------
    sql_filepath : str
        Path to the SQL migration script (absolute or relative).

    Returns
    -------
    dict
        {
            "file":     <absolute path as string>,
            "findings": [ <finding dict>, ... ]
        }

    Each finding dict contains:
        pattern        — risk class name (e.g. "DROP COLUMN")
        severity       — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        line           — 1-based line number of the match in the source file
        match          — verbatim SQL fragment that triggered the rule
        recommendation — actionable zero-downtime guidance

    Raises
    ------
    FileNotFoundError
        If *sql_filepath* does not exist.
    """
    path = Path(sql_filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"SQL file not found: {sql_filepath}")

    sql = path.read_text(encoding="utf-8")
    findings = _analyse_sql(sql)

    return {
        "file":     str(path),
        "findings": findings,
    }


# ------------------------------------------------------------------------------
# CLI entry point — pretty-print results when run directly
# ------------------------------------------------------------------------------

def _severity_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 99)


def _print_report(result: dict) -> None:
    """Print a human-readable summary of *result* to stdout."""
    findings = result["findings"]
    print(f"\n[analyzer] File : {result['file']}")
    print(f"[analyzer] Risks : {len(findings)} finding(s)\n")

    if not findings:
        print("[analyzer] ✓ No destructive DDL patterns detected.")
        return

    for f in sorted(findings, key=lambda x: _severity_order(x["severity"])):
        print(f"  [{f['severity']}]  {f['pattern']}  (line {f['line']})")
        print(f"    Match  : {f['match']}")
        print(f"    Fix    : {f['recommendation']}")
        print()


if __name__ == "__main__":
    import sys
    import os

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path/to/migration.sql>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        report = analyze_migration(target)
    except FileNotFoundError as exc:
        print(f"[analyzer] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    _print_report(report)
    # Exit 1 when findings exist so CI pipelines can gate on this.
    sys.exit(1 if report["findings"] else 0)
