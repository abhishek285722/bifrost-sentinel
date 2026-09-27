"""
reporter.py — Bifrost CI/CD report generator.

Converts the structured outputs of the analyzer, rehearsal, and healer stages
into enterprise-grade deliverables ready for GitHub Actions, audit systems,
and code-scanning pipelines.

Public API
----------
    generate_json_report(analysis_results, rehearsal_results, healing_results,
                         output_path="bifrost_audit.json") -> str
        Full audit trail with timestamps, per-finding risk details, and
        mitigation status.  Returns the absolute path of the written file.

    generate_sarif_report(analysis_results, output_path="bifrost.sarif") -> str
        Valid SARIF v2.1.0 document mapping every destructive-DDL finding to
        a CWE-backed rule so GitHub Code Scanning can render inline annotations.
        Returns the absolute path of the written file.

    generate_pr_comment(analysis_results, rehearsal_results,
                        healing_results) -> str
        Markdown string ready to POST as a GitHub Pull Request review comment.

Input shapes (all dicts produced by the other Bifrost modules):

    analysis_results  — returned by analyzer.analyze_migration():
        {
            "file":     str,            # absolute path of the SQL file
            "findings": [               # may be empty
                {
                    "pattern":        str,   # e.g. "DROP COLUMN"
                    "severity":       str,   # CRITICAL | HIGH | MEDIUM | LOW
                    "line":           int,   # 1-based line number
                    "match":          str,   # verbatim SQL fragment
                    "recommendation": str,   # actionable guidance
                },
                ...
            ],
        }

    rehearsal_results — produced by the caller after running rehearsal.rehearse():
        {
            "breaking_change_detected": bool,
            "message":                  str,
        }

    healing_results — produced by the caller after running healer.heal():
        {
            "healed":  bool,
            "message": str,
            "ddl":     str,   # synthesized VIEW DDL (empty string if not healed)
        }

Standard library only: json, os, datetime, pathlib.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

# ------------------------------------------------------------------------------
# Internal constants
# ------------------------------------------------------------------------------

# SARIF v2.1.0 schema URI (official Microsoft/OASIS location)
_SARIF_SCHEMA  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Tool identity embedded in every generated document
_TOOL_NAME    = "bifrost"
_TOOL_VERSION = "1.0.0"
_TOOL_URI     = "https://github.com/bifrost-engine/bifrost"

# CWE taxonomy reference used by SARIF rules
_CWE_TAXONOMY_GUID = "FFC64C90-42B6-44CE-8A7C-37EE2CE35F78"  # well-known CWE GUID

# Map each Bifrost risk pattern → (CWE-ID, CWE name, short description)
# These are the closest CWE entries for data-integrity / schema-change risks.
_PATTERN_CWE: Dict[str, tuple] = {
    "DROP COLUMN": (
        "CWE-1059",
        "Incomplete Documentation",
        "Irreversible removal of a schema column causes runtime query failures "
        "for any application version that has not been re-deployed.",
    ),
    "TABLE RENAME": (
        "CWE-1059",
        "Incomplete Documentation",
        "Renaming a table breaks all existing SQL queries that reference the "
        "original name without a coordinated, multi-step expand-contract deploy.",
    ),
    "NOT NULL WITHOUT DEFAULT": (
        "CWE-1006",
        "Bad Coding Practices",
        "Adding a NOT NULL constraint without a DEFAULT value causes INSERT "
        "failures for older application versions that omit the new column.",
    ),
    "ADD CONSTRAINT": (
        "CWE-400",
        "Uncontrolled Resource Consumption",
        "ALTER TABLE … ADD CONSTRAINT acquires a full table lock that can stall "
        "production writes for the duration of the historical-row validation scan.",
    ),
}

# Severity → SARIF level mapping
_SEVERITY_SARIF_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC time in ISO-8601 format (Z suffix)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 99)


def _finding_status(finding: Dict[str, Any], healing_results: Dict[str, Any]) -> str:
    """
    Derive a mitigation status string for a single finding.

    A finding is considered 'mitigated' when healing succeeded, because the
    healer's VIEW shim restores backward compatibility for all flagged
    patterns in the current supported set.  Callers may extend this logic.
    """
    if healing_results.get("healed"):
        return "MITIGATED"
    return "OPEN"


def _write_json(data: Any, output_path: str) -> str:
    """
    Serialise *data* to *output_path* as pretty-printed JSON (UTF-8).

    Returns the absolute path of the written file.
    """
    abs_path = str(Path(output_path).resolve())
    with open(abs_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return abs_path


# ------------------------------------------------------------------------------
# 1. JSON audit report
# ------------------------------------------------------------------------------

def generate_json_report(
    analysis_results:  Dict[str, Any],
    rehearsal_results: Dict[str, Any],
    healing_results:   Dict[str, Any],
    output_path:       str = "bifrost_audit.json",
    blast_radius:      Dict[str, Any] = None,
) -> str:
    """
    Generate a full audit trail as a JSON file.

    The document records:
    - run metadata (tool version, timestamp, migration file path)
    - per-finding details with risk severity, matched SQL fragment, and
      current mitigation status
    - rehearsal stage outcome (was the breaking change detected?)
    - healing stage outcome (was backward-compatibility restored?)
    - an aggregate risk_summary with counts per severity level
    - blast_radius section (when provided): root_cause, affected_entities,
      risk_assessment, recommended_action

    Parameters
    ----------
    analysis_results : dict
        Output of analyzer.analyze_migration().
    rehearsal_results : dict
        {"breaking_change_detected": bool, "message": str}
    healing_results : dict
        {"healed": bool, "message": str, "ddl": str}
    output_path : str
        Destination file path (created or overwritten).
    blast_radius : dict | None
        Output of explainer.analyze_blast_radius() (optional).

    Returns
    -------
    str
        Absolute path of the written JSON file.
    """
    timestamp = _utc_now()
    findings  = analysis_results.get("findings", [])

    # Per-finding audit records — enrich with mitigation status
    audit_findings: List[Dict[str, Any]] = []
    for f in findings:
        cwe_id, cwe_name, _ = _PATTERN_CWE.get(
            f["pattern"], ("CWE-UNKNOWN", "Unknown", "")
        )
        audit_findings.append(
            {
                "pattern":          f["pattern"],
                "severity":         f["severity"],
                "line":             f["line"],
                "match":            f["match"],
                "recommendation":   f["recommendation"],
                "cwe":              cwe_id,
                "cwe_name":         cwe_name,
                "mitigation_status": _finding_status(f, healing_results),
            }
        )

    # Severity distribution
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    }
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    overall_ok = (
        rehearsal_results.get("breaking_change_detected", False)
        and healing_results.get("healed", False)
    )

    report = {
        "schema_version": "1.0",
        "tool": {
            "name":    _TOOL_NAME,
            "version": _TOOL_VERSION,
            "uri":     _TOOL_URI,
        },
        "run": {
            "timestamp":      timestamp,
            "migration_file": analysis_results.get("file", ""),
            "overall_status": "PASS" if overall_ok else "FAIL",
        },
        "stages": {
            "analysis": {
                "finding_count": len(findings),
                "findings":      audit_findings,
            },
            "rehearsal": {
                "breaking_change_detected": rehearsal_results.get(
                    "breaking_change_detected", False
                ),
                "message": rehearsal_results.get("message", ""),
            },
            "healing": {
                "healed":  healing_results.get("healed", False),
                "message": healing_results.get("message", ""),
                "ddl":     healing_results.get("ddl", ""),
            },
        },
        "risk_summary": {
            "total_findings":  len(findings),
            "by_severity":     severity_counts,
            "mitigated_count": sum(
                1 for f in audit_findings
                if f["mitigation_status"] == "MITIGATED"
            ),
            "open_count": sum(
                1 for f in audit_findings
                if f["mitigation_status"] == "OPEN"
            ),
        },
    }

    if blast_radius is not None:
        report["blast_radius"] = blast_radius

    return _write_json(report, output_path)


# ------------------------------------------------------------------------------
# 2. SARIF v2.1.0 report
# ------------------------------------------------------------------------------

def generate_sarif_report(
    analysis_results: Dict[str, Any],
    output_path:      str = "bifrost.sarif",
) -> str:
    """
    Generate a SARIF v2.1.0 document for GitHub Code Scanning.

    Each unique risk pattern becomes a ``rule`` in the tool's ``rules`` array,
    annotated with its CWE taxonomy relationship so GitHub surfaces the correct
    vulnerability category.  Each individual finding becomes a ``result``
    pointing at the exact source line in the migration file.

    The document is valid against the official SARIF 2.1.0 JSON Schema and can
    be uploaded directly via ``github/codeql-action/upload-sarif``.

    Parameters
    ----------
    analysis_results : dict
        Output of analyzer.analyze_migration().
    output_path : str
        Destination file path (created or overwritten).

    Returns
    -------
    str
        Absolute path of the written SARIF file.
    """
    findings       = analysis_results.get("findings", [])
    migration_file = analysis_results.get("file", "unknown.sql")

    # Collect unique patterns to build the rules table
    seen_patterns: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        pat = f["pattern"]
        if pat not in seen_patterns:
            cwe_id, cwe_name, cwe_desc = _PATTERN_CWE.get(
                pat, ("CWE-UNKNOWN", "Unknown Risk", f["recommendation"])
            )
            rule_id = pat.upper().replace(" ", "_")
            seen_patterns[pat] = {
                "id":   rule_id,
                "cwe":  cwe_id,
                "name": cwe_name,
                "desc": cwe_desc,
                "rec":  f["recommendation"],
            }

    # Build the ``rules`` array
    rules: List[Dict[str, Any]] = []
    for pat, r in seen_patterns.items():
        rules.append(
            {
                "id": r["id"],
                "name": pat.title().replace(" ", ""),
                "shortDescription": {"text": pat},
                "fullDescription":  {"text": r["desc"]},
                "helpUri":          _TOOL_URI,
                "help":             {"text": r["rec"], "markdown": r["rec"]},
                "properties": {
                    "tags": ["security", "correctness", "database"],
                    "precision": "high",
                    "problem.severity": (
                        "error"
                        if _SEVERITY_SARIF_LEVEL.get(
                            next(
                                (
                                    f["severity"]
                                    for f in findings
                                    if f["pattern"] == pat
                                ),
                                "LOW",
                            )
                        ) == "error"
                        else "warning"
                    ),
                },
                "relationships": [
                    {
                        "target": {
                            "id":            r["cwe"],
                            "guid":          _CWE_TAXONOMY_GUID,
                            "toolComponent": {"name": "CWE", "guid": _CWE_TAXONOMY_GUID},
                        },
                        "kinds": ["superset"],
                    }
                ],
            }
        )

    # Build the ``results`` array — one entry per finding instance
    results: List[Dict[str, Any]] = []
    for f in findings:
        pat     = f["pattern"]
        rule_id = seen_patterns[pat]["id"]
        level   = _SEVERITY_SARIF_LEVEL.get(f["severity"], "warning")

        results.append(
            {
                "ruleId":  rule_id,
                "level":   level,
                "message": {
                    "text": (
                        f"{f['pattern']} detected: `{f['match']}`. "
                        f"{f['recommendation']}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri":       Path(migration_file).name,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine":   f["line"],
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "severity":     f["severity"],
                    "match":        f["match"],
                },
            }
        )

    sarif_doc: Dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            _TOOL_NAME,
                        "version":         _TOOL_VERSION,
                        "informationUri":  _TOOL_URI,
                        "rules":           rules,
                        "supportedTaxonomies": [
                            {
                                "name":             "CWE",
                                "version":          "4.12",
                                "organization":     "MITRE",
                                "shortDescription": {"text": "Common Weakness Enumeration"},
                                "guid":             _CWE_TAXONOMY_GUID,
                            }
                        ],
                    }
                },
                "artifacts": [
                    {
                        "location": {
                            "uri":       Path(migration_file).name,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "roles": ["analysisTarget"],
                    }
                ],
                "results": results,
            }
        ],
    }

    return _write_json(sarif_doc, output_path)


# ------------------------------------------------------------------------------
# 3. GitHub PR comment (Markdown)
# ------------------------------------------------------------------------------

def generate_pr_comment(
    analysis_results:  Dict[str, Any],
    rehearsal_results: Dict[str, Any],
    healing_results:   Dict[str, Any],
    blast_radius:      Dict[str, Any] = None,
) -> str:
    """
    Generate a GitHub Pull Request comment in Markdown.

    The comment is structured as a collapsible summary with:
    - A status badge line (PASS / FAIL) with stage icons
    - A findings table (severity, pattern, line, SQL fragment)
    - A recommendations block for each unique pattern
    - A healing DDL section (collapsed) if a shim was generated
    - A blast-radius section (collapsed) when *blast_radius* is provided
    - A footer with the tool name and run timestamp

    Parameters
    ----------
    analysis_results : dict
        Output of analyzer.analyze_migration().
    rehearsal_results : dict
        {"breaking_change_detected": bool, "message": str}
    healing_results : dict
        {"healed": bool, "message": str, "ddl": str}
    blast_radius : dict | None
        Output of explainer.analyze_blast_radius() (optional).

    Returns
    -------
    str
        Complete Markdown string suitable for a GitHub PR comment body.
    """
    findings   = analysis_results.get("findings", [])
    mig_file   = os.path.basename(analysis_results.get("file", "migration.sql"))
    timestamp  = _utc_now()

    rehearsed  = rehearsal_results.get("breaking_change_detected", False)
    healed     = healing_results.get("healed", False)
    overall_ok = rehearsed and healed

    status_icon  = "✅" if overall_ok else "❌"
    status_label = "**PASS** — zero-downtime compatibility restored" if overall_ok \
                   else "**FAIL** — manual intervention required"

    rehearsal_icon = "✅" if rehearsed else "❌"
    healing_icon   = "✅" if healed    else "❌"

    lines: List[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append(f"## {status_icon} Bifrost Migration Safety Report")
    lines.append("")
    lines.append(f"> **File:** `{mig_file}` &nbsp;|&nbsp; **Run:** `{timestamp}`")
    lines.append("")

    # ── Stage overview ─────────────────────────────────────────────────────────
    lines.append("### Pipeline Stages")
    lines.append("")
    lines.append("| Stage | Status | Detail |")
    lines.append("|-------|--------|--------|")
    lines.append(
        f"| 🔬 Rehearsal | {rehearsal_icon} {'Detected' if rehearsed else 'No change'} "
        f"| {rehearsal_results.get('message', '')} |"
    )
    lines.append(
        f"| 🩹 Healing   | {healing_icon} {'Restored' if healed else 'Failed'} "
        f"| {'Compatibility view synthesised' if healed else healing_results.get('message', '')} |"
    )
    lines.append("")

    # ── Findings ───────────────────────────────────────────────────────────────
    if findings:
        sorted_findings = sorted(findings, key=lambda f: _severity_order(f["severity"]))

        lines.append("### Destructive DDL Findings")
        lines.append("")
        lines.append("| Severity | Pattern | Line | SQL Fragment |")
        lines.append("|----------|---------|------|--------------|")
        for f in sorted_findings:
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
                f["severity"], "⚪"
            )
            # Escape pipe characters in the SQL fragment so the table renders correctly
            match_escaped = f["match"].replace("|", "\\|")
            lines.append(
                f"| {sev_icon} {f['severity']} | {f['pattern']} "
                f"| {f['line']} | `{match_escaped}` |"
            )
        lines.append("")

        # Unique recommendations
        lines.append("<details>")
        lines.append("<summary>📋 Recommendations</summary>")
        lines.append("")
        seen: List[str] = []
        for f in sorted_findings:
            if f["pattern"] not in seen:
                seen.append(f["pattern"])
                cwe_id, _, _ = _PATTERN_CWE.get(
                    f["pattern"], ("CWE-UNKNOWN", "", "")
                )
                lines.append(f"**{f['pattern']}** ({cwe_id})")
                lines.append("")
                lines.append(f"> {f['recommendation']}")
                lines.append("")
        lines.append("</details>")
        lines.append("")
    else:
        lines.append("### ✅ No Destructive DDL Patterns Detected")
        lines.append("")

    # ── Healing DDL ────────────────────────────────────────────────────────────
    ddl = healing_results.get("ddl", "").strip()
    if ddl:
        lines.append("<details>")
        lines.append("<summary>🔧 Synthesised Compatibility DDL</summary>")
        lines.append("")
        lines.append("```sql")
        lines.append(ddl)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # ── Blast-radius ───────────────────────────────────────────────────────────
    if blast_radius:
        lines.append("<details>")
        lines.append("<summary>💥 Blast-Radius Analysis</summary>")
        lines.append("")

        root_cause = blast_radius.get("root_cause", "")
        if root_cause:
            lines.append("**Root Cause**")
            lines.append("")
            lines.append(f"> {root_cause}")
            lines.append("")

        risk_assessment = blast_radius.get("risk_assessment", "")
        if risk_assessment:
            lines.append("**Risk Assessment**")
            lines.append("")
            lines.append(f"> {risk_assessment}")
            lines.append("")

        affected = blast_radius.get("affected_entities", [])
        if affected:
            lines.append("**Affected Entities**")
            lines.append("")
            lines.append("| Pattern | Severity | Table | Column |")
            lines.append("|---------|----------|-------|--------|")
            for e in affected:
                lines.append(
                    f"| {e.get('pattern', '')} "
                    f"| {e.get('severity', '')} "
                    f"| {e.get('table', '—')} "
                    f"| {e.get('column', '—')} |"
                )
            lines.append("")

        steps = blast_radius.get("recommended_action", [])
        if steps:
            lines.append("**Recommended Actions**")
            lines.append("")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        lines.append("</details>")
        lines.append("")

    # ── Risk summary ───────────────────────────────────────────────────────────
    if findings:
        open_count = 0 if healed else len(findings)
        mit_count  = len(findings) if healed else 0
        lines.append("### Risk Summary")
        lines.append("")
        lines.append(f"- **Total findings:** {len(findings)}")
        lines.append(f"- **Mitigated:** {mit_count}")
        lines.append(f"- **Open:** {open_count}")
        lines.append("")

    # ── Footer ─────────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append(
        f"*Generated by [Bifrost]({_TOOL_URI}) v{_TOOL_VERSION} &nbsp;·&nbsp; {timestamp}*"
    )

    return "\n".join(lines)


# ------------------------------------------------------------------------------
# CLI entry point — smoke-test with sample data when run directly
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import os

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Locate v2_breaking.sql relative to this file
    base = os.path.dirname(os.path.abspath(__file__))
    v2   = os.path.join(base, "sample_data", "v2_breaking.sql")

    from analyzer import analyze_migration

    analysis = analyze_migration(v2)
    rehearsal: Dict[str, Any] = {
        "breaking_change_detected": True,
        "message": "Legacy query failed: no such column: name",
    }
    healing: Dict[str, Any] = {
        "healed":  True,
        "message": "Compatibility view 'users' created over table 'users_v2'.",
        "ddl": (
            "CREATE VIEW IF NOT EXISTS users AS\n"
            "SELECT\n"
            "    id,\n"
            "    (first_name || ' ' || last_name) AS name,\n"
            "    email\n"
            "FROM users_v2"
        ),
    }

    json_path  = generate_json_report(analysis, rehearsal, healing)
    sarif_path = generate_sarif_report(analysis)
    comment    = generate_pr_comment(analysis, rehearsal, healing)

    print(f"[reporter] JSON audit  → {json_path}")
    print(f"[reporter] SARIF       → {sarif_path}")
    print()
    print("──── PR Comment Preview ────")
    print(comment)
