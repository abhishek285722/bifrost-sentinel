"""  # -*- coding: utf-8 -*-
bifrost.py — Unified CLI orchestrator for the Bifrost database rehearsal tool.

Usage:
    python bifrost.py analyze        — Pre-flight static analysis on v2_breaking.sql
    python bifrost.py rehearse       — Run migration rehearsal in sandbox (expect exit 1)
    python bifrost.py heal           — Apply compatibility shim and verify (expect exit 0)
    python bifrost.py run            — Run full pipeline: rehearse → heal → final report
    python bifrost.py run --report   — Full pipeline + write bifrost_audit.json,
                                       bifrost.sarif, and pr_comment.md
    python bifrost.py --help         — Show this help

Bifrost demonstrates zero-downtime rollback safety for destructive schema
migrations using only the Python 3.10+ standard library.
"""

import sys
import os
import io
import re
from typing import Dict, Any, Tuple

# Ensure stdout/stderr can handle Unicode on Windows (cp1252 by default).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Terminal formatting — ANSI colour helpers (no external deps)
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"


def _supports_colour() -> bool:
    """Return True when the terminal likely renders ANSI escape codes."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* in *code* + reset if colours are supported."""
    if _supports_colour():
        return f"{code}{text}{_RESET}"
    return text


def _banner() -> None:
    width = 60
    print()
    print(_c(_BOLD + _CYAN, "═" * width))
    print(_c(_BOLD + _CYAN, "  ██████╗ ██╗███████╗██████╗  ██████╗ ███████╗████████╗"))
    print(_c(_BOLD + _CYAN, "  ██╔══██╗██║██╔════╝██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝"))
    print(_c(_BOLD + _CYAN, "  ██████╔╝██║█████╗  ██████╔╝██║   ██║███████╗   ██║   "))
    print(_c(_BOLD + _CYAN, "  ██╔══██╗██║██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║   "))
    print(_c(_BOLD + _CYAN, "  ██████╔╝██║██║     ██║  ██║╚██████╔╝███████║   ██║   "))
    print(_c(_BOLD + _CYAN, "  ╚═════╝ ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   "))
    print(_c(_DIM,          "  Autonomous Database Rehearsal & Zero-Downtime Rollback"))
    print(_c(_BOLD + _CYAN, "═" * width))
    print()


def _section(title: str) -> None:
    print()
    print(_c(_BOLD + _YELLOW, f"┌─ {title} " + "─" * max(0, 54 - len(title))))


def _result(ok: bool, label: str) -> None:
    icon  = _c(_GREEN, "✓") if ok else _c(_RED, "✗")
    state = _c(_GREEN, "PASSED") if ok else _c(_RED, "FAILED")
    print(f"│  {icon}  {label}: {state}")


def _footer(ok: bool) -> None:
    print()
    if ok:
        print(_c(_BOLD + _GREEN, "  ✓ Pipeline complete — legacy compatibility restored with zero data loss."))
    else:
        print(_c(_BOLD + _RED, "  ✗ Pipeline finished with failures — review output above."))
    print()


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

_BASE = os.path.dirname(os.path.abspath(__file__))
_V1   = os.path.join(_BASE, "sample_data", "v1_schema.sql")
_V2   = os.path.join(_BASE, "sample_data", "v2_breaking.sql")


def _check_data_files() -> bool:
    """Verify that the SQL data files exist before running."""
    ok = True
    for path in (_V1, _V2):
        if not os.path.isfile(path):
            print(_c(_RED, f"  Missing required file: {path}"), file=sys.stderr)
            ok = False
    return ok


# ---------------------------------------------------------------------------
# ASCII risk table — used by cmd_analyze
# ---------------------------------------------------------------------------

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Fixed column widths for the risk table
_COL_SEV   = 10  # severity
_COL_PAT   = 28  # pattern name
_COL_LINE  =  6  # line number
_COL_MATCH = 46  # SQL match fragment


def _truncate(text: str, width: int) -> str:
    """Truncate *text* to *width* characters, appending … if truncated."""
    if len(text) <= width:
        return text
    return text[: width - 1] + "…"


def _sev_colour(sev: str) -> str:
    """Return the ANSI code appropriate for a severity level."""
    return {
        "CRITICAL": _RED + _BOLD,
        "HIGH":     _RED,
        "MEDIUM":   _YELLOW,
        "LOW":      _DIM,
    }.get(sev, "")


def _print_risk_table(findings: list) -> None:
    """Render an ASCII risk table to stdout."""
    sep = (
        "+"
        + "-" * (_COL_SEV + 2)
        + "+"
        + "-" * (_COL_PAT + 2)
        + "+"
        + "-" * (_COL_LINE + 2)
        + "+"
        + "-" * (_COL_MATCH + 2)
        + "+"
    )

    def _row(sev: str, pat: str, line: str, match: str) -> str:
        return (
            f"| {sev:<{_COL_SEV}} "
            f"| {pat:<{_COL_PAT}} "
            f"| {line:>{_COL_LINE}} "
            f"| {match:<{_COL_MATCH}} |"
        )

    print(sep)
    # Header
    hdr = _row("SEVERITY", "PATTERN", "LINE", "SQL FRAGMENT")
    print(_c(_BOLD, hdr))
    print(sep)

    if not findings:
        empty_msg = _truncate("No destructive DDL patterns detected.", _COL_MATCH)
        print(_row("", "— clean migration —", "", empty_msg))
    else:
        sorted_findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f["severity"], 99))
        for f in sorted_findings:
            sev_text  = _truncate(f["severity"], _COL_SEV)
            pat_text  = _truncate(f["pattern"],  _COL_PAT)
            line_text = str(f["line"])
            match_text = _truncate(f["match"],   _COL_MATCH)
            row = _row(sev_text, pat_text, line_text, match_text)
            # Colour the entire row by severity
            print(_c(_sev_colour(f["severity"]), row))

    print(sep)


def _print_recommendations(findings: list) -> None:
    """Print unique recommendations for each pattern found."""
    if not findings:
        return
    seen = []
    print()
    print(_c(_BOLD, "  Recommendations"))
    print()
    sorted_findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f["severity"], 99))
    for f in sorted_findings:
        if f["pattern"] not in seen:
            seen.append(f["pattern"])
            label = _c(_sev_colour(f["severity"]) + _BOLD, f"[{f['severity']}] {f['pattern']}")
            print(f"  {label}")
            # Word-wrap the recommendation at 72 chars
            words = f["recommendation"].split()
            line_buf = "    "
            for word in words:
                if len(line_buf) + len(word) + 1 > 76:
                    print(line_buf)
                    line_buf = "    " + word
                else:
                    line_buf = line_buf + (" " if line_buf.strip() else "") + word
            if line_buf.strip():
                print(line_buf)
            print()


# ---------------------------------------------------------------------------
# Sub-command: analyze
# ---------------------------------------------------------------------------

def cmd_analyze() -> int:
    """
    Run pre-flight static analysis on sample_data/v2_breaking.sql
    and print an ASCII risk table.

    Returns 1 when findings exist (so CI pipelines can gate on this),
    0 when the migration is clean.
    """
    from analyzer import analyze_migration  # local import

    _section("ANALYSIS — Pre-flight Static Risk Scan")
    print(f"│  File : {_V2}")

    try:
        result = analyze_migration(_V2)
    except FileNotFoundError as exc:
        print(_c(_RED, f"  ERROR: {exc}"), file=sys.stderr)
        return 1

    findings = result["findings"]
    n        = len(findings)
    print(f"│  Risks: {n} finding(s)")
    print()

    _print_risk_table(findings)
    _print_recommendations(findings)

    if findings:
        print(_c(_BOLD + _RED, f"  ✗ {n} risk(s) detected — review recommendations above."))
    else:
        print(_c(_BOLD + _GREEN, "  ✓ No destructive DDL patterns detected."))
    print()

    return 1 if findings else 0


# ---------------------------------------------------------------------------
# Structured wrappers around rehearsal / healer
# (capture stdout into a buffer so we can both display it and extract results)
# ---------------------------------------------------------------------------

def _run_rehearsal_structured() -> Tuple[int, Dict[str, Any]]:
    """
    Run rehearsal.rehearse() and return (exit_code, results_dict).

    results_dict shape:
        {
            "breaking_change_detected": bool,
            "message": str,
            "query_breakdown": {"total": int, "broken": int, "unaffected": int},
        }
    """
    # Capture printed output by temporarily redirecting stdout to a buffer.
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf

    from rehearsal import rehearse  # local import
    code = rehearse(_V1, _V2)

    sys.stdout = old_stdout
    captured = buf.getvalue()

    # Re-emit captured output to the real stdout so the user still sees it.
    print(captured, end="")

    breaking = (code == 1)
    # Extract the last meaningful line as a short message for the report.
    lines = [l for l in captured.strip().splitlines() if l.strip()]
    message = lines[-1].lstrip("[rehearsal] ").strip() if lines else ""

    # Parse the "Results: N total — X broken, Y unaffected." summary line.
    breakdown = {"total": 0, "broken": 0, "unaffected": 0}
    for line in lines:
        m = re.search(
            r"Results:\s*(\d+)\s*total\s*[—-]+\s*(\d+)\s*broken,\s*(\d+)\s*unaffected",
            line,
        )
        if m:
            breakdown = {
                "total":      int(m.group(1)),
                "broken":     int(m.group(2)),
                "unaffected": int(m.group(3)),
            }
            break

    return code, {
        "breaking_change_detected": breaking,
        "message":         message,
        "query_breakdown": breakdown,
    }


def _run_heal_structured() -> Tuple[int, Dict[str, Any]]:
    """
    Run healer.heal() and return (exit_code, results_dict).

    results_dict shape:
        {"healed": bool, "message": str, "ddl": str}
    """
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf

    from healer import heal  # local import
    code = heal(_V1, _V2)

    sys.stdout = old_stdout
    captured = buf.getvalue()

    print(captured, end="")

    healed = (code == 0)

    # Extract the short message and any synthesised DDL from captured output.
    lines = [l for l in captured.strip().splitlines() if l.strip()]
    message = ""
    ddl_lines = []
    in_ddl = False
    for line in lines:
        stripped = line.lstrip("[healer] ").strip()
        if stripped.startswith("Generated DDL:"):
            in_ddl = True
            continue
        if in_ddl:
            # Stop at the next healer progress line (starts with "[healer]")
            if line.startswith("[healer]"):
                in_ddl = False
            else:
                ddl_lines.append(line)
        if not in_ddl and (stripped.startswith("✓") or stripped.startswith("✗")):
            message = stripped.lstrip("✓✗ ").strip()

    ddl = "\n".join(ddl_lines).strip()
    if not message and lines:
        message = lines[-1].lstrip("[healer] ").strip()

    return code, {"healed": healed, "message": message, "ddl": ddl}


# ---------------------------------------------------------------------------
# Sub-command implementations
# ---------------------------------------------------------------------------

def _get_schema_diff_data() -> Dict[str, Any]:
    """
    Return v1_cols, v2_cols, and the healer mapping for display purposes.

    Applies v1 schema and v2 migration in separate in-memory connections to
    snapshot column lists, then calls _diff_schemas.  All in-memory; no side
    effects.
    """
    import sqlite3 as _sqlite3
    from healer import _diff_schemas, _get_columns, _apply_schema as _ha

    def _read(p: str) -> str:
        with open(p, "r", encoding="utf-8") as fh:
            return fh.read()

    # v1 columns
    c1 = _sqlite3.connect(":memory:")
    _ha(c1, _read(_V1))
    cur = c1.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid LIMIT 1"
    )
    row = cur.fetchone()
    legacy_table = row[0] if row else "users"
    v1_cols = _get_columns(c1, legacy_table)
    c1.close()

    # v2 columns (apply both scripts)
    c2 = _sqlite3.connect(":memory:")
    _ha(c2, _read(_V1))
    _ha(c2, _read(_V2))
    # After v2 migration the original table is gone; detect the new one
    # by looking for the table whose name starts with the legacy table name
    # (v2_breaking renames users→users_old then recreates users).
    # The simplest heuristic: pick the first table whose name == legacy_table.
    # If it doesn't exist (was renamed), pick the first user table.
    cur2 = c2.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid"
    )
    tables = [r[0] for r in cur2.fetchall()]
    # Prefer the original name if recreated (e.g. v2_breaking.sql recreates 'users')
    v2_table = legacy_table if legacy_table in tables else (tables[0] if tables else legacy_table)
    v2_cols = _get_columns(c2, v2_table)
    c2.close()

    mapping = _diff_schemas(v1_cols, v2_cols)
    return {"v1_cols": v1_cols, "v2_cols": v2_cols, "mapping": mapping}


def cmd_diff() -> int:
    """
    Render the schema compatibility matrix directly to stdout.

    Shows how every legacy v1 column is remapped through the healer's
    compatibility VIEW after the v2 migration.

    Returns 0 on success, 1 on failure.
    """
    from ui import render_schema_diff  # local import

    if not _check_data_files():
        return 1

    try:
        diff_data = _get_schema_diff_data()
    except Exception as exc:
        print(_c(_RED, f"  ERROR building schema diff: {exc}"), file=sys.stderr)
        return 1

    _section("SCHEMA COMPATIBILITY MATRIX")
    render_schema_diff(
        diff_data["v1_cols"],
        diff_data["v2_cols"],
        diff_data["mapping"],
    )
    return 0


def cmd_patch(output: str = "") -> int:
    """
    Generate the executable SQL remediation patch (expand-contract shim).

    When *output* is empty the patch is written to bifrost_remediation.sql
    in the project root and the path is printed to stdout.
    When *output* is ``"-"`` the patch SQL is written directly to stdout
    (useful for piping into a database CLI).

    Returns 0 on success, 1 on failure.
    """
    from healer   import heal    # local import
    from explainer import generate_remediation_patch, analyze_blast_radius  # local import
    from analyzer import analyze_migration  # local import

    if not _check_data_files():
        return 1

    # Run heal in-memory to get the synthesized DDL
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    code = heal(_V1, _V2)
    sys.stdout = old_stdout
    captured = buf.getvalue()

    healed = (code == 0)
    # Extract DDL from captured output (same logic as _run_heal_structured)
    ddl_lines = []
    in_ddl = False
    for line in captured.splitlines():
        stripped = line.lstrip("[healer] ").strip()
        if stripped.startswith("Generated DDL:"):
            in_ddl = True
            continue
        if in_ddl:
            # Stop at the next healer progress line (starts with "[healer]")
            if line.startswith("[healer]"):
                in_ddl = False
            else:
                ddl_lines.append(line)
    ddl = "\n".join(ddl_lines).strip()

    healing_results = {"healed": healed, "message": "", "ddl": ddl}

    if output == "-":
        # Write SQL directly to stdout
        from explainer import generate_remediation_patch as _gen
        import tempfile, os as _os
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sql", delete=False, encoding="utf-8"
        )
        tmp.close()
        try:
            _gen(healing_results, output_path=tmp.name)
            with open(tmp.name, encoding="utf-8") as fh:
                sys.stdout.write(fh.read())
        finally:
            _os.unlink(tmp.name)
        return 0

    dest = output if output else os.path.join(_BASE, "bifrost_remediation.sql")
    patch_path = generate_remediation_patch(healing_results, output_path=dest)
    print(f"[bifrost] Remediation patch written → {patch_path}")
    return 0


def cmd_rehearse(verbose: bool = True) -> int:
    """Run the rehearsal sandbox. Expected exit code: 1 (breaking change found)."""
    from rehearsal import rehearse  # local import — avoids circular deps at module level

    if verbose:
        _section("REHEARSAL — Sandbox Migration Test")
    code = rehearse(_V1, _V2)
    if verbose:
        _result(code == 1, "Breaking change detected (expected)")
    return code


def cmd_heal(verbose: bool = True) -> int:
    """Apply the compatibility shim. Expected exit code: 0."""
    from healer import heal  # local import

    if verbose:
        _section("HEALING — Backward-Compatibility Shim")
    code = heal(_V1, _V2)
    if verbose:
        _result(code == 0, "Heal + legacy query restored")
    return code


def cmd_run(report: bool = False) -> int:
    """
    Full pipeline:
        1. Pre-flight static analysis (always shown in terminal)
        2. Rehearse  → expect exit 1 (breaking change found)
        3. Heal      → expect exit 0 (legacy queries restored)
        4. (--report only) Write bifrost_audit.json, bifrost.sarif,
           pr_comment.md, and bifrost_remediation.sql

    Returns 0 only when:
        - rehearsal correctly identified the breaking change (exit 1), AND
        - healing successfully restored legacy compatibility (exit 0).
    Returns 1 if unmitigated breaking changes persist.
    """
    _banner()

    if not _check_data_files():
        return 1

    # ── Stage 1: static analysis ───────────────────────────────────────────
    from analyzer import analyze_migration  # local import

    _section("ANALYSIS — Pre-flight Static Risk Scan")
    print(f"│  File : {_V2}")
    try:
        analysis_results = analyze_migration(_V2)
    except FileNotFoundError as exc:
        print(_c(_RED, f"  ERROR: {exc}"), file=sys.stderr)
        return 1

    findings = analysis_results["findings"]
    print(f"│  Risks: {len(findings)} finding(s)")
    print()
    _print_risk_table(findings)

    # ── Stage 2: rehearsal ─────────────────────────────────────────────────
    _section("REHEARSAL — Sandbox Migration Test")
    rehearse_code, rehearsal_results = _run_rehearsal_structured()
    rehearse_ok = (rehearse_code == 1)
    _result(rehearse_ok, "Breaking change detected (expected)")

    # ── Stage 3: healing ───────────────────────────────────────────────────
    _section("HEALING — Backward-Compatibility Shim")
    heal_code, healing_results = _run_heal_structured()
    heal_ok = (heal_code == 0)
    _result(heal_ok, "Heal + legacy query restored")

    # ── Stage 4: report generation (optional) ─────────────────────────────
    if report:
        from reporter import (  # local import
            generate_json_report,
            generate_sarif_report,
            generate_pr_comment,
        )
        from explainer import (  # local import
            generate_remediation_patch,
            analyze_blast_radius,
        )

        _section("REPORT — Generating Audit Artefacts")

        blast_radius = analyze_blast_radius(analysis_results, rehearsal_results)

        json_path  = generate_json_report(
            analysis_results, rehearsal_results, healing_results,
            blast_radius=blast_radius,
        )
        sarif_path = generate_sarif_report(analysis_results)
        pr_md      = generate_pr_comment(
            analysis_results, rehearsal_results, healing_results,
            blast_radius=blast_radius,
        )
        patch_path = generate_remediation_patch(
            healing_results,
            output_path=os.path.join(_BASE, "bifrost_remediation.sql"),
        )

        pr_path = os.path.join(_BASE, "pr_comment.md")
        with open(pr_path, "w", encoding="utf-8") as fh:
            fh.write(pr_md)

        print(f"│  bifrost_audit.json       → {json_path}")
        print(f"│  bifrost.sarif            → {sarif_path}")
        print(f"│  pr_comment.md            → {pr_path}")
        print(f"│  bifrost_remediation.sql  → {patch_path}")

    # ── Stage 5: schema diff visualizer + safety scorecard ────────────────
    from ui import render_schema_diff, calculate_safety_score, render_scorecard  # local

    qb       = rehearsal_results.get("query_breakdown", {})
    broken_q = qb.get("broken", 0)

    try:
        diff_data = _get_schema_diff_data()
        _section("SCHEMA COMPATIBILITY MATRIX")
        render_schema_diff(
            diff_data["v1_cols"],
            diff_data["v2_cols"],
            diff_data["mapping"],
        )
    except Exception:
        pass   # non-fatal — visual only

    score_data = calculate_safety_score(findings, healed=heal_ok, broken_query_count=broken_q)
    render_scorecard(score_data)

    # ── Summary ────────────────────────────────────────────────────────────
    _section("SUMMARY")
    _result(len(findings) > 0, f"Analysis: {len(findings)} risk(s) detected")

    # Show harvested-query breakdown from the rehearsal stage
    total_q = qb.get("total",      0)
    safe_q  = qb.get("unaffected", 0)
    if total_q > 0:
        heal_label = "All healed" if heal_ok else "Unhealed"
        breakdown_label = (
            f"Harvested {total_q} application queries: "
            f"{broken_q} broken, {safe_q} unaffected → {heal_label}"
        )
        _result(rehearse_ok, breakdown_label)
    else:
        _result(rehearse_ok, "Rehearsal detected breaking change")

    _result(heal_ok, "Healer restored legacy compatibility")
    print("└" + "─" * 57)

    overall_ok = rehearse_ok and heal_ok
    _footer(overall_ok)

    return 0 if overall_ok else 1


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

_HELP = f"""
{_c(_BOLD, 'Bifrost')} — Autonomous Database Rehearsal & Zero-Downtime Rollback Safety CLI

{_c(_BOLD, 'Usage:')}
    python bifrost.py <command> [options]

{_c(_BOLD, 'Commands:')}
    analyze     Static pre-flight scan of sample_data/v2_breaking.sql
                Prints ASCII risk table with severity, pattern, line, and SQL fragment
                Expected exit code: 1 when risks detected, 0 when clean

    rehearse    Execute migration in isolated sandbox, simulate legacy query failure
                Expected exit code: 1  (breaking change detected)

    heal        Auto-generate backward-compatible view, restore legacy queries
                Expected exit code: 0  (zero data loss, queries pass)

    diff        Render the schema compatibility matrix (v1 → v2 column mapping).
                Shows remediation strategy and SAFE/HEALED/NEW/DROPPED status per column.
                Expected exit code: 0

    patch       Generate the executable SQL remediation patch (expand-contract shim).
                Writes bifrost_remediation.sql to the project root by default.
                Use  patch -  to emit SQL directly to stdout (pipe-friendly).
                Expected exit code: 0

    run         Full pipeline — analyze → rehearse → heal, with visual matrix + scorecard
                Expected exit code: 0  (all stages behaved correctly)

    run --report
                Full pipeline + write audit artefacts:
                  bifrost_audit.json        — structured JSON audit trail
                  bifrost.sarif             — SARIF v2.1.0 for GitHub Code Scanning
                  pr_comment.md             — Markdown ready for GitHub PR comment
                  bifrost_remediation.sql   — Executable SQL compatibility patch
                Expected exit code: 0 when all stages heal cleanly,
                                    1 if unmitigated breaking changes persist

    --help      Show this help message

{_c(_BOLD, 'Data files (relative to bifrost.py):')}
    sample_data/v1_schema.sql    — Initial schema with seed data
    sample_data/v2_breaking.sql  — Destructive migration (drops 'name' column)

{_c(_DIM, 'Zero external dependencies — Python 3.10+ standard library only.')}
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h", "help"):
        print(_HELP)
        return 0

    command = args[0].lower()

    if command == "analyze":
        if not _check_data_files():
            return 1
        return cmd_analyze()

    if command == "rehearse":
        if not _check_data_files():
            return 1
        return cmd_rehearse()

    if command == "heal":
        if not _check_data_files():
            return 1
        return cmd_heal()

    if command == "diff":
        return cmd_diff()

    if command == "patch":
        # optional positional arg: output path or "-" for stdout
        dest = args[1] if len(args) > 1 else ""
        return cmd_patch(output=dest)

    if command == "run":
        report_flag = "--report" in args[1:]
        return cmd_run(report=report_flag)

    print(_c(_RED, f"  Unknown command: '{command}'"))
    print("  Run  python bifrost.py --help  for usage.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
