"""
ui.py — Bifrost interactive schema diff visualizer and safety scorecard.

Renders human-readable terminal output for the schema compatibility matrix
and the composite migration safety score.

Public API
----------
    render_schema_diff(v1_cols, v2_cols, mapping) -> None
        Prints a side-by-side ASCII compatibility matrix showing how every
        v1 column is remapped through the healer's compatibility VIEW, plus
        any new v2-only columns.

    calculate_safety_score(findings, healed, broken_query_count) -> dict
        Computes a composite safety score (0–100) and letter grade (A/B/C/F)
        from the severity of static-analysis findings, the number of broken
        queries, and whether healing succeeded.

    render_scorecard(score_data) -> None
        Prints an ASCII badge showing the Safety Score, grade, and deployment
        readiness verdict.

Standard library only: sys, typing.
"""

import sys
from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# Windows UTF-8 guard (mirrors bifrost.py)
# ---------------------------------------------------------------------------
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# ANSI colour codes (same palette as bifrost.py; gracefully degraded when
# stdout is not a TTY)
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"
_BLUE   = "\033[34m"


def _supports_colour() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if _supports_colour():
        return f"{code}{text}{_RESET}"
    return text


# ---------------------------------------------------------------------------
# Column widths for the schema diff table
# ---------------------------------------------------------------------------

_W_COL  = 22   # v1 column name  (or "(new) v2col")
_W_STRAT = 34  # remediation strategy
_W_STATUS = 8  # status badge

# Separator line for the table body
_BODY_SEP = (
    "│  "
    + "─" * _W_COL
    + " ┼ "
    + "─" * _W_STRAT
    + " ┼ "
    + "─" * _W_STATUS
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _strategy_label(col: str, mapping: Dict[str, str]) -> str:
    """
    Return a short human-readable strategy label for *col*.

    Derives from the SQL expression stored in *mapping*.
    """
    expr = mapping.get(col, col)
    if expr == col:
        return "1:1 Direct Mapping"
    if expr.startswith("NULL AS"):
        return "Dropped — NULL fallback"
    if "||" in expr:
        # Concatenation — show abbreviated form
        # e.g. "(first_name || ' ' || last_name) AS name"
        # → "(first_name || ' ' || last_name)"
        inner = expr.split(" AS ")[0].strip()
        if len(inner) > _W_STRAT:
            inner = inner[: _W_STRAT - 1] + "…"
        return inner
    # Single-column alias: "first_name AS name"
    return expr


def _status_for_col(col: str, mapping: Dict[str, str]) -> str:
    """Return a status token for a v1 column based on its mapping expression."""
    expr = mapping.get(col, col)
    if expr == col:
        return "SAFE"
    if expr.startswith("NULL AS"):
        return "DROPPED"
    return "HEALED"


def _status_colour(status: str) -> str:
    return {
        "SAFE":    _GREEN,
        "HEALED":  _CYAN,
        "DROPPED": _RED,
        "NEW":     _YELLOW,
    }.get(status, "")


def _fmt_row(v1_col: str, strategy: str, status: str) -> str:
    """Format one table row, colour-coding the status cell."""
    col_cell      = v1_col[:_W_COL].ljust(_W_COL)
    strategy_cell = strategy[:_W_STRAT].ljust(_W_STRAT)
    status_text   = _c(_status_colour(status) + _BOLD, status.ljust(_W_STATUS))
    return f"│  {col_cell} │ {strategy_cell} │ {status_text}"


# ---------------------------------------------------------------------------
# Public API — 1. Schema diff table
# ---------------------------------------------------------------------------

def render_schema_diff(
    v1_cols:  List[str],
    v2_cols:  List[str],
    mapping:  Dict[str, str],
) -> None:
    """
    Print a side-by-side ASCII schema compatibility matrix.

    The table shows every v1 column and its remediation strategy, followed by
    any v2-only (new) columns.

    Parameters
    ----------
    v1_cols : list[str]
        Ordered column names from the v1 (legacy) schema.
    v2_cols : list[str]
        Ordered column names from the v2 (migrated) schema.
    mapping : dict
        Output of healer._diff_schemas(v1_cols, v2_cols).
    """
    title = " SCHEMA COMPATIBILITY MATRIX "
    width = _W_COL + _W_STRAT + _W_STATUS + 10   # padding + separators
    top   = "┌─" + title + "─" * max(0, width - len(title) - 2)

    print()
    print(_c(_BOLD + _CYAN, top))
    # Header row
    hdr_col    = "Legacy v1 Column".ljust(_W_COL)
    hdr_strat  = "Remediation Strategy".ljust(_W_STRAT)
    hdr_status = "Status".ljust(_W_STATUS)
    print(_c(_BOLD, f"│  {hdr_col} │ {hdr_strat} │ {hdr_status}"))
    print(_BODY_SEP)

    # v1 columns
    for col in v1_cols:
        strategy = _strategy_label(col, mapping)
        status   = _status_for_col(col, mapping)
        print(_fmt_row(col, strategy, status))

    # v2-only (new) columns
    v1_set = set(v1_cols)
    for col in v2_cols:
        if col not in v1_set:
            new_label = f"(new)  {col}"
            strategy  = "v2 Direct Column"
            print(_fmt_row(new_label, strategy, "NEW"))

    # Footer
    foot_left  = "└" + "─" * (_W_COL + 3)
    foot_mid   = "┴" + "─" * (_W_STRAT + 2)
    foot_right = "┴" + "─" * (_W_STATUS + 1)
    print(_c(_CYAN, foot_left + foot_mid + foot_right))
    print()


# ---------------------------------------------------------------------------
# Public API — 2. Safety score calculator
# ---------------------------------------------------------------------------

# Severity penalty weights applied to static-analysis findings
_SEVERITY_PENALTY: Dict[str, int] = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    8,
    "LOW":       3,
}

# Points deducted per broken query (capped at 20 total deduction)
_QUERY_BREAK_PENALTY = 5
_QUERY_BREAK_CAP     = 20

# Bonus points awarded when healing fully succeeds
_HEAL_BONUS = 20


def calculate_safety_score(
    findings:            List[Dict[str, Any]],
    healed:              bool,
    broken_query_count:  int,
) -> Dict[str, Any]:
    """
    Compute a composite migration safety score (0–100) and letter grade.

    Scoring model
    -------------
    Start at 100.  Deduct:
      - Per finding severity:  CRITICAL −25, HIGH −15, MEDIUM −8, LOW −3
      - Per broken query:      −5 per query, capped at −20 total
    Add:
      - Heal bonus:            +20 when all queries were successfully healed

    Clamp result to [0, 100].

    Grade thresholds
    ----------------
      A  90–100  Excellent — deploy with confidence
      B  75–89   Good — minor risks, healing in place
      C  50–74   Caution — review recommendations before deploying
      F   0–49   Critical — do not deploy until issues are resolved

    Parameters
    ----------
    findings : list[dict]
        Output of analyzer.analyze_migration()["findings"].
    healed : bool
        Whether the healer successfully restored all queries.
    broken_query_count : int
        Number of application queries that broke after migration.

    Returns
    -------
    dict
        {
            "score":   int,   # 0–100
            "grade":   str,   # "A" | "B" | "C" | "F"
            "verdict": str,   # human-readable deployment readiness
        }
    """
    score = 100

    # Deduct for findings
    for f in findings:
        penalty = _SEVERITY_PENALTY.get(f.get("severity", "LOW"), 3)
        score  -= penalty

    # Deduct for broken queries (capped)
    query_deduction = min(broken_query_count * _QUERY_BREAK_PENALTY, _QUERY_BREAK_CAP)
    score -= query_deduction

    # Bonus for successful heal
    if healed:
        score += _HEAL_BONUS

    # Clamp
    score = max(0, min(100, score))

    # Grade
    if score >= 90:
        grade   = "A"
        verdict = "DEPLOY — all risks mitigated, zero-downtime compatibility restored."
    elif score >= 75:
        grade   = "B"
        verdict = "DEPLOY WITH CARE — healing succeeded, minor residual risks remain."
    elif score >= 50:
        grade   = "C"
        verdict = "REVIEW BEFORE DEPLOY — significant risks detected; review recommendations."
    else:
        grade   = "F"
        verdict = "DO NOT DEPLOY — critical unmitigated risks; manual intervention required."

    return {"score": score, "grade": grade, "verdict": verdict}


# ---------------------------------------------------------------------------
# Public API — 3. Safety scorecard renderer
# ---------------------------------------------------------------------------

def render_scorecard(score_data: Dict[str, Any]) -> None:
    """
    Print an ASCII safety scorecard badge.

    Parameters
    ----------
    score_data : dict
        Output of calculate_safety_score().
    """
    score   = score_data.get("score",   0)
    grade   = score_data.get("grade",   "F")
    verdict = score_data.get("verdict", "")

    # Choose colour based on grade
    grade_colour = {
        "A": _GREEN  + _BOLD,
        "B": _CYAN   + _BOLD,
        "C": _YELLOW + _BOLD,
        "F": _RED    + _BOLD,
    }.get(grade, _DIM)

    bar_filled  = round(score / 5)       # 20 cells = full bar
    bar_empty   = 20 - bar_filled
    bar         = "█" * bar_filled + "░" * bar_empty

    # Width of inner content
    inner_w = 58
    top     = "┌" + "─" * inner_w + "┐"
    bot     = "└" + "─" * inner_w + "┘"
    blank   = "│" + " " * inner_w + "│"

    def _pad(text: str) -> str:
        """Left-pad *text* to *inner_w* with trailing spaces."""
        return "│  " + text.ljust(inner_w - 2) + "│"

    print()
    print(_c(_BOLD + _CYAN, top))
    print(_c(_BOLD + _CYAN, blank))
    title_text = "BIFROST MIGRATION SAFETY SCORECARD"
    print(_c(_BOLD, _pad(title_text)))
    print(_c(_CYAN, blank))

    # Score line
    score_line  = f"Safety Score:  {_c(grade_colour, str(score).rjust(3))}  / 100"
    score_raw   = f"Safety Score:  {str(score).rjust(3)}  / 100"
    print("│  " + score_line + " " * (inner_w - 2 - len(score_raw)) + "│")

    # Grade line
    grade_line  = f"Grade:         {_c(grade_colour, grade)}"
    grade_raw   = f"Grade:         {grade}"
    print("│  " + grade_line + " " * (inner_w - 2 - len(grade_raw)) + "│")

    # Progress bar
    bar_display = _c(grade_colour, bar)
    bar_raw     = bar
    print("│  " + bar_display + " " * (inner_w - 2 - len(bar_raw)) + "│")

    print(_c(_CYAN, blank))

    # Verdict — word-wrap at inner_w - 4 chars
    wrap_w = inner_w - 4
    words  = verdict.split()
    line_buf = ""
    verdict_lines: List[str] = []
    for word in words:
        if not line_buf:
            line_buf = word
        elif len(line_buf) + 1 + len(word) <= wrap_w:
            line_buf += " " + word
        else:
            verdict_lines.append(line_buf)
            line_buf = word
    if line_buf:
        verdict_lines.append(line_buf)

    for vl in verdict_lines:
        print(_pad(_c(grade_colour, vl)))

    print(_c(_CYAN, blank))
    print(_c(_BOLD + _CYAN, bot))
    print()


# ---------------------------------------------------------------------------
# CLI entry point — smoke-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from healer import _diff_schemas

    v1 = ["id", "name", "email"]
    v2 = ["id", "first_name", "last_name", "email"]
    mapping = _diff_schemas(v1, v2)

    render_schema_diff(v1, v2, mapping)

    findings = [
        {"pattern": "TABLE RENAME",           "severity": "HIGH"},
        {"pattern": "NOT NULL WITHOUT DEFAULT", "severity": "HIGH"},
    ]
    score_data = calculate_safety_score(findings, healed=True, broken_query_count=3)
    render_scorecard(score_data)
