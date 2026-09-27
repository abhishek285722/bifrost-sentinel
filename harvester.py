"""
harvester.py — Bifrost autonomous codebase SQL query harvester.

Scans Python and SQL source files for embedded SQL SELECT statements so
that rehearsal can test every application query against a proposed migration,
not just a single hard-coded probe.

Public API
----------
    harvest_queries_from_code(filepath: str) -> List[str]
        Extract all SQL query strings from a single source file.
        Supports string literals (single, double, triple-quoted) and
        direct string concatenations in Python, plus bare SQL in .sql files.

    harvest_codebase_queries(search_dir: str = "sample_data") -> List[dict]
        Scan every .py and .sql file under *search_dir* and return a list
        of records:
            {
                "file":         str,   # absolute path of the source file
                "query":        str,   # normalised SQL text
                "target_table": str,   # first table name after FROM
            }

Standard library only: re, os, pathlib, typing.
"""

import re
import os
from pathlib import Path
from typing import List, Dict

# ---------------------------------------------------------------------------
# Section dividers (project convention: 78-dash)
# ------------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Matches a SELECT … FROM … query.
# A SQL string token is: '...' or "..." (simple, no escaping needed for this purpose).
# The pattern consumes SQL token by token, stopping only at a bare semicolon,
# the end of the enclosing Python string delimiter, or end-of-string.
#
# Strategy: match either a single-quoted SQL string, a double-quoted SQL string,
# or any non-quote, non-semicolon character — greedily.  Stop when we hit a
# bare semicolon or end-of-string.
_SELECT_RE = re.compile(
    r"SELECT\b"                         # must start with SELECT
    r"(?:"
        r"'[^']*'"                      # single-quoted SQL string token
        r"|"
        r'"[^"]*"'                      # double-quoted SQL string token
        r"|"
        r"[^;\"']"                      # any other character (not ; or quote)
    r")+"
    r"FROM\s+\w+"                       # must contain FROM <table>
    r"(?:"
        r"'[^']*'"
        r"|"
        r'"[^"]*"'
        r"|"
        r"[^;\"']"
    r")*",
    re.IGNORECASE | re.DOTALL,
)

# Extracts the first table name that follows FROM (ignoring sub-selects).
_FROM_TABLE_RE = re.compile(r"\bFROM\s+(\w+)", re.IGNORECASE)

# String-literal extraction patterns for Python source.
# Ordered from most to least specific (triple-quoted first).
_PY_STRING_RE = re.compile(
    r'"""(.*?)"""|'          # triple double-quoted
    r"'''(.*?)'''|"          # triple single-quoted
    r'"((?:[^"\\]|\\.)*)"|'  # double-quoted
    r"'((?:[^'\\]|\\.)*)'",  # single-quoted
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_query(sql: str) -> str:
    """
    Return a normalised, single-line version of *sql*.

    Collapses runs of whitespace (including newlines) to a single space and
    strips leading/trailing whitespace.
    """
    return re.sub(r"\s+", " ", sql).strip()


def _table_from_query(sql: str) -> str:
    """
    Return the first table name following FROM in *sql*.

    Returns an empty string when no FROM clause is found.
    """
    m = _FROM_TABLE_RE.search(sql)
    return m.group(1) if m else ""


def _looks_like_select(text: str) -> bool:
    """Return True when *text* (stripped) starts with SELECT (case-insensitive)."""
    return bool(re.match(r"^\s*SELECT\b", text, re.IGNORECASE))


def _extract_from_python(source: str) -> List[str]:
    """
    Extract all SQL SELECT strings embedded in Python source code.

    Looks inside all string literals (triple-quoted and regular) for text
    that begins with SELECT and contains FROM.
    """
    queries: List[str] = []
    for m in _PY_STRING_RE.finditer(source):
        # group(1..4) are the capture groups for each alternative
        text = next((g for g in m.groups() if g is not None), "")
        text = text.strip()
        if not _looks_like_select(text):
            continue
        # There might be multiple SELECT statements in one big triple-quoted string
        for sel in _SELECT_RE.finditer(text):
            q = _normalise_query(sel.group(0))
            if q:
                queries.append(q)
    return queries


def _extract_from_sql(source: str) -> List[str]:
    """
    Extract all SELECT statements from a raw .sql file.

    Strips SQL comments first to avoid harvesting commented-out queries.
    """
    # Remove block comments
    clean = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    # Remove line comments
    clean = re.sub(r"--[^\n]*", "", clean)

    queries: List[str] = []
    for sel in _SELECT_RE.finditer(clean):
        q = _normalise_query(sel.group(0))
        if q:
            queries.append(q)
    return queries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def harvest_queries_from_code(filepath: str) -> List[str]:
    """
    Extract all SQL SELECT query strings from a single source file.

    Handles both Python (.py) source files (by scanning string literals) and
    raw SQL (.sql) files (by scanning directly for SELECT statements).

    Parameters
    ----------
    filepath : str
        Path to the source file (absolute or relative).

    Returns
    -------
    list[str]
        Unique, normalised SQL SELECT strings found in the file.
        Order matches the order they appear in the source.

    Raises
    ------
    FileNotFoundError
        If *filepath* does not exist.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {filepath}")

    source = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()

    if suffix == ".py":
        raw = _extract_from_python(source)
    elif suffix == ".sql":
        raw = _extract_from_sql(source)
    else:
        # Best-effort: try both strategies
        raw = _extract_from_python(source) or _extract_from_sql(source)

    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for q in raw:
        key = re.sub(r"\s+", " ", q).upper()
        if key not in seen:
            seen.add(key)
            unique.append(q)
    return unique


def harvest_codebase_queries(search_dir: str = "sample_data") -> List[Dict[str, str]]:
    """
    Scan all .py and .sql files under *search_dir* for embedded SQL queries.

    Parameters
    ----------
    search_dir : str
        Directory to scan (absolute or relative to CWD).

    Returns
    -------
    list[dict]
        One record per distinct query found:
            {
                "file":         str,   # absolute path of the source file
                "query":        str,   # normalised SQL text
                "target_table": str,   # first table after FROM
            }

    Note
    ----
    Files are scanned in deterministic alphabetical order so that results are
    reproducible across runs.
    """
    base = Path(search_dir).resolve()
    if not base.is_dir():
        return []

    records: List[Dict[str, str]] = []
    # Collect files in sorted order for reproducibility
    source_files = sorted(
        p for p in base.rglob("*")
        if p.is_file() and p.suffix.lower() in (".py", ".sql")
    )

    for src_path in source_files:
        try:
            queries = harvest_queries_from_code(str(src_path))
        except (FileNotFoundError, OSError):
            continue

        for q in queries:
            records.append(
                {
                    "file":         str(src_path),
                    "query":        q,
                    "target_table": _table_from_query(q),
                }
            )

    return records


# ---------------------------------------------------------------------------
# CLI entry point — smoke-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    base = os.path.dirname(os.path.abspath(__file__))
    results = harvest_codebase_queries(os.path.join(base, "sample_data"))

    print(f"[harvester] Found {len(results)} query record(s):\n")
    for r in results:
        rel = os.path.relpath(r["file"], base)
        print(f"  [{r['target_table']}]  {r['query'][:72]}")
        print(f"       in {rel}")
        print()
