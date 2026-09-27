# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project

**Bifrost** — autonomous database rehearsal and zero-downtime rollback safety CLI.
Python 3.10+ standard library **only** (`sqlite3`, `os`, `sys`, `typing`, `io`). Zero external dependencies — do not add any.

## Commands

```bash
python bifrost.py run        # Full pipeline (rehearse → heal). Exit 0 = both stages OK.
python bifrost.py rehearse   # Sandbox migration only. Exit 1 is the EXPECTED success code.
python bifrost.py heal       # Compatibility shim only. Exit 0 is the EXPECTED success code.
python bifrost.py --help
```

> **Critical:** `rehearse` intentionally exits 1. In `bifrost.py cmd_run()`, `rehearse_ok = (rehearse_code == 1)` — a zero exit from rehearsal means the migration had no breaking change (unexpected). Do not change this logic.

No test runner configured. Validate by running `python bifrost.py run` — all four `✓ PASSED` lines must appear.

## Architecture

```
bifrost.py          CLI + formatted terminal output (ANSI colours, UTF-8 reconfigure for Windows)
  └─ rehearsal.py   In-memory SQLite sandbox: applies v1 → v2, runs legacy query → exit 1
  └─ healer.py      In-memory SQLite sandbox: applies v1 → v2, then renames table to users_v2
                    and creates a VIEW named users (exposes synthetic `name` column) → exit 0
sample_data/
  v1_schema.sql     CREATE TABLE users(id, name, email) + 3 seed rows
  v2_breaking.sql   Renames users→users_old, creates users(id, first_name, last_name, email),
                    migrates data by splitting name on first space, drops users_old
```

## Non-Obvious Patterns

- **All migration work is in-memory (`:memory:`)** — no file is ever written to disk. Both `rehearsal.py` and `healer.py` rebuild the full state from SQL files on every run.
- **Heal strategy**: the view is named `users` (same as the original table). The physical v2 table is renamed `users_v2`. This makes legacy `SELECT … FROM users` work transparently without any app changes.
- **Name-split logic in `v2_breaking.sql`** uses `INSTR(name || ' ', ' ')` (appends a trailing space) to handle single-word names without producing an out-of-bounds result.
- **Windows UTF-8**: `bifrost.py` calls `sys.stdout.reconfigure(encoding="utf-8")` at module top to avoid `cp1252` encode errors from the box-drawing characters. Any new print statements using Unicode must come after that block.
- **Local imports in `bifrost.py`**: `rehearsal` and `healer` are imported inside `cmd_rehearse()`/`cmd_heal()` to avoid circular dependency at module level. Keep them as local imports.
- **`conn.row_factory = sqlite3.Row`** is set in both modules but the heal view verification accesses columns by index (`r[0]`, `r[1]`, `r[2]`), not by name — keep it consistent.

## Code Style

- Module-level docstring on every file (first line, triple-quoted).
- Type hints on all function signatures (`-> int`, `-> Tuple[bool, str]`, etc.).
- Section dividers: `# ---…--- ` (78 dashes) with a label, consistent across all files.
- `Tuple` imported from `typing` (not `tuple[…]`) for 3.10 compatibility.
- Error messages to `sys.stderr`; progress messages to `stdout`.
- No bare `except` — always catch the specific exception (e.g., `sqlite3.OperationalError`).
