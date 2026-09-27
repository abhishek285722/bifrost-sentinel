# AGENTS.md — Agent (Coding) Mode

This file provides guidance to agents when working with code in this repository.

## Critical Coding Rules

- **No external packages.** `import` only from the Python 3.10+ standard library. Installing anything via pip breaks the zero-dependency contract.
- **`rehearse` exit 1 is intentional success.** Do not "fix" the non-zero exit in `rehearsal.py`. The orchestrator in `bifrost.py` maps `rehearse_code == 1` → `rehearse_ok = True`.
- **Local imports inside `cmd_rehearse` / `cmd_heal`** in `bifrost.py` are deliberate (avoids circular module-level import). Keep them there.
- **`sys.stdout.reconfigure(encoding="utf-8")` must stay at the top of `bifrost.py`** before any Unicode output. New Unicode print statements added to `bifrost.py` must come after that block.
- **SQL files are the single source of truth for schema.** Do not duplicate CREATE TABLE DDL in Python; always `_read_sql(path)` → `_apply_schema(conn, sql)`.
- **Heal creates a VIEW named `users`, not a table.** After healing, `users_v2` is the real table. Any code that assumes `users` is a table will break on a healed database.
- **Name-split in `v2_breaking.sql`** appends `|| ' '` before `INSTR` to handle single-word names. Preserve this when modifying the migration.
- **All work is in-memory.** Never open a file-backed SQLite DB (`sqlite3.connect("some.db")`). The architecture is stateless-by-design — each run rebuilds from SQL files.
- **`Tuple` from `typing`**, not built-in `tuple[…]`, for Python 3.10 compat.
- **Section dividers** use the 78-dash pattern `# ---…---` with a label. Follow this in any new module added to the project.
