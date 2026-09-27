# AGENTS.md — Ask Mode

This file provides guidance to agents when working with code in this repository.

## Key Context for Questions

- **`rehearse` exits 1 by design** — this is the documented expected exit code, not a bug.
- **"healing"** means creating a SQLite VIEW (not altering the table) so that legacy queries keep working after a destructive migration.
- **The `users` table is a VIEW after healing** — `users_v2` is the real physical table post-heal.
- **No persistent database exists** — everything runs in `:memory:`. There is no `.db` file to inspect.
- **`v2_breaking.sql` splits names on the first space** using `INSTR(name || ' ', ' ')`. The trailing-space trick handles single-word names (no index out-of-bounds).
- **`bifrost.py` is the only user-facing entrypoint.** `rehearsal.py` and `healer.py` are importable modules but are also runnable standalone (`__main__` guard present on both).
- **The canonical run to verify everything works: `python bifrost.py run`** — all four `✓ PASSED` lines must appear.
