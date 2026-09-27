# AGENTS.md — Plan Mode

This file provides guidance to agents when working with code in this repository.

## Architectural Constraints

- **Stateless by design.** Every run rebuilds from the SQL files in `sample_data/`. There is no shared mutable state between runs, no database file, and no caching. Extensions must preserve this.
- **Exit-code semantics are part of the contract.** `rehearse` → 1 (breaking change found), `heal` → 0 (legacy restored). `bifrost.py cmd_run()` inverts the rehearsal code when computing pipeline success. Any new sub-command must document its expected exit code explicitly.
- **Heal is a VIEW strategy, not a column backfill.** Adding `name TEXT` back to the table via ALTER is intentionally avoided — it would require a data migration and could fail on large datasets. The view approach is zero-cost and reversible.
- **Two independent in-memory environments.** `rehearsal.py` and `healer.py` each open their own `:memory:` connection and replay the full history from SQL files. They do not share a connection. This is intentional: each module is independently testable.
- **Windows compatibility constraint.** `bifrost.py` must call `sys.stdout.reconfigure(encoding="utf-8")` before any Unicode output. Any planned feature that adds output to `bifrost.py` must respect this ordering.
- **No test framework dependency.** Validation is done by running the pipeline and checking exit codes + printed output. If a formal test harness is added, it must not require `pip install` (use `unittest` from stdlib).
- **`bifrost.py` imports `rehearsal` and `healer` as local imports inside functions** — this is an intentional cycle-break, not a lazy import. Do not hoist them to module level.
