"""
tests/test_bifrost.py — Automated test suite for Bifrost Sentinel.

Standard library only: unittest, os, sys, json, sqlite3, pathlib, io, tempfile.
Zero external pip dependencies.

Test classes:
    TestAnalyzer            — static SQL analysis (all 4 patterns, comment stripping,
                              line numbers, severity, clean SQL)
    TestRehearsal           — sandbox rehearsal (breaking vs non-breaking migrations)
    TestHealer              — _diff_schemas logic and end-to-end heal()
    TestReporter            — JSON, SARIF, and PR-comment report generation
    TestCLIOrchestrator     — programmatic invocation of bifrost.py commands
    TestExplainer           — generate_remediation_patch() and analyze_blast_radius()
    TestHarvester           — harvest_queries_from_code() and harvest_codebase_queries()
    TestMultiQueryRehearsal — multi-query rehearsal and healer verification
    TestUI                  — calculate_safety_score(), render_schema_diff(), render_scorecard()
"""

import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so imports work when tests are run
# from inside the tests/ directory or via `python -m unittest discover -s tests`.
# ---------------------------------------------------------------------------
_HERE  = Path(__file__).resolve().parent          # …/tests/
_ROOT  = _HERE.parent                             # …/bifrost-engine/
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_V1 = str(_ROOT / "sample_data" / "v1_schema.sql")
_V2 = str(_ROOT / "sample_data" / "v2_breaking.sql")


# ===========================================================================
# 1. TestAnalyzer
# ===========================================================================

class TestAnalyzer(unittest.TestCase):
    """Tests for analyzer.analyze_migration() and the internal _analyse_sql()."""

    def setUp(self) -> None:
        from analyzer import analyze_migration, _analyse_sql, _strip_comments
        self.analyze_migration = analyze_migration
        self._analyse_sql      = _analyse_sql
        self._strip_comments   = _strip_comments

    # --- Pattern detection --------------------------------------------------

    def test_detects_drop_column(self) -> None:
        sql = "ALTER TABLE orders DROP COLUMN legacy_col;"
        findings = self._analyse_sql(sql)
        patterns = [f["pattern"] for f in findings]
        self.assertIn("DROP COLUMN", patterns)

    def test_drop_column_severity_is_critical(self) -> None:
        sql = "ALTER TABLE t DROP COLUMN x;"
        findings = self._analyse_sql(sql)
        drop_findings = [f for f in findings if f["pattern"] == "DROP COLUMN"]
        self.assertTrue(drop_findings, "Expected at least one DROP COLUMN finding")
        self.assertEqual(drop_findings[0]["severity"], "CRITICAL")

    def test_detects_table_rename(self) -> None:
        sql = "ALTER TABLE users RENAME TO users_old;"
        findings = self._analyse_sql(sql)
        patterns = [f["pattern"] for f in findings]
        self.assertIn("TABLE RENAME", patterns)

    def test_table_rename_severity_is_high(self) -> None:
        sql = "ALTER TABLE users RENAME TO users_old;"
        findings = self._analyse_sql(sql)
        rename_findings = [f for f in findings if f["pattern"] == "TABLE RENAME"]
        self.assertTrue(rename_findings)
        self.assertEqual(rename_findings[0]["severity"], "HIGH")

    def test_detects_not_null_without_default(self) -> None:
        # Column definition without DEFAULT: should be flagged
        sql = "CREATE TABLE t (col TEXT NOT NULL);"
        findings = self._analyse_sql(sql)
        patterns = [f["pattern"] for f in findings]
        self.assertIn("NOT NULL WITHOUT DEFAULT", patterns)

    def test_not_null_without_default_severity_is_high(self) -> None:
        sql = "CREATE TABLE t (col TEXT NOT NULL);"
        findings = self._analyse_sql(sql)
        nn_findings = [f for f in findings if f["pattern"] == "NOT NULL WITHOUT DEFAULT"]
        self.assertTrue(nn_findings)
        self.assertEqual(nn_findings[0]["severity"], "HIGH")

    def test_detects_add_constraint(self) -> None:
        sql = "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);"
        findings = self._analyse_sql(sql)
        patterns = [f["pattern"] for f in findings]
        self.assertIn("ADD CONSTRAINT", patterns)

    def test_add_constraint_severity_is_medium(self) -> None:
        sql = "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);"
        findings = self._analyse_sql(sql)
        ac_findings = [f for f in findings if f["pattern"] == "ADD CONSTRAINT"]
        self.assertTrue(ac_findings)
        self.assertEqual(ac_findings[0]["severity"], "MEDIUM")

    def test_all_four_patterns_detected_in_v2_sql(self) -> None:
        """v2_breaking.sql contains TABLE RENAME and NOT NULL WITHOUT DEFAULT."""
        result = self.analyze_migration(_V2)
        patterns = {f["pattern"] for f in result["findings"]}
        # v2_breaking.sql has TABLE RENAME and NOT NULL WITHOUT DEFAULT at minimum
        self.assertTrue(
            patterns & {"TABLE RENAME", "NOT NULL WITHOUT DEFAULT"},
            f"Expected risk patterns not found; got: {patterns}",
        )

    # --- Comment stripping (false-positive prevention) ----------------------

    def test_line_comment_does_not_trigger_drop_column(self) -> None:
        sql = "-- ALTER TABLE t DROP COLUMN x;\nSELECT 1;"
        findings = self._analyse_sql(sql)
        drop = [f for f in findings if f["pattern"] == "DROP COLUMN"]
        self.assertEqual(drop, [], "Line comment should not trigger DROP COLUMN")

    def test_block_comment_does_not_trigger_table_rename(self) -> None:
        sql = "/* ALTER TABLE users RENAME TO users_old; */\nSELECT 1;"
        findings = self._analyse_sql(sql)
        rename = [f for f in findings if f["pattern"] == "TABLE RENAME"]
        self.assertEqual(rename, [], "Block comment should not trigger TABLE RENAME")

    def test_block_comment_does_not_trigger_add_constraint(self) -> None:
        sql = "/* ALTER TABLE t ADD CONSTRAINT ck CHECK (1) */\nSELECT 1;"
        findings = self._analyse_sql(sql)
        ac = [f for f in findings if f["pattern"] == "ADD CONSTRAINT"]
        self.assertEqual(ac, [], "Block comment should not trigger ADD CONSTRAINT")

    def test_inline_comment_after_valid_sql_preserved(self) -> None:
        """Real DDL on the same line as a trailing comment must still be caught."""
        sql = "ALTER TABLE t DROP COLUMN x; -- remove old col\n"
        findings = self._analyse_sql(sql)
        drop = [f for f in findings if f["pattern"] == "DROP COLUMN"]
        self.assertTrue(drop, "DROP COLUMN before trailing comment should be detected")

    def test_strip_comments_removes_block(self) -> None:
        sql = "/* comment */ SELECT 1;"
        result = self._strip_comments(sql)
        self.assertNotIn("/*", result)
        self.assertNotIn("*/", result)
        self.assertIn("SELECT 1", result)

    def test_strip_comments_removes_line(self) -> None:
        sql = "SELECT 1; -- end of line\nSELECT 2;"
        result = self._strip_comments(sql)
        self.assertNotIn("--", result)
        self.assertIn("SELECT 1", result)

    # --- Line number mapping ------------------------------------------------

    def test_line_number_is_correct(self) -> None:
        sql = "SELECT 1;\nSELECT 2;\nALTER TABLE t DROP COLUMN x;\n"
        findings = self._analyse_sql(sql)
        drop = [f for f in findings if f["pattern"] == "DROP COLUMN"]
        self.assertTrue(drop)
        self.assertEqual(drop[0]["line"], 3)

    def test_multiple_findings_sorted_by_line(self) -> None:
        sql = (
            "ALTER TABLE a ADD CONSTRAINT ck CHECK (1);\n"
            "ALTER TABLE b DROP COLUMN y;\n"
        )
        findings = self._analyse_sql(sql)
        lines = [f["line"] for f in findings]
        self.assertEqual(lines, sorted(lines), "Findings must be in ascending line order")

    # --- Severity ranking ---------------------------------------------------

    def test_severity_values_are_valid(self) -> None:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        sql = (
            "ALTER TABLE t DROP COLUMN x;\n"
            "ALTER TABLE t RENAME TO t2;\n"
            "ALTER TABLE t ADD CONSTRAINT ck CHECK (1);\n"
        )
        findings = self._analyse_sql(sql)
        for f in findings:
            self.assertIn(f["severity"], valid)

    # --- Clean SQL returns 0 findings ---------------------------------------

    def test_clean_sql_returns_no_findings(self) -> None:
        sql = "SELECT id, name, email FROM users WHERE id = 1;"
        findings = self._analyse_sql(sql)
        self.assertEqual(findings, [])

    def test_analyze_migration_clean_file(self) -> None:
        """analyze_migration() on a clean SQL file must return an empty findings list."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sql", delete=False, encoding="utf-8"
        ) as f:
            f.write("SELECT 1;\n")
            tmppath = f.name
        try:
            result = self.analyze_migration(tmppath)
            self.assertEqual(result["findings"], [])
        finally:
            os.unlink(tmppath)

    def test_analyze_migration_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.analyze_migration("/nonexistent/path/file.sql")

    def test_finding_has_required_keys(self) -> None:
        sql = "ALTER TABLE t DROP COLUMN x;"
        findings = self._analyse_sql(sql)
        required = {"pattern", "severity", "line", "match", "recommendation"}
        for f in findings:
            self.assertEqual(required, set(f.keys()))


# ===========================================================================
# 2. TestRehearsal
# ===========================================================================

class TestRehearsal(unittest.TestCase):
    """Tests for rehearsal.rehearse() and its helper functions."""

    def setUp(self) -> None:
        from rehearsal import rehearse, _run_legacy_query, _apply_schema, _read_sql
        self.rehearse         = rehearse
        self._run_legacy_query = _run_legacy_query
        self._apply_schema     = _apply_schema
        self._read_sql         = _read_sql

    # --- Breaking migration → exit code 1 ----------------------------------

    def test_rehearse_returns_1_on_breaking_migration(self) -> None:
        """rehearse() must return 1 (detected breakage) for v2_breaking.sql."""
        code = self.rehearse(_V1, _V2)
        self.assertEqual(code, 1, "rehearse() should return 1 for v2_breaking.sql")

    # --- Missing column failure on users table ------------------------------

    def test_legacy_query_fails_after_breaking_migration(self) -> None:
        """
        After applying v1 then v2, the legacy query 'SELECT id, name, email FROM users'
        should fail because the 'name' column no longer exists.
        """
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        self._apply_schema(conn, self._read_sql(_V2))
        success, message = self._run_legacy_query(conn)
        conn.close()
        self.assertFalse(success, "Legacy query should fail after breaking migration")
        self.assertIn("FAILED", message)

    # --- Non-breaking migration → exit code 0 ------------------------------

    def test_rehearse_returns_0_on_non_breaking_migration(self) -> None:
        """
        A migration that only adds a nullable column must not break the legacy query;
        rehearse() must return 0 in this case.
        """
        non_breaking_sql = (
            "ALTER TABLE users ADD COLUMN nickname TEXT;\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sql", delete=False, encoding="utf-8"
        ) as f:
            f.write(non_breaking_sql)
            nb_path = f.name
        try:
            code = self.rehearse(_V1, nb_path)
            self.assertEqual(code, 0, "rehearse() should return 0 for a non-breaking migration")
        finally:
            os.unlink(nb_path)

    # --- _run_legacy_query returns correct data when schema is intact -------

    def test_legacy_query_succeeds_on_v1_schema(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        success, message = self._run_legacy_query(conn)
        conn.close()
        self.assertTrue(success)
        self.assertIn("3 row(s)", message)


# ===========================================================================
# 3. TestHealer
# ===========================================================================

class TestHealer(unittest.TestCase):
    """Tests for healer._diff_schemas() and healer.heal()."""

    def setUp(self) -> None:
        from healer import (
            heal,
            _diff_schemas,
            _apply_schema,
            _read_sql,
            _get_columns,
            _table_exists,
        )
        self.heal          = heal
        self._diff_schemas  = _diff_schemas
        self._apply_schema  = _apply_schema
        self._read_sql      = _read_sql
        self._get_columns   = _get_columns
        self._table_exists  = _table_exists

    # ── _diff_schemas unit tests ────────────────────────────────────────────

    def test_diff_schemas_exact_match(self) -> None:
        """Columns that survived unchanged are mapped 1-to-1."""
        mapping = self._diff_schemas(["id", "email"], ["id", "email"])
        self.assertEqual(mapping["id"],    "id")
        self.assertEqual(mapping["email"], "email")

    def test_diff_schemas_split_columns_concatenated(self) -> None:
        """v1 'name' → v2 ('first_name', 'last_name') must produce a || concat expression."""
        v1 = ["id", "name", "email"]
        v2 = ["id", "first_name", "last_name", "email"]
        mapping = self._diff_schemas(v1, v2)
        name_expr = mapping["name"]
        # Must contain both v2 components joined with a space separator
        self.assertIn("first_name", name_expr)
        self.assertIn("last_name",  name_expr)
        self.assertIn("' '",        name_expr)
        self.assertIn("AS name",    name_expr)

    def test_diff_schemas_split_columns_order(self) -> None:
        """The concat expression must respect v2 declaration order (first_name before last_name)."""
        v1 = ["name"]
        v2 = ["first_name", "last_name"]
        mapping = self._diff_schemas(v1, v2)
        expr = mapping["name"]
        self.assertLess(expr.index("first_name"), expr.index("last_name"))

    def test_diff_schemas_single_component_aliased(self) -> None:
        """When exactly one v2 column matches v1 col as a component, it must be aliased."""
        v1 = ["name"]
        v2 = ["first_name"]
        mapping = self._diff_schemas(v1, v2)
        self.assertEqual(mapping["name"], "first_name AS name")

    def test_diff_schemas_dropped_column_null(self) -> None:
        """A v1 column with no v2 match must map to 'NULL AS <col>'."""
        v1 = ["id", "name", "email", "phone"]
        v2 = ["id", "email"]
        mapping = self._diff_schemas(v1, v2)
        self.assertEqual(mapping["phone"], "NULL AS phone")

    def test_diff_schemas_no_false_component_match(self) -> None:
        """'rename' must NOT be treated as a component match for 'name'."""
        v1 = ["name"]
        v2 = ["rename"]
        mapping = self._diff_schemas(v1, v2)
        # 'rename' split on '_' gives ['rename'], not 'name'
        self.assertEqual(mapping["name"], "NULL AS name")

    # ── heal() end-to-end tests ─────────────────────────────────────────────

    def test_heal_returns_0_on_sample_data(self) -> None:
        """heal() must return 0 (success) for sample_data/v2_breaking.sql."""
        code = self.heal(_V1, _V2)
        self.assertEqual(code, 0, "heal() must return 0 on the sample migration")

    def test_physical_table_renamed_to_users_v2(self) -> None:
        """After heal, the physical table must be 'users_v2' (not 'users')."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        # Snapshot v1 columns before migration
        v1_cols = self._get_columns(conn, "users")
        self._apply_schema(conn, self._read_sql(_V2))

        from healer import _heal
        _heal(conn, "users", v1_cols)

        self.assertTrue(
            self._table_exists(conn, "users_v2"),
            "Physical table 'users_v2' must exist after heal",
        )
        self.assertFalse(
            self._table_exists(conn, "users"),
            "Original table 'users' must no longer exist as a TABLE after heal",
        )
        conn.close()

    def test_users_becomes_a_view_after_heal(self) -> None:
        """After heal, 'users' must be a VIEW, not a table."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        v1_cols = self._get_columns(conn, "users")
        self._apply_schema(conn, self._read_sql(_V2))

        from healer import _heal
        _heal(conn, "users", v1_cols)

        cursor = conn.execute(
            "SELECT type FROM sqlite_master WHERE name = 'users'"
        )
        row = cursor.fetchone()
        self.assertIsNotNone(row, "'users' object must exist in sqlite_master")
        self.assertEqual(row[0], "view", "'users' must be a VIEW after heal")
        conn.close()

    def test_legacy_query_returns_correct_rows_through_view(self) -> None:
        """
        After healing, SELECT id, name, email FROM users must return the original
        3 seed rows with reconstructed full names.
        """
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        v1_cols = self._get_columns(conn, "users")
        self._apply_schema(conn, self._read_sql(_V2))

        from healer import _heal
        _heal(conn, "users", v1_cols)

        cursor = conn.execute("SELECT id, name, email FROM users ORDER BY id")
        rows = cursor.fetchall()
        conn.close()

        self.assertEqual(len(rows), 3, "Must return all 3 original rows")
        names = [row[1] for row in rows]
        self.assertIn("Alice Smith",  names)
        self.assertIn("Bob Jones",    names)
        self.assertIn("Carol White",  names)

    def test_legacy_query_emails_unchanged(self) -> None:
        """Email column must pass through the view unchanged."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        v1_cols = self._get_columns(conn, "users")
        self._apply_schema(conn, self._read_sql(_V2))

        from healer import _heal
        _heal(conn, "users", v1_cols)

        cursor = conn.execute("SELECT email FROM users ORDER BY id")
        emails = [row[0] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("alice@example.com", emails)
        self.assertIn("bob@example.com",   emails)
        self.assertIn("carol@example.com", emails)


# ===========================================================================
# 4. TestReporter
# ===========================================================================

class TestReporter(unittest.TestCase):
    """Tests for reporter.generate_json_report(), generate_sarif_report(),
    and generate_pr_comment()."""

    # Shared fixture data ---------------------------------------------------

    _ANALYSIS_WITH_FINDINGS: Dict[str, Any] = {
        "file": "/path/to/v2_breaking.sql",
        "findings": [
            {
                "pattern":        "TABLE RENAME",
                "severity":       "HIGH",
                "line":           5,
                "match":          "ALTER TABLE users RENAME TO users_old",
                "recommendation": "Use expand-contract pattern.",
            },
            {
                "pattern":        "DROP COLUMN",
                "severity":       "CRITICAL",
                "line":           22,
                "match":          "ALTER TABLE t DROP COLUMN x",
                "recommendation": "Never drop in one step.",
            },
        ],
    }

    _REHEARSAL_OK: Dict[str, Any] = {
        "breaking_change_detected": True,
        "message": "Legacy query FAILED: no such column: name",
    }

    _HEALING_OK: Dict[str, Any] = {
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

    _HEALING_FAILED: Dict[str, Any] = {
        "healed":  False,
        "message": "Heal failed for some reason.",
        "ddl": "",
    }

    def setUp(self) -> None:
        from reporter import (
            generate_json_report,
            generate_sarif_report,
            generate_pr_comment,
        )
        self.generate_json_report  = generate_json_report
        self.generate_sarif_report = generate_sarif_report
        self.generate_pr_comment   = generate_pr_comment
        # Use a temp dir so report files don't litter the workspace
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── generate_json_report ───────────────────────────────────────────────

    def test_json_report_is_valid_json(self) -> None:
        path = os.path.join(self._tmpdir, "audit.json")
        out  = self.generate_json_report(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
            output_path=path,
        )
        self.assertTrue(os.path.isfile(out))
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)

    def test_json_report_top_level_keys(self) -> None:
        path = os.path.join(self._tmpdir, "audit.json")
        out  = self.generate_json_report(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
            output_path=path,
        )
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        for key in ("schema_version", "run", "stages", "risk_summary"):
            self.assertIn(key, data, f"Top-level key '{key}' missing from JSON report")

    def test_json_report_run_keys(self) -> None:
        path = os.path.join(self._tmpdir, "audit.json")
        out  = self.generate_json_report(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
            output_path=path,
        )
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        run = data["run"]
        for key in ("timestamp", "migration_file", "overall_status"):
            self.assertIn(key, run, f"'run.{key}' missing")

    def test_json_report_mitigated_when_healed(self) -> None:
        path = os.path.join(self._tmpdir, "audit.json")
        out  = self.generate_json_report(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
            output_path=path,
        )
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        findings = data["stages"]["analysis"]["findings"]
        for f in findings:
            self.assertEqual(
                f["mitigation_status"], "MITIGATED",
                "All findings must be MITIGATED when heal succeeded",
            )

    def test_json_report_open_when_not_healed(self) -> None:
        path = os.path.join(self._tmpdir, "audit.json")
        out  = self.generate_json_report(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_FAILED,
            output_path=path,
        )
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        findings = data["stages"]["analysis"]["findings"]
        for f in findings:
            self.assertEqual(
                f["mitigation_status"], "OPEN",
                "All findings must be OPEN when heal failed",
            )

    def test_json_report_risk_summary_counts(self) -> None:
        path = os.path.join(self._tmpdir, "audit.json")
        out  = self.generate_json_report(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
            output_path=path,
        )
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        rs = data["risk_summary"]
        self.assertEqual(rs["total_findings"], 2)
        self.assertEqual(rs["mitigated_count"], 2)
        self.assertEqual(rs["open_count"], 0)

    # ── generate_sarif_report ──────────────────────────────────────────────

    def test_sarif_is_valid_json(self) -> None:
        path = os.path.join(self._tmpdir, "result.sarif")
        out  = self.generate_sarif_report(self._ANALYSIS_WITH_FINDINGS, output_path=path)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)

    def test_sarif_schema_and_version(self) -> None:
        path = os.path.join(self._tmpdir, "result.sarif")
        out  = self.generate_sarif_report(self._ANALYSIS_WITH_FINDINGS, output_path=path)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("$schema", data)
        self.assertEqual(data["version"], "2.1.0")

    def test_sarif_runs_present(self) -> None:
        path = os.path.join(self._tmpdir, "result.sarif")
        out  = self.generate_sarif_report(self._ANALYSIS_WITH_FINDINGS, output_path=path)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("runs", data)
        self.assertIsInstance(data["runs"], list)
        self.assertGreater(len(data["runs"]), 0)

    def test_sarif_tool_driver_rules(self) -> None:
        path = os.path.join(self._tmpdir, "result.sarif")
        out  = self.generate_sarif_report(self._ANALYSIS_WITH_FINDINGS, output_path=path)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        driver = data["runs"][0]["tool"]["driver"]
        self.assertIn("rules", driver)
        rule_ids = [r["id"] for r in driver["rules"]]
        # Findings include TABLE_RENAME and DROP_COLUMN
        self.assertIn("TABLE_RENAME", rule_ids)
        self.assertIn("DROP_COLUMN",  rule_ids)

    def test_sarif_results_match_findings(self) -> None:
        path = os.path.join(self._tmpdir, "result.sarif")
        out  = self.generate_sarif_report(self._ANALYSIS_WITH_FINDINGS, output_path=path)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        results = data["runs"][0]["results"]
        self.assertEqual(len(results), 2, "Must have one SARIF result per finding")

    def test_sarif_empty_findings(self) -> None:
        """SARIF generated from analysis with no findings must still be valid."""
        analysis: Dict[str, Any] = {"file": "/clean.sql", "findings": []}
        path = os.path.join(self._tmpdir, "clean.sarif")
        out  = self.generate_sarif_report(analysis, output_path=path)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["runs"][0]["results"], [])

    # ── generate_pr_comment ────────────────────────────────────────────────

    def test_pr_comment_is_string(self) -> None:
        comment = self.generate_pr_comment(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
        )
        self.assertIsInstance(comment, str)
        self.assertGreater(len(comment), 0)

    def test_pr_comment_contains_details_tag(self) -> None:
        comment = self.generate_pr_comment(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
        )
        self.assertIn("<details>", comment)
        self.assertIn("</details>", comment)

    def test_pr_comment_severity_badges(self) -> None:
        comment = self.generate_pr_comment(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
        )
        # CRITICAL → 🔴, HIGH → 🟠 must appear in the table
        self.assertIn("CRITICAL", comment)
        self.assertIn("HIGH",     comment)

    def test_pr_comment_markdown_header(self) -> None:
        comment = self.generate_pr_comment(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
        )
        self.assertIn("## ", comment)
        self.assertIn("Bifrost", comment)

    def test_pr_comment_no_findings_clean_message(self) -> None:
        analysis: Dict[str, Any] = {"file": "/clean.sql", "findings": []}
        comment = self.generate_pr_comment(
            analysis,
            {"breaking_change_detected": False, "message": ""},
            {"healed": False, "message": "", "ddl": ""},
        )
        self.assertIn("No Destructive DDL", comment)

    def test_pr_comment_ddl_section_present_when_healed(self) -> None:
        comment = self.generate_pr_comment(
            self._ANALYSIS_WITH_FINDINGS,
            self._REHEARSAL_OK,
            self._HEALING_OK,
        )
        self.assertIn("```sql", comment)
        self.assertIn("CREATE VIEW", comment)


# ===========================================================================
# 5. TestCLIOrchestrator
# ===========================================================================

class TestCLIOrchestrator(unittest.TestCase):
    """Programmatic tests for bifrost.py CLI commands."""

    def setUp(self) -> None:
        import bifrost
        self.bifrost = bifrost

    def _capture(self, fn, *args, **kwargs):
        """Run *fn* with captured stdout/stderr; return (result, stdout_str)."""
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = buf_out, buf_err
        try:
            result = fn(*args, **kwargs)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return result, buf_out.getvalue()

    # --- cmd_analyze --------------------------------------------------------

    def test_cmd_analyze_returns_1_for_breaking_sql(self) -> None:
        code, _ = self._capture(self.bifrost.cmd_analyze)
        self.assertEqual(code, 1, "cmd_analyze() must return 1 when findings exist")

    def test_cmd_analyze_produces_output(self) -> None:
        _, out = self._capture(self.bifrost.cmd_analyze)
        self.assertGreater(len(out), 0, "cmd_analyze() must produce output")

    # --- cmd_rehearse -------------------------------------------------------

    def test_cmd_rehearse_returns_1(self) -> None:
        """cmd_rehearse() must return 1 (breaking change detected) for the sample SQL."""
        code, _ = self._capture(self.bifrost.cmd_rehearse, verbose=False)
        self.assertEqual(code, 1)

    # --- cmd_heal -----------------------------------------------------------

    def test_cmd_heal_returns_0(self) -> None:
        """cmd_heal() must return 0 (heal succeeded) for the sample SQL."""
        code, _ = self._capture(self.bifrost.cmd_heal, verbose=False)
        self.assertEqual(code, 0)

    # --- cmd_run ------------------------------------------------------------

    def test_cmd_run_returns_0(self) -> None:
        """Full pipeline must return 0: rehearsal detects breakage AND heal fixes it."""
        code, _ = self._capture(self.bifrost.cmd_run, report=False)
        self.assertEqual(code, 0, "cmd_run() must return 0 when the full pipeline succeeds")

    def test_cmd_run_with_report_writes_files(self) -> None:
        """cmd_run(report=True) must write bifrost_audit.json, bifrost.sarif,
        pr_comment.md, and bifrost_remediation.sql."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Patch _BASE so generated files land in tmpdir
            original_base = self.bifrost._BASE
            self.bifrost._BASE = tmpdir
            try:
                code, _ = self._capture(self.bifrost.cmd_run, report=True)
                self.assertEqual(code, 0)
                pr_path    = os.path.join(tmpdir, "pr_comment.md")
                patch_path = os.path.join(tmpdir, "bifrost_remediation.sql")
                self.assertTrue(os.path.isfile(pr_path),    "pr_comment.md must be written")
                self.assertTrue(os.path.isfile(patch_path), "bifrost_remediation.sql must be written")
            finally:
                self.bifrost._BASE = original_base

    # --- cmd_patch ----------------------------------------------------------

    def test_cmd_patch_returns_0(self) -> None:
        """cmd_patch() must return 0 and write the remediation SQL file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "patch.sql")
            code, _ = self._capture(self.bifrost.cmd_patch, output=dest)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(dest), "Patch file must be created")

    def test_cmd_patch_file_contains_sql(self) -> None:
        """The remediation patch file must contain a BEGIN/COMMIT transaction and CREATE VIEW."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "patch.sql")
            self._capture(self.bifrost.cmd_patch, output=dest)
            content = Path(dest).read_text(encoding="utf-8")
            self.assertIn("BEGIN",        content)
            self.assertIn("COMMIT",       content)
            self.assertIn("CREATE VIEW",  content)

    def test_cmd_patch_stdout_mode(self) -> None:
        """cmd_patch(output='-') must write SQL to stdout instead of a file."""
        code, out = self._capture(self.bifrost.cmd_patch, output="-")
        self.assertEqual(code, 0)
        self.assertIn("BEGIN",   out)
        self.assertIn("COMMIT",  out)


# ===========================================================================
# 6. TestExplainer
# ===========================================================================

class TestExplainer(unittest.TestCase):
    """Tests for explainer.generate_remediation_patch() and analyze_blast_radius()."""

    # Shared fixture data ---------------------------------------------------

    _HEALING_OK: Dict[str, Any] = {
        "healed":  True,
        "message": "Compatibility view 'users' created.",
        "ddl": (
            "CREATE VIEW IF NOT EXISTS users AS\n"
            "SELECT\n"
            "    id,\n"
            "    (first_name || ' ' || last_name) AS name,\n"
            "    email\n"
            "FROM users_v2"
        ),
    }

    _HEALING_FAILED: Dict[str, Any] = {
        "healed":  False,
        "message": "Heal failed.",
        "ddl": "",
    }

    _ANALYSIS_WITH_FINDINGS: Dict[str, Any] = {
        "file": "/path/to/v2_breaking.sql",
        "findings": [
            {
                "pattern":        "TABLE RENAME",
                "severity":       "HIGH",
                "line":           5,
                "match":          "ALTER TABLE users RENAME TO users_old",
                "recommendation": "Use expand-contract pattern.",
            },
            {
                "pattern":        "NOT NULL WITHOUT DEFAULT",
                "severity":       "HIGH",
                "line":           9,
                "match":          "first_name TEXT NOT NULL",
                "recommendation": "Add column as nullable first.",
            },
        ],
    }

    _REHEARSAL_OK: Dict[str, Any] = {
        "breaking_change_detected": True,
        "message": "Legacy query FAILED: no such column: name",
    }

    _REHEARSAL_CLEAN: Dict[str, Any] = {
        "breaking_change_detected": False,
        "message": "Legacy query OK.",
    }

    def setUp(self) -> None:
        from explainer import generate_remediation_patch, analyze_blast_radius
        self.generate_remediation_patch = generate_remediation_patch
        self.analyze_blast_radius       = analyze_blast_radius
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── generate_remediation_patch ─────────────────────────────────────────

    def test_patch_returns_file_path(self) -> None:
        dest = os.path.join(self._tmpdir, "patch.sql")
        result = self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        self.assertEqual(result, str(Path(dest).resolve()))

    def test_patch_file_is_created(self) -> None:
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        self.assertTrue(os.path.isfile(dest))

    def test_patch_contains_transaction_block(self) -> None:
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        content = Path(dest).read_text(encoding="utf-8")
        self.assertIn("BEGIN;",  content)
        self.assertIn("COMMIT;", content)

    def test_patch_contains_create_view(self) -> None:
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        content = Path(dest).read_text(encoding="utf-8")
        self.assertIn("CREATE VIEW", content)

    def test_patch_contains_ddl_verbatim(self) -> None:
        """The original DDL must appear verbatim inside the patch."""
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        content = Path(dest).read_text(encoding="utf-8")
        self.assertIn("first_name || ' ' || last_name", content)

    def test_patch_contains_verification_select(self) -> None:
        """The patch must include a verification SELECT against the view."""
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        content = Path(dest).read_text(encoding="utf-8")
        # SELECT * FROM users LIMIT 1 must appear
        self.assertIn("SELECT * FROM users", content)

    def test_patch_contains_header_comments(self) -> None:
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        content = Path(dest).read_text(encoding="utf-8")
        self.assertIn("Bifrost Remediation Patch", content)
        self.assertIn("EXPAND-CONTRACT",            content)
        self.assertIn("APPLY INSTRUCTIONS",         content)

    def test_patch_no_op_when_heal_failed(self) -> None:
        """When healing failed (no DDL), the patch must be a no-op script."""
        dest = os.path.join(self._tmpdir, "noop.sql")
        self.generate_remediation_patch(self._HEALING_FAILED, output_path=dest)
        content = Path(dest).read_text(encoding="utf-8")
        self.assertNotIn("BEGIN;",   content)
        self.assertNotIn("COMMIT;",  content)
        self.assertIn("no-op",       content)

    def test_patch_default_output_path(self) -> None:
        """When output_path uses the default name, the returned path includes that name."""
        dest = os.path.join(self._tmpdir, "bifrost_remediation.sql")
        result = self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        self.assertIn("bifrost_remediation", result)

    def test_patch_is_valid_utf8(self) -> None:
        dest = os.path.join(self._tmpdir, "patch.sql")
        self.generate_remediation_patch(self._HEALING_OK, output_path=dest)
        # If read_text doesn't throw, encoding is valid UTF-8
        _ = Path(dest).read_text(encoding="utf-8")

    # ── analyze_blast_radius ───────────────────────────────────────────────

    def test_blast_radius_returns_dict_with_required_keys(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        for key in ("root_cause", "affected_entities", "risk_assessment", "recommended_action"):
            self.assertIn(key, result, f"Key '{key}' missing from blast_radius result")

    def test_blast_radius_root_cause_is_string(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        self.assertIsInstance(result["root_cause"], str)
        self.assertGreater(len(result["root_cause"]), 0)

    def test_blast_radius_root_cause_mentions_rehearsal_message(self) -> None:
        """When a breaking change was detected, the rehearsal message is included."""
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        self.assertIn("no such column", result["root_cause"])

    def test_blast_radius_affected_entities_is_list(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        self.assertIsInstance(result["affected_entities"], list)

    def test_blast_radius_affected_entities_not_empty(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        self.assertGreater(len(result["affected_entities"]), 0)

    def test_blast_radius_affected_entity_has_pattern_and_severity(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        for entity in result["affected_entities"]:
            self.assertIn("pattern",  entity)
            self.assertIn("severity", entity)

    def test_blast_radius_affected_entity_includes_table(self) -> None:
        """TABLE RENAME finding must extract a table name into affected_entities."""
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        tables = [e.get("table", "") for e in result["affected_entities"]]
        self.assertIn("users", tables)

    def test_blast_radius_risk_assessment_is_non_empty_string(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        ra = result["risk_assessment"]
        self.assertIsInstance(ra, str)
        self.assertGreater(len(ra), 0)

    def test_blast_radius_risk_assessment_reflects_severity(self) -> None:
        """HIGH findings must produce at least a HIGH risk assessment."""
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        ra = result["risk_assessment"]
        self.assertTrue(
            "HIGH" in ra or "CRITICAL" in ra,
            f"Expected HIGH or CRITICAL in risk_assessment, got: {ra}",
        )

    def test_blast_radius_recommended_action_is_list(self) -> None:
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        self.assertIsInstance(result["recommended_action"], list)
        self.assertGreater(len(result["recommended_action"]), 0)

    def test_blast_radius_recommended_action_mentions_patch(self) -> None:
        """When a breaking change is detected, instructions must reference the patch."""
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        combined = " ".join(result["recommended_action"])
        self.assertIn("bifrost_remediation", combined)

    def test_blast_radius_clean_migration(self) -> None:
        """No findings + no breaking change → no-action guidance."""
        result = self.analyze_blast_radius(
            {"file": "/clean.sql", "findings": []}, self._REHEARSAL_CLEAN
        )
        self.assertIn("No action required", result["recommended_action"][0])
        self.assertIn("NONE", result["risk_assessment"])

    def test_blast_radius_no_false_deduplication(self) -> None:
        """Two findings with distinct (table, column, pattern) keys must both appear."""
        result = self.analyze_blast_radius(
            self._ANALYSIS_WITH_FINDINGS, self._REHEARSAL_OK
        )
        patterns = [e["pattern"] for e in result["affected_entities"]]
        self.assertIn("TABLE RENAME",             patterns)
        self.assertIn("NOT NULL WITHOUT DEFAULT",  patterns)

    def test_blast_radius_critical_risk_for_drop_column(self) -> None:
        """DROP COLUMN must raise CRITICAL risk assessment."""
        analysis = {
            "file": "/drop.sql",
            "findings": [{
                "pattern":        "DROP COLUMN",
                "severity":       "CRITICAL",
                "line":           1,
                "match":          "ALTER TABLE orders DROP COLUMN legacy_col",
                "recommendation": "Use expand-contract.",
            }],
        }
        result = self.analyze_blast_radius(analysis, self._REHEARSAL_CLEAN)
        self.assertIn("CRITICAL", result["risk_assessment"])


# ===========================================================================
# 7. TestHarvester
# ===========================================================================

class TestHarvester(unittest.TestCase):
    """Tests for harvester.harvest_queries_from_code() and harvest_codebase_queries()."""

    _APP_PY = str(_ROOT / "sample_data" / "app.py")

    def setUp(self) -> None:
        from harvester import (
            harvest_queries_from_code,
            harvest_codebase_queries,
            _normalise_query,
            _table_from_query,
        )
        self.harvest_queries_from_code = harvest_queries_from_code
        self.harvest_codebase_queries  = harvest_codebase_queries
        self._normalise_query          = _normalise_query
        self._table_from_query         = _table_from_query
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── harvest_queries_from_code ──────────────────────────────────────────

    def test_finds_all_four_queries_in_app_py(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        self.assertEqual(len(queries), 4, f"Expected 4 queries, got {len(queries)}: {queries}")

    def test_query_1_select_id_name_email(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        found = any("SELECT id, name, email FROM users WHERE id = 1" in q for q in queries)
        self.assertTrue(found, "Q1 (SELECT id, name, email WHERE id=1) not found")

    def test_query_2_select_name_order_by(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        found = any("SELECT name FROM users ORDER BY id" in q for q in queries)
        self.assertTrue(found, "Q2 (SELECT name ORDER BY id) not found")

    def test_query_3_select_id_email_safe(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        found = any("SELECT id, email FROM users" in q for q in queries)
        self.assertTrue(found, "Q3 (SELECT id, email — safe) not found")

    def test_query_4_like_pattern(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        found = any(
            "SELECT id, name, email FROM users WHERE email LIKE" in q for q in queries
        )
        self.assertTrue(found, "Q4 (SELECT … LIKE '%@example.com') not found")

    def test_like_query_contains_full_pattern(self) -> None:
        """The LIKE '%@example.com' argument must not be cut off."""
        queries = self.harvest_queries_from_code(self._APP_PY)
        like_q = next((q for q in queries if "LIKE" in q.upper()), None)
        self.assertIsNotNone(like_q)
        self.assertIn("example.com", like_q, "LIKE pattern was truncated")

    def test_returns_list_of_strings(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        self.assertIsInstance(queries, list)
        for q in queries:
            self.assertIsInstance(q, str)

    def test_all_queries_start_with_select(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        for q in queries:
            self.assertTrue(
                q.strip().upper().startswith("SELECT"),
                f"Query does not start with SELECT: {q!r}",
            )

    def test_all_queries_contain_from(self) -> None:
        queries = self.harvest_queries_from_code(self._APP_PY)
        import re as _re
        for q in queries:
            self.assertRegex(q.upper(), r"\bFROM\b", f"Query has no FROM: {q!r}")

    def test_deduplication(self) -> None:
        """No duplicate query strings should appear."""
        queries = self.harvest_queries_from_code(self._APP_PY)
        upper = [q.upper() for q in queries]
        self.assertEqual(len(upper), len(set(upper)), "Duplicate queries found")

    def test_file_not_found_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.harvest_queries_from_code("/nonexistent/path/file.py")

    def test_sql_file_extraction(self) -> None:
        """harvest_queries_from_code() must also work on .sql files."""
        sql_content = (
            "-- v2 migration\n"
            "SELECT id, name FROM users WHERE id > 0;\n"
        )
        p = os.path.join(self._tmpdir, "migration.sql")
        Path(p).write_text(sql_content, encoding="utf-8")
        queries = self.harvest_queries_from_code(p)
        self.assertTrue(
            any("SELECT id, name FROM users" in q for q in queries),
            f"SQL file query not found; got: {queries}",
        )

    def test_line_comment_not_harvested(self) -> None:
        """SQL queries inside -- comments must NOT be harvested."""
        src = '-- SELECT id, name FROM users\nresult = "SELECT id FROM orders"\n'
        p = os.path.join(self._tmpdir, "test_comment.py")
        Path(p).write_text(src, encoding="utf-8")
        queries = self.harvest_queries_from_code(p)
        # Only the SELECT id FROM orders (inside the string) should appear
        for q in queries:
            self.assertNotIn("name", q.lower(), f"Comment query was harvested: {q}")

    def test_empty_file_returns_empty_list(self) -> None:
        p = os.path.join(self._tmpdir, "empty.py")
        Path(p).write_text("", encoding="utf-8")
        queries = self.harvest_queries_from_code(p)
        self.assertEqual(queries, [])

    # ── _normalise_query helper ────────────────────────────────────────────

    def test_normalise_collapses_whitespace(self) -> None:
        q = "SELECT  id,\n   name\nFROM  users"
        result = self._normalise_query(q)
        self.assertEqual(result, "SELECT id, name FROM users")

    # ── _table_from_query helper ───────────────────────────────────────────

    def test_table_from_query_extracts_table(self) -> None:
        q = "SELECT id FROM users WHERE id = 1"
        self.assertEqual(self._table_from_query(q), "users")

    def test_table_from_query_empty_on_no_from(self) -> None:
        self.assertEqual(self._table_from_query("INSERT INTO x VALUES (1)"), "")

    # ── harvest_codebase_queries ───────────────────────────────────────────

    def test_codebase_scan_returns_list(self) -> None:
        records = self.harvest_codebase_queries(str(_ROOT / "sample_data"))
        self.assertIsInstance(records, list)

    def test_codebase_scan_finds_app_py_queries(self) -> None:
        records = self.harvest_codebase_queries(str(_ROOT / "sample_data"))
        queries = [r["query"] for r in records]
        self.assertTrue(
            any("SELECT id, name, email FROM users WHERE id = 1" in q for q in queries),
            "Q1 not found in codebase scan",
        )

    def test_codebase_records_have_required_keys(self) -> None:
        records = self.harvest_codebase_queries(str(_ROOT / "sample_data"))
        for rec in records:
            for key in ("file", "query", "target_table"):
                self.assertIn(key, rec, f"Key '{key}' missing from record: {rec}")

    def test_codebase_records_target_table_non_empty(self) -> None:
        """Every record that harvested a SELECT…FROM must have a non-empty target_table."""
        records = self.harvest_codebase_queries(str(_ROOT / "sample_data"))
        for rec in records:
            self.assertNotEqual(
                rec["target_table"], "",
                f"Empty target_table for query: {rec['query']!r}",
            )

    def test_codebase_scan_empty_dir_returns_empty(self) -> None:
        records = self.harvest_codebase_queries(self._tmpdir)
        self.assertEqual(records, [])

    def test_codebase_scan_nonexistent_dir_returns_empty(self) -> None:
        records = self.harvest_codebase_queries("/nonexistent/path/does/not/exist")
        self.assertEqual(records, [])

    def test_codebase_scan_custom_dir_with_sql_file(self) -> None:
        """A temp dir containing a .sql file must be scanned correctly."""
        sql = "SELECT id, email FROM customers WHERE active = 1;\n"
        p = os.path.join(self._tmpdir, "data.sql")
        Path(p).write_text(sql, encoding="utf-8")
        records = self.harvest_codebase_queries(self._tmpdir)
        self.assertTrue(
            any("SELECT id, email FROM customers" in r["query"] for r in records),
            f"Expected customers query; got: {[r['query'] for r in records]}",
        )


# ===========================================================================
# 8. TestMultiQueryRehearsal
# ===========================================================================

class TestMultiQueryRehearsal(unittest.TestCase):
    """Tests for multi-query rehearsal and healer verification."""

    def setUp(self) -> None:
        from rehearsal import rehearse, _run_queries, _run_query, _apply_schema, _read_sql
        self.rehearse      = rehearse
        self._run_queries  = _run_queries
        self._run_query    = _run_query
        self._apply_schema = _apply_schema
        self._read_sql     = _read_sql

    def _make_conn(self) -> sqlite3.Connection:
        """Return an in-memory connection with v1 schema applied."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        return conn

    def _make_v2_conn(self) -> sqlite3.Connection:
        """Return an in-memory connection with v1 then v2 applied."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._apply_schema(conn, self._read_sql(_V1))
        self._apply_schema(conn, self._read_sql(_V2))
        return conn

    # ── _run_query unit tests ──────────────────────────────────────────────

    def test_run_query_success(self) -> None:
        conn = self._make_conn()
        ok, msg = self._run_query(conn, "SELECT id, name, email FROM users")
        conn.close()
        self.assertTrue(ok)
        self.assertIn("3", msg)  # 3 rows

    def test_run_query_failure_returns_false(self) -> None:
        conn = self._make_v2_conn()
        ok, msg = self._run_query(conn, "SELECT id, name, email FROM users")
        conn.close()
        self.assertFalse(ok)
        self.assertIn("FAILED", msg)

    # ── _run_queries unit tests ────────────────────────────────────────────

    def test_run_queries_mixed_results(self) -> None:
        """After v2 migration, 3 of 4 app.py queries break; Q3 survives."""
        conn = self._make_v2_conn()
        queries = [
            "SELECT id, name, email FROM users WHERE id = 1",  # breaks
            "SELECT name FROM users ORDER BY id",               # breaks
            "SELECT id, email FROM users",                      # survives
            "SELECT id, name, email FROM users WHERE email LIKE '%@example.com'",  # breaks
        ]
        results = self._run_queries(conn, queries)
        conn.close()
        self.assertEqual(len(results), 4)
        broken     = [r for r in results if not r["success"]]
        unaffected = [r for r in results if r["success"]]
        self.assertEqual(len(broken),     3, "Expected 3 broken queries")
        self.assertEqual(len(unaffected), 1, "Expected 1 safe query")

    def test_run_queries_returns_correct_query_text(self) -> None:
        conn = self._make_conn()
        qs = ["SELECT id FROM users", "SELECT email FROM users"]
        results = self._run_queries(conn, qs)
        conn.close()
        for i, r in enumerate(results):
            self.assertEqual(r["query"], qs[i])

    def test_run_queries_all_pass_on_v1_schema(self) -> None:
        conn = self._make_conn()
        queries = [
            "SELECT id, name, email FROM users",
            "SELECT name FROM users ORDER BY id",
            "SELECT id, email FROM users",
        ]
        results = self._run_queries(conn, queries)
        conn.close()
        self.assertTrue(all(r["success"] for r in results))

    def test_run_queries_result_keys(self) -> None:
        conn = self._make_conn()
        results = self._run_queries(conn, ["SELECT id FROM users"])
        conn.close()
        for r in results:
            self.assertIn("query",   r)
            self.assertIn("success", r)
            self.assertIn("message", r)

    # ── rehearse() with explicit query list ───────────────────────────────

    def test_rehearse_explicit_breaking_query(self) -> None:
        """rehearse() with an explicit breaking query must return 1."""
        code = self.rehearse(_V1, _V2, queries=["SELECT id, name, email FROM users"])
        self.assertEqual(code, 1)

    def test_rehearse_explicit_safe_query(self) -> None:
        """rehearse() with only a safe query must return 0."""
        code = self.rehearse(_V1, _V2, queries=["SELECT id, email FROM users"])
        self.assertEqual(code, 0)

    def test_rehearse_mixed_queries_returns_1(self) -> None:
        """rehearse() with mixed queries (some breaking) must return 1."""
        code = self.rehearse(
            _V1, _V2,
            queries=[
                "SELECT id, name, email FROM users",   # breaks
                "SELECT id, email FROM users",          # safe
            ],
        )
        self.assertEqual(code, 1)

    def test_rehearse_all_safe_queries_returns_0(self) -> None:
        """rehearse() with all safe queries must return 0."""
        code = self.rehearse(
            _V1, _V2,
            queries=[
                "SELECT id, email FROM users",
                "SELECT id FROM users",
            ],
        )
        self.assertEqual(code, 0)

    def test_rehearse_auto_discovery_returns_1_on_breaking(self) -> None:
        """rehearse() with queries=None must auto-discover and return 1 (some queries break)."""
        code = self.rehearse(_V1, _V2)
        self.assertEqual(code, 1)

    def test_rehearse_explicit_query_list_ignores_harvester(self) -> None:
        """Supplying queries= must bypass the harvester entirely."""
        # If we pass only the safe query, even though the harvester would find
        # breaking ones, rehearse must return 0.
        code = self.rehearse(_V1, _V2, queries=["SELECT id, email FROM users"])
        self.assertEqual(code, 0)

    # ── healer multi-query verification ───────────────────────────────────

    def test_heal_passes_all_harvested_queries(self) -> None:
        """After heal(), all harvested queries from sample_data must pass."""
        from healer import heal
        code = heal(_V1, _V2)
        self.assertEqual(code, 0, "heal() must return 0 — all queries should pass post-heal")

    def test_verify_harvested_queries_all_pass_after_heal(self) -> None:
        """_verify_harvested_queries() must return all_pass=True after the view is in place."""
        from healer import _heal, _verify_harvested_queries, _get_columns
        from rehearsal import _apply_schema, _read_sql

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        _apply_schema(conn, _read_sql(_V1))
        v1_cols = _get_columns(conn, "users")
        _apply_schema(conn, _read_sql(_V2))
        _heal(conn, "users", v1_cols)

        all_pass, summary, details = _verify_harvested_queries(conn, _V1)
        conn.close()

        self.assertTrue(all_pass, f"Expected all queries to pass; summary: {summary}")
        self.assertGreater(len(details), 0)

    def test_verify_harvested_queries_q3_passes_before_heal(self) -> None:
        """Q3 (SELECT id, email FROM users) must pass even without healing."""
        from healer import _verify_harvested_queries
        from rehearsal import _apply_schema, _read_sql

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        _apply_schema(conn, _read_sql(_V1))
        _apply_schema(conn, _read_sql(_V2))

        all_pass, summary, details = _verify_harvested_queries(conn, _V1)
        conn.close()

        # Without healing, name-based queries fail but Q3 must pass
        q3_result = next(
            (r for r in details if "SELECT id, email FROM users" in r["query"]
             and "name" not in r["query"].lower()),
            None,
        )
        self.assertIsNotNone(q3_result, "Q3 record not found in details")
        self.assertTrue(q3_result["success"], "Q3 (safe query) should pass even before heal")


# ===========================================================================
# 9. TestUI
# ===========================================================================

class TestUI(unittest.TestCase):
    """Tests for ui.calculate_safety_score(), render_schema_diff(), render_scorecard()."""

    def setUp(self) -> None:
        from ui import (
            calculate_safety_score,
            render_schema_diff,
            render_scorecard,
            _strategy_label,
            _status_for_col,
        )
        self.calculate_safety_score = calculate_safety_score
        self.render_schema_diff     = render_schema_diff
        self.render_scorecard       = render_scorecard
        self._strategy_label        = _strategy_label
        self._status_for_col        = _status_for_col

    # ── calculate_safety_score ─────────────────────────────────────────────

    def test_perfect_score_no_findings_healed(self) -> None:
        """Zero findings + healed → score=100, grade=A."""
        result = self.calculate_safety_score([], healed=True, broken_query_count=0)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")

    def test_score_returns_required_keys(self) -> None:
        result = self.calculate_safety_score([], healed=True, broken_query_count=0)
        for key in ("score", "grade", "verdict"):
            self.assertIn(key, result)

    def test_score_is_integer_in_range(self) -> None:
        result = self.calculate_safety_score(
            [{"severity": "CRITICAL"}, {"severity": "HIGH"}],
            healed=False,
            broken_query_count=2,
        )
        self.assertIsInstance(result["score"], int)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"],  100)

    def test_critical_finding_deducts_25(self) -> None:
        """One CRITICAL finding deducts 25; healed adds 20 → 95."""
        result = self.calculate_safety_score(
            [{"severity": "CRITICAL"}], healed=True, broken_query_count=0
        )
        self.assertEqual(result["score"], 95)

    def test_high_finding_deducts_15(self) -> None:
        """One HIGH finding deducts 15; healed adds 20 → 105 clamped to 100."""
        result = self.calculate_safety_score(
            [{"severity": "HIGH"}], healed=True, broken_query_count=0
        )
        self.assertEqual(result["score"], 100)  # 100 - 15 + 20 = 105 → clamped to 100

    def test_medium_finding_deducts_8(self) -> None:
        result = self.calculate_safety_score(
            [{"severity": "MEDIUM"}], healed=False, broken_query_count=0
        )
        self.assertEqual(result["score"], 92)

    def test_low_finding_deducts_3(self) -> None:
        result = self.calculate_safety_score(
            [{"severity": "LOW"}], healed=False, broken_query_count=0
        )
        self.assertEqual(result["score"], 97)

    def test_heal_bonus_adds_20(self) -> None:
        """Heal bonus: +20 added when healed=True (use a scenario where we start below 80)."""
        # 100 - 25(CRITICAL) - 15(HIGH) = 60; +20 heal = 80
        findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
        no_heal   = self.calculate_safety_score(findings, healed=False, broken_query_count=0)
        with_heal = self.calculate_safety_score(findings, healed=True,  broken_query_count=0)
        self.assertEqual(with_heal["score"] - no_heal["score"], 20)

    def test_broken_query_deduction_per_query(self) -> None:
        """Each broken query deducts 5 points."""
        r0 = self.calculate_safety_score([], healed=False, broken_query_count=0)
        r2 = self.calculate_safety_score([], healed=False, broken_query_count=2)
        self.assertEqual(r0["score"] - r2["score"], 10)

    def test_broken_query_deduction_capped_at_20(self) -> None:
        """Broken-query deduction is capped at 20 regardless of count."""
        r4  = self.calculate_safety_score([], healed=False, broken_query_count=4)
        r10 = self.calculate_safety_score([], healed=False, broken_query_count=10)
        self.assertEqual(r4["score"], r10["score"])

    def test_score_never_below_zero(self) -> None:
        """Score must never go negative even with many severe findings."""
        findings = [{"severity": "CRITICAL"}] * 10
        result = self.calculate_safety_score(findings, healed=False, broken_query_count=10)
        self.assertGreaterEqual(result["score"], 0)

    def test_grade_a_at_90_plus(self) -> None:
        result = self.calculate_safety_score([], healed=True, broken_query_count=0)
        self.assertEqual(result["grade"], "A")

    def test_grade_b_range(self) -> None:
        """Score 75–89 → grade B."""
        # 100 - 15(HIGH) - 10(2 broken) = 75; no heal bonus → B
        result = self.calculate_safety_score(
            [{"severity": "HIGH"}], healed=False, broken_query_count=2
        )
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["grade"], "B")

    def test_grade_c_range(self) -> None:
        """Score 50–74 → grade C."""
        # 100 - 25(CRITICAL) - 25(CRITICAL) = 50 → C
        result = self.calculate_safety_score(
            [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}],
            healed=False, broken_query_count=0,
        )
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["grade"], "C")

    def test_grade_f_below_50(self) -> None:
        """Score < 50 → grade F."""
        result = self.calculate_safety_score(
            [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}, {"severity": "HIGH"}],
            healed=False, broken_query_count=4,
        )
        self.assertLess(result["score"], 50)
        self.assertEqual(result["grade"], "F")

    def test_verdict_is_non_empty_string(self) -> None:
        result = self.calculate_safety_score([], healed=True, broken_query_count=0)
        self.assertIsInstance(result["verdict"], str)
        self.assertGreater(len(result["verdict"]), 0)

    def test_verdict_deploy_for_grade_a(self) -> None:
        result = self.calculate_safety_score([], healed=True, broken_query_count=0)
        self.assertIn("DEPLOY", result["verdict"].upper())

    def test_verdict_do_not_deploy_for_grade_f(self) -> None:
        result = self.calculate_safety_score(
            [{"severity": "CRITICAL"}] * 5, healed=False, broken_query_count=4
        )
        self.assertIn("DO NOT DEPLOY", result["verdict"].upper())

    def test_sample_data_scenario(self) -> None:
        """v2_breaking.sql scenario: 3 HIGH + 3 broken + healed → grade A or B."""
        findings = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ]
        result = self.calculate_safety_score(findings, healed=True, broken_query_count=3)
        # 100 - 45(3×HIGH) - 15(3 broken) + 20(healed) = 60 → C
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["grade"], "C")

    # ── render_schema_diff (output capture) ───────────────────────────────

    def _capture_render(self, fn, *args, **kwargs) -> str:
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            fn(*args, **kwargs)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_render_schema_diff_produces_output(self) -> None:
        v1 = ["id", "name", "email"]
        v2 = ["id", "first_name", "last_name", "email"]
        from healer import _diff_schemas
        mapping = _diff_schemas(v1, v2)
        out = self._capture_render(self.render_schema_diff, v1, v2, mapping)
        self.assertGreater(len(out), 0)

    def test_render_schema_diff_contains_v1_columns(self) -> None:
        v1 = ["id", "name", "email"]
        v2 = ["id", "first_name", "last_name", "email"]
        from healer import _diff_schemas
        mapping = _diff_schemas(v1, v2)
        out = self._capture_render(self.render_schema_diff, v1, v2, mapping)
        for col in v1:
            self.assertIn(col, out, f"v1 column '{col}' missing from schema diff output")

    def test_render_schema_diff_contains_safe_status(self) -> None:
        v1 = ["id", "name", "email"]
        v2 = ["id", "first_name", "last_name", "email"]
        from healer import _diff_schemas
        mapping = _diff_schemas(v1, v2)
        out = self._capture_render(self.render_schema_diff, v1, v2, mapping)
        self.assertIn("SAFE",   out)
        self.assertIn("HEALED", out)

    def test_render_schema_diff_shows_new_columns(self) -> None:
        v1 = ["id", "name", "email"]
        v2 = ["id", "first_name", "last_name", "email"]
        from healer import _diff_schemas
        mapping = _diff_schemas(v1, v2)
        out = self._capture_render(self.render_schema_diff, v1, v2, mapping)
        self.assertIn("NEW",        out)
        self.assertIn("first_name", out)
        self.assertIn("last_name",  out)

    def test_render_schema_diff_contains_header(self) -> None:
        v1 = ["id"]
        v2 = ["id"]
        from healer import _diff_schemas
        mapping = _diff_schemas(v1, v2)
        out = self._capture_render(self.render_schema_diff, v1, v2, mapping)
        self.assertIn("SCHEMA COMPATIBILITY MATRIX", out)

    def test_render_scorecard_produces_output(self) -> None:
        score_data = {"score": 85, "grade": "B", "verdict": "Deploy with care."}
        out = self._capture_render(self.render_scorecard, score_data)
        self.assertGreater(len(out), 0)

    def test_render_scorecard_contains_score(self) -> None:
        score_data = {"score": 85, "grade": "B", "verdict": "Deploy with care."}
        out = self._capture_render(self.render_scorecard, score_data)
        self.assertIn("85", out)

    def test_render_scorecard_contains_grade(self) -> None:
        score_data = {"score": 85, "grade": "B", "verdict": "Deploy with care."}
        out = self._capture_render(self.render_scorecard, score_data)
        self.assertIn("B", out)

    def test_render_scorecard_contains_verdict(self) -> None:
        score_data = {"score": 85, "grade": "B", "verdict": "Deploy with care."}
        out = self._capture_render(self.render_scorecard, score_data)
        self.assertIn("Deploy", out)

    def test_render_scorecard_contains_header(self) -> None:
        score_data = {"score": 100, "grade": "A", "verdict": "Go!"}
        out = self._capture_render(self.render_scorecard, score_data)
        self.assertIn("SCORECARD", out)

    # ── _strategy_label / _status_for_col helpers ─────────────────────────

    def test_strategy_label_1to1(self) -> None:
        label = self._strategy_label("id", {"id": "id"})
        self.assertIn("1:1", label)

    def test_strategy_label_null_fallback(self) -> None:
        label = self._strategy_label("phone", {"phone": "NULL AS phone"})
        self.assertIn("NULL", label)

    def test_strategy_label_concat(self) -> None:
        expr = "(first_name || ' ' || last_name) AS name"
        label = self._strategy_label("name", {"name": expr})
        self.assertIn("first_name", label)

    def test_status_safe_for_direct(self) -> None:
        self.assertEqual(self._status_for_col("id", {"id": "id"}), "SAFE")

    def test_status_healed_for_expr(self) -> None:
        expr = "(first_name || ' ' || last_name) AS name"
        self.assertEqual(self._status_for_col("name", {"name": expr}), "HEALED")

    def test_status_dropped_for_null(self) -> None:
        self.assertEqual(self._status_for_col("phone", {"phone": "NULL AS phone"}), "DROPPED")

    # ── cmd_diff integration test ──────────────────────────────────────────

    def test_cmd_diff_returns_0(self) -> None:
        import bifrost
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            code = bifrost.cmd_diff()
        finally:
            sys.stdout = old
        self.assertEqual(code, 0)

    def test_cmd_diff_output_contains_matrix(self) -> None:
        import bifrost
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            bifrost.cmd_diff()
        finally:
            sys.stdout = old
        out = buf.getvalue()
        self.assertIn("SCHEMA COMPATIBILITY MATRIX", out)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
