import os
import tempfile
import unittest

from scanner.reporter.html_reporter import (
    generate_report,
    build_report_context,
    compute_risk_score,
    _normalize_severity,
)


def make_finding(**overrides):
    base = {
        "rule_id": "SQL_INJECTION_001",
        "category": "SQL Injection",
        "severity": "high",
        "file_path": "app/db.py",
        "line_number": 42,
        "message": "User input concatenated directly into SQL query string.",
        "suggested_fix": "Use parameterized queries instead of string formatting.",
        "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "severity_reason": "Direct string interpolation into a SQL execute call with no sanitization.",
        "reduced_severity": False,
        "reduced_reason": "",
    }
    base.update(overrides)
    return base


class TestSeverityNormalization(unittest.TestCase):
    def test_unknown_severity_defaults_to_low(self):
        self.assertEqual(_normalize_severity("wat"), "low")

    def test_case_insensitive(self):
        self.assertEqual(_normalize_severity("CRITICAL"), "critical")

    def test_none_defaults_to_low(self):
        self.assertEqual(_normalize_severity(None), "low")


class TestRiskScore(unittest.TestCase):
    def test_no_findings_is_zero_risk(self):
        score, label, _ = compute_risk_score([], files_scanned=10)
        self.assertEqual(score, 0)
        self.assertEqual(label, "Low Risk")

    def test_single_critical_in_small_project_is_low_moderate(self):
        findings = [make_finding(severity="critical")]
        score, _, _ = compute_risk_score(findings, files_scanned=50)
        # density = 10/50 = 0.2 -> score = round(0.2*20) = 4
        self.assertEqual(score, 4)

    def test_dense_high_severity_project_saturates_near_100(self):
        findings = [make_finding(severity="high") for _ in range(10)]
        score, label, _ = compute_risk_score(findings, files_scanned=10)
        # density = (10*5)/10 = 5 -> round(5*20)=100, capped at 100
        self.assertEqual(score, 100)
        self.assertEqual(label, "Critical Risk")

    def test_score_never_exceeds_100(self):
        findings = [make_finding(severity="critical") for _ in range(500)]
        score, _, _ = compute_risk_score(findings, files_scanned=1)
        self.assertLessEqual(score, 100)


class TestBuildReportContext(unittest.TestCase):
    def test_groups_findings_by_severity(self):
        findings = [
            make_finding(severity="critical", rule_id="A"),
            make_finding(severity="low", rule_id="B"),
            make_finding(severity="critical", rule_id="C"),
        ]
        ctx = build_report_context(findings, "demo", files_scanned=5)
        self.assertEqual(len(ctx["findings_by_severity"]["critical"]), 2)
        self.assertEqual(len(ctx["findings_by_severity"]["low"]), 1)
        self.assertEqual(ctx["total_findings"], 3)
        self.assertEqual(ctx["severity_counts"]["critical"], 2)

    def test_findings_sorted_by_file_then_line(self):
        findings = [
            make_finding(severity="high", file_path="b.py", line_number=5, rule_id="X"),
            make_finding(severity="high", file_path="a.py", line_number=20, rule_id="Y"),
            make_finding(severity="high", file_path="a.py", line_number=3, rule_id="Z"),
        ]
        ctx = build_report_context(findings, "demo", files_scanned=5)
        ordered = [f["rule_id"] for f in ctx["findings_by_severity"]["high"]]
        self.assertEqual(ordered, ["Z", "Y", "X"])

    def test_accepts_object_findings_not_just_dicts(self):
        class FakeFinding:
            rule_id = "OBJ_001"
            category = "Hardcoded Secrets"
            severity = "medium"
            file_path = "config.py"
            line_number = 7
            message = "Hardcoded API key detected."
            suggested_fix = "Move to environment variable."
            code_snippet = 'API_KEY = "sk-abc123"'
            severity_reason = "Secret pattern matched outside test/config-example paths."
            reduced_severity = False
            reduced_reason = ""

        ctx = build_report_context([FakeFinding()], "demo", files_scanned=1)
        self.assertEqual(ctx["total_findings"], 1)
        self.assertEqual(ctx["findings_by_severity"]["medium"][0]["rule_id"], "OBJ_001")

    def test_category_counts_present(self):
        findings = [
            make_finding(category="SQL Injection"),
            make_finding(category="SQL Injection"),
            make_finding(category="Weak Crypto"),
        ]
        ctx = build_report_context(findings, "demo", files_scanned=3)
        cat_dict = dict(ctx["category_counts"])
        self.assertEqual(cat_dict["SQL Injection"], 2)
        self.assertEqual(cat_dict["Weak Crypto"], 1)


class TestGenerateReport(unittest.TestCase):
    def test_writes_html_file_with_expected_content(self):
        findings = [
            make_finding(severity="critical", rule_id="CMD_INJ_001", category="Command Injection"),
            make_finding(severity="low", rule_id="DEADCODE_001", category="Dead Code",
                         message="Unreachable code after return statement.",
                         suggested_fix="Remove the unreachable block.",
                         code_snippet=None),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report.html")
            result = generate_report(findings, "demo-project", files_scanned=20, output_path=out_path)

            self.assertTrue(os.path.exists(result))
            with open(result, encoding="utf-8") as fh:
                html = fh.read()

            self.assertIn("demo-project", html)
            self.assertIn("CMD_INJ_001", html)
            self.assertIn("Command Injection", html)
            self.assertIn("Overall Risk Score", html)
            self.assertIn("Unreachable code after return statement.", html)

    def test_empty_findings_shows_clean_scan_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report.html")
            generate_report([], "clean-project", files_scanned=15, output_path=out_path)
            with open(out_path, encoding="utf-8") as fh:
                html = fh.read()
            self.assertIn("No findings", html)


if __name__ == "__main__":
    unittest.main()