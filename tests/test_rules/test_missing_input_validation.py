"""
test_missing_input_validation.py
-----------------------------------
Unit tests for scanner/rules/missing_input_validation.py (CWE-20).
"""

import unittest

from scanner.rules.missing_input_validation import MissingInputValidationRule
from scanner.rules.finding import Severity
from tests.test_rules.helpers import parse_source


class TestMissingInputValidationRule(unittest.TestCase):
    def setUp(self):
        self.rule = MissingInputValidationRule()

    def test_unvalidated_filename_to_open_is_flagged(self):
        pf = parse_source(
            """
def f(request):
    filename = request.args.get("filename")
    return open(filename)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-20")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_unvalidated_input_to_db_execute_is_flagged(self):
        pf = parse_source(
            """
def f(request, conn):
    user_id = request.form.get("user_id")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_unvalidated_input_to_eval_is_flagged(self):
        pf = parse_source(
            """
def f():
    expr = input("Enter expression: ")
    return eval(expr)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_isalnum_check_counts_as_validation(self):
        pf = parse_source(
            """
def f(request):
    filename = request.args.get("filename")
    if not filename.isalnum():
        raise ValueError("bad filename")
    return open(filename)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_length_check_counts_as_validation(self):
        pf = parse_source(
            """
def f(request):
    user_id = request.form.get("user_id")
    if len(user_id) > 10:
        raise ValueError("too long")
    return open(user_id)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_whitelist_membership_check_counts_as_validation(self):
        pf = parse_source(
            """
def f(request):
    action = request.args.get("action")
    if action not in ["view", "edit"]:
        raise ValueError("bad action")
    return open(action)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_no_sensitive_sink_not_flagged(self):
        pf = parse_source(
            """
def f(request):
    name = request.args.get("name")
    return name.upper()
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_no_user_input_source_not_flagged(self):
        pf = parse_source(
            """
def f():
    return open("static_file.txt")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
def f(request):
    filename = request.args.get("filename")
    return open(filename)
""",
            filename="tests/test_something.py",
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()