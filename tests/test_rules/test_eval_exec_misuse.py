"""
test_eval_exec_misuse.py
---------------------------
Unit tests for scanner/rules/eval_exec_misuse.py (CWE-95).
"""

import unittest

from scanner.rules.eval_exec_misuse import EvalExecMisuseRule
from scanner.rules.finding import Confidence, Severity
from tests.test_rules.helpers import parse_source


class TestEvalExecMisuseRule(unittest.TestCase):
    def setUp(self):
        self.rule = EvalExecMisuseRule()

    def test_eval_on_input_result_is_critical(self):
        pf = parse_source(
            """
def f():
    expr = input("Enter expression: ")
    return eval(expr)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-95")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)

    def test_exec_on_variable_is_critical(self):
        pf = parse_source(
            """
def f(user_code):
    exec(user_code)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_eval_on_fstring_is_critical(self):
        pf = parse_source(
            """
def f(x):
    return eval(f"{x} + 1")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_compile_on_dynamic_source_is_critical(self):
        pf = parse_source(
            """
def f(source_code):
    return compile(source_code, "<string>", "eval")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_eval_on_string_literal_is_low_severity(self):
        pf = parse_source(
            """
def f():
    return eval("1 + 1")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertEqual(findings[0].confidence, Confidence.LOW)

    def test_ast_literal_eval_not_flagged(self):
        pf = parse_source(
            """
import ast
def f(data):
    return ast.literal_eval(data)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_unrelated_function_not_flagged(self):
        pf = parse_source(
            """
def f():
    return sum([1, 2, 3])
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
def f(user_code):
    exec(user_code)
""",
            filename="tests/test_something.py",
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()