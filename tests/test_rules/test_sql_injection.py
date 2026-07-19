"""
test_sql_injection.py
-----------------------
Unit tests for scanner/rules/sql_injection.py (CWE-89).
"""

import unittest

from scanner.rules.sql_injection import SqlInjectionRule
from scanner.rules.finding import Severity
from tests.test_rules.helpers import parse_source


class TestSqlInjectionRule(unittest.TestCase):
    def setUp(self):
        self.rule = SqlInjectionRule()

    def test_fstring_query_is_flagged(self):
        pf = parse_source(
            """
def f(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-89")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_string_concatenation_query_is_flagged(self):
        pf = parse_source(
            """
def f(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_percent_formatting_query_is_flagged(self):
        pf = parse_source(
            """
def f(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_dot_format_query_is_flagged(self):
        pf = parse_source(
            """
def f(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_parameterized_query_not_flagged(self):
        pf = parse_source(
            """
def f(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_static_query_not_flagged(self):
        pf = parse_source(
            """
def f(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_unrelated_method_call_not_flagged(self):
        # .format() used on a non-SQL string, not passed to a DB sink --
        # should not be flagged just because .format() appears somewhere.
        pf = parse_source(
            """
def f(name):
    greeting = "Hello, {}!".format(name)
    return greeting
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
def f(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
""",
            filename="tests/test_something.py",
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()