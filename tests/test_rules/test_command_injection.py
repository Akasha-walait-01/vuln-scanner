"""
test_command_injection.py
---------------------------
Unit tests for scanner/rules/command_injection.py (CWE-78).
"""

import unittest

from scanner.rules.command_injection import CommandInjectionRule
from scanner.rules.finding import Confidence, Severity
from tests.test_rules.helpers import parse_source


class TestCommandInjectionRule(unittest.TestCase):
    def setUp(self):
        self.rule = CommandInjectionRule()

    def test_os_system_with_fstring_is_flagged(self):
        pf = parse_source(
            """
import os
def f(filename):
    os.system(f"cat {filename}")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-78")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)

    def test_os_popen_with_concatenation_is_flagged(self):
        pf = parse_source(
            """
import os
def f(username):
    os.popen("ls -la /home/" + username)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_os_system_static_string_not_flagged(self):
        pf = parse_source(
            """
import os
def f():
    os.system("echo hello")
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_subprocess_shell_true_with_dynamic_command_is_high_confidence(self):
        pf = parse_source(
            """
import subprocess
def f(user_cmd):
    subprocess.run(f"echo {user_cmd}", shell=True)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)

    def test_subprocess_shell_true_with_static_command_is_medium_confidence(self):
        # shell=True is still a flagged risky pattern even with a static
        # command, but at lower confidence than a confirmed dynamic build.
        pf = parse_source(
            """
import subprocess
def f():
    subprocess.call("ls -la", shell=True)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].confidence, Confidence.MEDIUM)

    def test_subprocess_with_list_args_not_flagged(self):
        # The safe, recommended pattern: list of arguments, no shell=True.
        pf = parse_source(
            """
import subprocess
def f(filename):
    subprocess.run(["cat", filename])
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_subprocess_without_shell_true_not_flagged(self):
        pf = parse_source(
            """
import subprocess
def f(cmd):
    subprocess.run(cmd)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
import os
def f(filename):
    os.system(f"cat {filename}")
""",
            filename="tests/test_something.py",
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()