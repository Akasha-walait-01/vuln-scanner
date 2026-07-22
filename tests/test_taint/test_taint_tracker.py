"""
test_taint_tracker.py
------------------------
Unit tests for scanner/taint/taint_tracker.py (Phase 6 -- command
injection data-flow tracing).
"""

import unittest

from scanner.taint.taint_tracker import CommandInjectionTaintTracker
from scanner.rules.finding import Confidence, Severity
from tests.test_rules.helpers import parse_source


class TestCommandInjectionTaintTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = CommandInjectionTaintTracker()

    def test_bare_parameter_passed_directly_to_sink_is_flagged(self):
        # This is the exact case Phase 4's structural rule MISSES --
        # `cmd` is a bare variable, not a dynamically-built string.
        pf = parse_source(
            """
import os
def f(cmd):
    os.system(cmd)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-78")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)

    def test_taint_propagates_through_string_concatenation(self):
        pf = parse_source(
            """
import os
def f(filename):
    cmd = "cat " + filename
    os.system(cmd)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 1)

    def test_taint_propagates_through_fstring(self):
        pf = parse_source(
            """
import os
def f(filename):
    full_cmd = f"cat {filename}"
    os.system(full_cmd)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 1)

    def test_taint_propagates_through_multiple_reassignments(self):
        pf = parse_source(
            """
import os
def f(user_input):
    step1 = user_input
    step2 = step1
    step3 = "echo " + step2
    os.system(step3)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 1)

    def test_taint_propagates_to_subprocess_shell_true(self):
        pf = parse_source(
            """
import subprocess
def f(user_cmd):
    final_cmd = user_cmd
    subprocess.run(final_cmd, shell=True)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 1)

    def test_taint_killed_by_reassignment_to_literal(self):
        # `cmd` starts tainted (it's a parameter) but is overwritten
        # with a fixed literal BEFORE reaching the sink -- must not flag.
        pf = parse_source(
            """
import os
def f(cmd):
    cmd = "ls -la"
    os.system(cmd)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 0)

    def test_unrelated_variable_not_flagged(self):
        pf = parse_source(
            """
import os
def f(cmd):
    safe = "ls -la"
    os.system(safe)
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 0)

    def test_no_sink_call_not_flagged(self):
        pf = parse_source(
            """
def f(cmd):
    return cmd.upper()
"""
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
import os
def f(cmd):
    os.system(cmd)
""",
            filename="tests/test_something.py",
        )
        findings = self.tracker.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()