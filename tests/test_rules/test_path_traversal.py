"""
test_path_traversal.py
-------------------------
Unit tests for scanner/rules/path_traversal.py (CWE-22).
"""

import unittest

from scanner.rules.path_traversal import PathTraversalRule
from scanner.rules.finding import Severity
from tests.test_rules.helpers import parse_source


class TestPathTraversalRule(unittest.TestCase):
    def setUp(self):
        self.rule = PathTraversalRule()

    def test_unvalidated_open_is_flagged(self):
        pf = parse_source(
            """
def f(request):
    filename = request.args.get("filename")
    return open(filename)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-22")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_unvalidated_os_path_join_is_flagged(self):
        pf = parse_source(
            """
import os
def f(request):
    filename = request.args.get("filename")
    full_path = os.path.join("/var/uploads", filename)
    return open(full_path)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_unvalidated_pathlib_path_is_flagged(self):
        pf = parse_source(
            """
from pathlib import Path
def f(request):
    filename = request.args.get("filename")
    return Path(filename)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_dotdot_containment_check_counts_as_safety(self):
        pf = parse_source(
            """
def f(request):
    filename = request.args.get("filename")
    if ".." in filename:
        raise ValueError("bad path")
    return open(filename)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_realpath_and_startswith_check_counts_as_safety(self):
        pf = parse_source(
            """
import os
def f(request):
    filename = request.args.get("filename")
    base = "/var/uploads"
    full_path = os.path.realpath(os.path.join(base, filename))
    if not full_path.startswith(base):
        raise ValueError("traversal detected")
    return open(full_path)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_no_path_sink_not_flagged(self):
        pf = parse_source(
            """
def f(request):
    filename = request.args.get("filename")
    return filename.upper()
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_no_user_input_source_not_flagged(self):
        pf = parse_source(
            """
def f():
    return open("static_config.json")
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