"""
test_dead_code.py
-------------------
Unit tests for scanner/analysis/dead_code.py.
"""

import unittest

from scanner.analysis.dead_code import find_dead_code
from tests.test_analysis.helpers import parse_source


class TestFindDeadCode(unittest.TestCase):
    def test_code_after_return_is_flagged(self):
        pf = parse_source(
            """
def f():
    return 1
    print("never runs")
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check, "dead_code")

    def test_code_after_raise_is_flagged(self):
        pf = parse_source(
            """
def f():
    raise ValueError("bad")
    print("never runs")
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 1)

    def test_code_after_break_in_loop_is_flagged(self):
        pf = parse_source(
            """
def f(items):
    for item in items:
        break
        print("never runs")
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 1)

    def test_if_false_block_is_flagged(self):
        pf = parse_source(
            """
def f():
    if False:
        print("never runs")
    print("this runs fine")
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 1)
        self.assertIn("always False", findings[0].message)

    def test_if_true_else_is_flagged(self):
        pf = parse_source(
            """
def f():
    if True:
        print("runs")
    else:
        print("never runs")
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 1)
        self.assertIn("always True", findings[0].message)

    def test_clean_function_has_no_dead_code(self):
        pf = parse_source(
            """
def f(x):
    if x > 0:
        return "positive"
    return "non-positive"
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 0)

    def test_return_inside_if_does_not_kill_code_after_the_if(self):
        # A return inside an `if` branch only terminates THAT branch,
        # not the code that follows the whole `if` statement.
        pf = parse_source(
            """
def f(x):
    if x > 0:
        return "positive"
    print("this is reachable if x <= 0")
"""
        )
        findings = find_dead_code(pf)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()