"""
test_unused_vars.py
--------------------
Unit tests for scanner/analysis/unused_vars.py.
"""

import unittest

from scanner.analysis.unused_vars import find_unused_vars
from tests.test_analysis.helpers import parse_source


class TestFindUnusedVars(unittest.TestCase):
    def test_unused_variable_is_flagged(self):
        pf = parse_source(
            """
def f():
    used = 1
    unused = 2
    print(used)
"""
        )
        findings = find_unused_vars(pf)
        self.assertEqual(len(findings), 1)
        self.assertIn("'unused'", findings[0].message)

    def test_used_variable_not_flagged(self):
        pf = parse_source(
            """
def f():
    x = 1
    return x
"""
        )
        findings = find_unused_vars(pf)
        self.assertEqual(len(findings), 0)

    def test_underscore_prefixed_not_flagged(self):
        pf = parse_source(
            """
def f():
    _ignored = compute()
    return 1
"""
        )
        findings = find_unused_vars(pf)
        self.assertEqual(len(findings), 0)

    def test_tuple_unpacking_not_flagged(self):
        # Deliberately skipped per design decision -- unpacking and only
        # using part of the result is extremely common, valid code.
        pf = parse_source(
            """
def f():
    a, b = (1, 2)
    return a
"""
        )
        findings = find_unused_vars(pf)
        self.assertEqual(len(findings), 0)

    def test_variable_used_in_nested_closure_not_flagged(self):
        pf = parse_source(
            """
def f():
    total = 0
    def add(n):
        return total + n
    return add
"""
        )
        findings = find_unused_vars(pf)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()