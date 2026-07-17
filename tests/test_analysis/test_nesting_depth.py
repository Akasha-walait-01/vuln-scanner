"""
test_nesting_depth.py
----------------------
Unit tests for scanner/analysis/nesting_depth.py.
"""

import unittest

from scanner.analysis.nesting_depth import max_nesting_depth, find_deep_nesting
from tests.test_analysis.helpers import parse_source, get_function


class TestMaxNestingDepth(unittest.TestCase):
    def test_flat_function_has_depth_zero(self):
        pf = parse_source(
            """
def f(x):
    y = x + 1
    return y
"""
        )
        func = get_function(pf, "f")
        self.assertEqual(max_nesting_depth(func), 0)

    def test_single_if_has_depth_one(self):
        pf = parse_source(
            """
def f(x):
    if x > 0:
        return "positive"
"""
        )
        func = get_function(pf, "f")
        self.assertEqual(max_nesting_depth(func), 1)

    def test_if_inside_if_has_depth_two(self):
        pf = parse_source(
            """
def f(x):
    if x > 0:
        if x > 10:
            return "big"
"""
        )
        func = get_function(pf, "f")
        self.assertEqual(max_nesting_depth(func), 2)

    def test_elif_chain_does_not_inflate_depth(self):
        pf = parse_source(
            """
def f(x):
    if x == 1: pass
    elif x == 2: pass
    elif x == 3: pass
    elif x == 4: pass
    else: pass
"""
        )
        func = get_function(pf, "f")
        # No matter how many elif branches, this stays at depth 1 --
        # it's a flat chain of alternatives, not nested logic.
        self.assertEqual(max_nesting_depth(func), 1)

    def test_nested_for_and_if_combine(self):
        pf = parse_source(
            """
def f(items):
    for item in items:
        if item > 0:
            for sub in item:
                pass
"""
        )
        func = get_function(pf, "f")
        self.assertEqual(max_nesting_depth(func), 3)


class TestFindDeepNesting(unittest.TestCase):
    def test_flags_function_above_threshold(self):
        pf = parse_source(
            """
def f(x):
    if x > 0:
        if x > 1:
            if x > 2:
                pass
"""
        )
        findings = find_deep_nesting(pf, threshold=2)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check, "nesting_depth")

    def test_does_not_flag_function_below_threshold(self):
        pf = parse_source(
            """
def f(x):
    if x > 0:
        return True
"""
        )
        findings = find_deep_nesting(pf, threshold=4)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()