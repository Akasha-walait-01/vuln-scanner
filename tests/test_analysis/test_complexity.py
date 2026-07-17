"""
test_complexity.py
-------------------
Unit tests for scanner/analysis/complexity.py.
"""

import unittest

from scanner.analysis.complexity import calculate_complexity, find_complex_functions
from tests.test_analysis.helpers import parse_source, get_function


class TestCalculateComplexity(unittest.TestCase):
    def test_simple_function_has_baseline_complexity_1(self):
        pf = parse_source(
            """
def add(a, b):
    return a + b
"""
        )
        func = get_function(pf, "add")
        self.assertEqual(calculate_complexity(func), 1)

    def test_single_if_adds_one(self):
        pf = parse_source(
            """
def check(x):
    if x > 0:
        return "positive"
    return "non-positive"
"""
        )
        func = get_function(pf, "check")
        self.assertEqual(calculate_complexity(func), 2)

    def test_boolean_operators_add_extra_decision_points(self):
        pf = parse_source(
            """
def check(a, b, c):
    if a and b and c:
        return True
    return False
"""
        )
        func = get_function(pf, "check")
        # baseline 1 + if(1) + (3 operands - 1 = 2 for the 'and' chain) = 4
        self.assertEqual(calculate_complexity(func), 4)

    def test_nested_function_not_counted_into_parent(self):
        pf = parse_source(
            """
def outer():
    def inner():
        if True:
            pass
    return inner
"""
        )
        func = get_function(pf, "outer")
        # outer itself has no branches of its own -- inner's `if` must
        # NOT leak into outer's score.
        self.assertEqual(calculate_complexity(func), 1)


class TestFindComplexFunctions(unittest.TestCase):
    def test_flags_function_above_threshold(self):
        pf = parse_source(
            """
def complicated(x):
    if x == 1: pass
    elif x == 2: pass
    elif x == 3: pass
    elif x == 4: pass
    elif x == 5: pass
"""
        )
        findings = find_complex_functions(pf, threshold=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].function_name, "complicated")
        self.assertEqual(findings[0].check, "complexity")

    def test_does_not_flag_function_below_threshold(self):
        pf = parse_source(
            """
def simple(a, b):
    return a + b
"""
        )
        findings = find_complex_functions(pf, threshold=10)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()