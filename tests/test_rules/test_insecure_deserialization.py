"""
test_insecure_deserialization.py
-----------------------------------
Unit tests for scanner/rules/insecure_deserialization.py (CWE-502).
"""

import unittest

from scanner.rules.insecure_deserialization import InsecureDeserializationRule
from scanner.rules.finding import Severity
from tests.test_rules.helpers import parse_source


class TestInsecureDeserializationRule(unittest.TestCase):
    def setUp(self):
        self.rule = InsecureDeserializationRule()

    def test_pickle_loads_is_flagged(self):
        pf = parse_source(
            """
import pickle
def f(data):
    return pickle.loads(data)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-502")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_pickle_load_is_flagged(self):
        pf = parse_source(
            """
import pickle
def f(fileobj):
    return pickle.load(fileobj)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_yaml_load_without_safe_loader_is_flagged(self):
        pf = parse_source(
            """
import yaml
def f(data):
    return yaml.load(data)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_yaml_unsafe_load_is_flagged(self):
        pf = parse_source(
            """
import yaml
def f(data):
    return yaml.unsafe_load(data)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_yaml_safe_load_not_flagged(self):
        pf = parse_source(
            """
import yaml
def f(data):
    return yaml.safe_load(data)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_yaml_load_with_safe_loader_kwarg_not_flagged(self):
        pf = parse_source(
            """
import yaml
def f(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_unrelated_json_loads_not_flagged(self):
        pf = parse_source(
            """
import json
def f(data):
    return json.loads(data)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
import pickle
def f(data):
    return pickle.loads(data)
""",
            filename="tests/test_something.py",
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()