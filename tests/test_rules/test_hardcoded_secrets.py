"""
test_hardcoded_secrets.py
----------------------------
Unit tests for scanner/rules/hardcoded_secrets.py (CWE-798).
"""

import unittest

from scanner.rules.hardcoded_secrets import HardcodedSecretsRule
from scanner.rules.finding import Severity
from tests.test_rules.helpers import parse_source


class TestHardcodedSecretsRule(unittest.TestCase):
    def setUp(self):
        self.rule = HardcodedSecretsRule()

    def test_simple_assignment_is_flagged(self):
        pf = parse_source('password = "hunter2"')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-798")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_api_key_naming_variant_is_flagged(self):
        pf = parse_source('API_KEY = "sk_live_abc123xyz"')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_dict_literal_secret_key_is_flagged(self):
        pf = parse_source('config = {"host": "localhost", "password": "supersecret"}')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_function_default_argument_secret_is_flagged(self):
        pf = parse_source(
            """
def connect(secret_token="hardcoded_default_token"):
    pass
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_hash_suffix_is_not_flagged(self):
        # A hash is a derived value, not the plaintext secret -- storing
        # one is normal, expected code, not a hardcoded-secret issue.
        pf = parse_source('password_hash = "5f4dcc3b5aa765d61d8327deb882cf99"')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_value_loaded_from_environment_not_flagged(self):
        pf = parse_source('password = os.environ["DB_PASSWORD"]')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_value_from_function_call_not_flagged(self):
        pf = parse_source('password = get_secret_from_vault()')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_empty_string_not_flagged(self):
        pf = parse_source('password = ""')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_non_secret_variable_name_not_flagged(self):
        pf = parse_source('name = "just a normal string"')
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source('password = "hunter2"', filename="tests/test_something.py")
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()