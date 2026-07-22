"""
test_vulnerable_project_catches_all.py
------------------------------------------
Phase 8 -- automated version of the manual False Negative check: scans
tests/test_project_vulnerable/ and asserts every one of the 8 planted
vulnerability categories is caught by at least one rule. This turns the
one-off manual validation into something that re-runs automatically
(e.g. if a future change to a rule accidentally breaks detection).
"""

import unittest
from pathlib import Path

from scanner.input_handler import walk_project
from scanner.parser import parse_project
from scanner.rules import ALL_RULES
from scanner.taint import CommandInjectionTaintTracker

VULNERABLE_PROJECT = Path(__file__).parent / "test_project_vulnerable"

EXPECTED_RULE_IDS = {
    "sql_injection",
    "command_injection_taint",
    "hardcoded_secrets",
    "insecure_deserialization",
    "weak_crypto",
    "eval_exec_misuse",
    "path_traversal",
    "missing_input_validation",
}


class TestVulnerableProjectCatchesAll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = walk_project(VULNERABLE_PROJECT)
        parsed = parse_project(files)
        ok_files = [p for p in parsed if p.ok]

        rules = [rule_cls() for rule_cls in ALL_RULES] + [CommandInjectionTaintTracker()]
        cls.findings = []
        for pf in ok_files:
            for rule in rules:
                cls.findings += rule.check(pf)
        cls.rule_ids_found = {f.rule_id for f in cls.findings}

    def test_all_eight_vulnerability_categories_are_caught(self):
        missing = EXPECTED_RULE_IDS - self.rule_ids_found
        self.assertEqual(
            missing,
            set(),
            f"False negative: these rule categories caught nothing in the "
            f"intentionally-vulnerable test project: {missing}",
        )

    def test_at_least_eight_findings_total(self):
        # 8 planted vulnerabilities minimum; some files legitimately
        # trigger more than one rule (e.g. open() with unsafe input
        # matches both path_traversal and missing_input_validation).
        self.assertGreaterEqual(len(self.findings), 8)


if __name__ == "__main__":
    unittest.main()