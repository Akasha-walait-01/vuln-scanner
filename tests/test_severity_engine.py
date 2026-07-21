"""
test_severity_engine.py
--------------------------
Unit tests for scanner/severity/severity_engine.py (Phase 5).
"""

import unittest
from pathlib import Path

from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding
from scanner.severity.severity_engine import (
    calculate_risk_score,
    effective_severity,
    risk_level_label,
    severity_breakdown,
)


def make_finding(severity: Severity, confidence: Confidence) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        rule_id="test_rule",
        cwe_id="CWE-000",
        severity=severity,
        file_path=Path("f.py"),
        line=1,
        message="msg",
        fix_suggestion="fix",
        confidence=confidence,
    )


class TestEffectiveSeverity(unittest.TestCase):
    def test_low_confidence_critical_downgrades_to_high(self):
        f = make_finding(Severity.CRITICAL, Confidence.LOW)
        self.assertEqual(effective_severity(f), Severity.HIGH)

    def test_high_confidence_critical_stays_critical(self):
        f = make_finding(Severity.CRITICAL, Confidence.HIGH)
        self.assertEqual(effective_severity(f), Severity.CRITICAL)

    def test_medium_confidence_not_downgraded(self):
        f = make_finding(Severity.HIGH, Confidence.MEDIUM)
        self.assertEqual(effective_severity(f), Severity.HIGH)

    def test_low_severity_low_confidence_stays_at_floor(self):
        f = make_finding(Severity.LOW, Confidence.LOW)
        self.assertEqual(effective_severity(f), Severity.LOW)


class TestCalculateRiskScore(unittest.TestCase):
    def test_no_findings_scores_zero(self):
        self.assertEqual(calculate_risk_score([]), 0.0)

    def test_single_critical_high_confidence(self):
        score = calculate_risk_score([make_finding(Severity.CRITICAL, Confidence.HIGH)])
        self.assertEqual(score, 10.0)

    def test_many_low_findings_score_less_than_one_critical(self):
        lows = [make_finding(Severity.LOW, Confidence.HIGH) for _ in range(5)]
        critical = [make_finding(Severity.CRITICAL, Confidence.HIGH)]
        self.assertLess(calculate_risk_score(lows), calculate_risk_score(critical))

    def test_low_confidence_discounts_score(self):
        high_conf = calculate_risk_score([make_finding(Severity.HIGH, Confidence.HIGH)])
        low_conf = calculate_risk_score([make_finding(Severity.HIGH, Confidence.LOW)])
        self.assertLess(low_conf, high_conf)

    def test_score_is_capped_at_100(self):
        many_criticals = [make_finding(Severity.CRITICAL, Confidence.HIGH) for _ in range(20)]
        self.assertEqual(calculate_risk_score(many_criticals), 100.0)


class TestSeverityBreakdown(unittest.TestCase):
    def test_breakdown_counts_all_four_tiers(self):
        findings = [
            make_finding(Severity.CRITICAL, Confidence.HIGH),
            make_finding(Severity.MEDIUM, Confidence.MEDIUM),
        ]
        breakdown = severity_breakdown(findings)
        self.assertEqual(breakdown["critical"], 1)
        self.assertEqual(breakdown["medium"], 1)
        self.assertEqual(breakdown["high"], 0)
        self.assertEqual(breakdown["low"], 0)

    def test_breakdown_uses_effective_not_raw_severity(self):
        # A LOW-confidence Critical finding should count under "high"
        # in the breakdown, not "critical" -- effective_severity applies.
        findings = [make_finding(Severity.CRITICAL, Confidence.LOW)]
        breakdown = severity_breakdown(findings)
        self.assertEqual(breakdown["critical"], 0)
        self.assertEqual(breakdown["high"], 1)


class TestRiskLevelLabel(unittest.TestCase):
    def test_zero_score_is_no_findings(self):
        self.assertEqual(risk_level_label(0), "No Findings")

    def test_low_score_is_low_risk(self):
        self.assertEqual(risk_level_label(5), "Low Risk")

    def test_medium_score_is_medium_risk(self):
        self.assertEqual(risk_level_label(15), "Medium Risk")

    def test_high_score_is_high_risk(self):
        self.assertEqual(risk_level_label(40), "High Risk")

    def test_critical_score_is_critical_risk(self):
        self.assertEqual(risk_level_label(70), "Critical Risk")


if __name__ == "__main__":
    unittest.main()