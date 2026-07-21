"""
severity_engine.py
--------------------
Phase 5 -- takes the findings each Phase 4 rule already produced (each
one carries an INTRINSIC severity + confidence, assigned by the rule
itself -- see each rule's docstring for that reasoning) and adds two
things on top:

1. effective_severity(finding) -- an adjusted severity for REPORTING
   purposes, which discounts a finding's severity when confidence is
   low. See the reasoning docstring on that function for why.

2. calculate_risk_score(findings) -- a single 0-100 number summarizing
   how risky the whole scanned codebase is, for the Phase 7 dashboard.

Why this is a separate layer from the rules themselves: each rule only
sees ITS OWN findings in isolation -- it has no view of the codebase as
a whole. Aggregating severity into one risk score, and adjusting
individual severities for confidence, are both "look at everything
together" decisions that don't belong inside any single rule.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List

from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

# --- Severity weighting -------------------------------------------------
#
# Reasoning for these specific numbers: they're spaced so that ONE
# Critical finding always outweighs any number of Low findings a
# realistic codebase would have (10 vs a handful of 1s), while still
# letting a large pile of Medium/High findings meaningfully move the
# score -- a codebase with 20 High findings and zero Critical ones
# should NOT score lower than one with a single Critical finding, but
# it should still show clearly elevated risk. A 5x gap between adjacent
# tiers achieves both: dominance for the top tier, but real accumulation
# below it.
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

# --- Confidence discounting ----------------------------------------------
#
# Reasoning: confidence reflects how sure the STRUCTURAL heuristic is
# that a finding is real (see base_rule.py / individual rules). A
# HIGH-confidence finding (e.g. a confirmed f-string built directly
# into cursor.execute()) counts at full weight. A LOW-confidence one
# (e.g. missing_input_validation.py's coarse function-level heuristic)
# is weaker evidence, so it should move the risk score less -- but it
# should NOT count as zero, because it's still a real signal worth
# surfacing, just a noisier one.
CONFIDENCE_MULTIPLIERS: Dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}

# Reasoning for the downgrade table: a LOW-confidence finding at
# Critical/High severity is exactly the case most likely to be a false
# positive dominating a report and causing "alert fatigue" -- someone
# skimming a dashboard sees "3 Critical findings" and panics, even if
# all 3 came from the weakest heuristic in the tool. Downgrading by
# ONE tier for LOW confidence keeps the finding visible (it doesn't
# disappear) but stops it from occupying the same visual/priority slot
# as a confirmed, HIGH-confidence Critical finding. MEDIUM and HIGH
# confidence are left untouched -- only LOW confidence is uncertain
# enough to warrant this adjustment.
_DOWNGRADE_ONE_TIER: Dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,  # already the floor
}


def effective_severity(finding: VulnerabilityFinding) -> Severity:
    """The severity to actually SHOW in the report/dashboard, as
    opposed to finding.severity (the rule's original, intrinsic
    assignment, which is left untouched for traceability/debugging).

    Only LOW-confidence findings are adjusted -- see the reasoning on
    _DOWNGRADE_ONE_TIER above.
    """
    if finding.confidence == Confidence.LOW:
        return _DOWNGRADE_ONE_TIER[finding.severity]
    return finding.severity


def severity_breakdown(findings: List[VulnerabilityFinding]) -> Dict[str, int]:
    """Count findings per EFFECTIVE severity tier, e.g.
    {"critical": 3, "high": 12, "medium": 8, "low": 5} -- used directly
    by the Phase 7 dashboard summary."""
    counts = Counter(effective_severity(f).value for f in findings)
    # Always include all 4 tiers (even at 0) so the dashboard doesn't
    # need to handle missing keys.
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def calculate_risk_score(findings: List[VulnerabilityFinding]) -> float:
    """Return a single 0-100 risk score summarizing the whole scanned
    codebase.

    Formula: sum(severity_weight * confidence_multiplier) across every
    finding, using the ORIGINAL (non-downgraded) severity -- the risk
    score should reflect the full weight of what each rule detected,
    with confidence as a separate discount factor, rather than
    double-applying the reporting-only downgrade from
    effective_severity() on top of it.

    The raw sum is capped at 100. Reasoning: an uncapped sum would let
    a codebase with hundreds of minor findings show an absurd score
    (e.g. 1400) that's meaningless to compare against anything.
    Capping at 100 treats "100+ raw weighted points of findings" as
    already being at the ceiling of "this codebase needs serious
    attention" -- the exact raw number stops mattering past that point.
    """
    if not findings:
        return 0.0

    raw_score = sum(
        SEVERITY_WEIGHTS[f.severity] * CONFIDENCE_MULTIPLIERS[f.confidence] for f in findings
    )
    return min(100.0, round(raw_score, 1))


def risk_level_label(risk_score: float) -> str:
    """Map a 0-100 risk score to a human-readable overall risk level
    for the dashboard headline (e.g. "72.5 -- High Risk").

    Thresholds reasoning: mirrors the severity tier spacing above --
    a single Critical finding alone (10 points, at full confidence)
    should already push a codebase out of "Low risk" territory, so the
    Low ceiling is set below that. The remaining thresholds are spaced
    roughly geometrically (10 / 30 / 60) so the label moves meaningfully
    as more or more-severe findings accumulate, without every codebase
    immediately maxing out at "Critical."
    """
    if risk_score >= 60:
        return "Critical Risk"
    if risk_score >= 30:
        return "High Risk"
    if risk_score >= 10:
        return "Medium Risk"
    if risk_score > 0:
        return "Low Risk"
    return "No Findings"