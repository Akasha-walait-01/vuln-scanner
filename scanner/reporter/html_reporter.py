"""
html_reporter.py
------------------
Phase 7 -- renders the final HTML report using Jinja2, combining:
- Security vulnerability findings (Phase 4 rules + Phase 6 taint tracker)
- Code quality findings (Phase 3 analysis modules)
into one structured, actionable HTML file with a summary dashboard.

Design decisions:
- Security findings are grouped by EFFECTIVE severity (Phase 5's
  confidence-adjusted severity, not each rule's raw assigned one) --
  that's what should drive what a reader sees first, since it already
  accounts for how sure the scanner is about each finding.
- Code quality findings are shown in a SEPARATE section from security
  findings -- they use a different Finding type (AnalysisFinding, no
  CWE/severity) and represent a different KIND of concern
  (maintainability, not exploitability), so mixing them into one
  severity-sorted list would blur two things a reader cares about
  differently.
- Jinja2's autoescape is left ON for .html templates, so any finding
  message/snippet containing HTML-special characters (e.g. a code
  snippet with `<` or `&`) renders safely as text instead of being
  interpreted as markup -- important since report content ultimately
  comes from scanned SOURCE CODE, which this generator treats as
  untrusted input.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.analysis.finding import AnalysisFinding
from scanner.rules.finding import VulnerabilityFinding
from scanner.severity.severity_engine import (
    calculate_risk_score,
    effective_severity,
    risk_level_label,
    severity_breakdown,
)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_SEVERITY_DISPLAY_ORDER = ["critical", "high", "medium", "low"]


def _group_security_findings_by_severity(
    findings: List[VulnerabilityFinding],
) -> Dict[str, List[VulnerabilityFinding]]:
    groups: Dict[str, List[VulnerabilityFinding]] = {sev: [] for sev in _SEVERITY_DISPLAY_ORDER}
    for f in findings:
        groups[effective_severity(f).value].append(f)
    for sev in groups:
        groups[sev].sort(key=lambda f: (str(f.file_path), f.line))
    return groups


def _category_counts(findings: List[VulnerabilityFinding]) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)


def _group_quality_findings_by_check(
    findings: List[AnalysisFinding],
) -> Dict[str, List[AnalysisFinding]]:
    groups: Dict[str, List[AnalysisFinding]] = {}
    for f in findings:
        groups.setdefault(f.check, []).append(f)
    for check in groups:
        groups[check].sort(key=lambda f: (str(f.file_path), f.line))
    return groups


def generate_html_report(
    security_findings: List[VulnerabilityFinding],
    quality_findings: List[AnalysisFinding],
    scanned_file_count: int,
    source_label: str,
    output_path: str,
) -> Path:
    """Render the full HTML report and write it to `output_path`.

    Args:
        security_findings: all VulnerabilityFinding objects from every
            Phase 4 rule + the Phase 6 taint tracker.
        quality_findings: all AnalysisFinding objects from the Phase 3
            analysis modules.
        scanned_file_count: how many files were successfully parsed
            and scanned (shown in the report header).
        source_label: what was scanned (a local path or GitHub URL),
            shown in the report header.
        output_path: where to write the .html file.

    Returns:
        The Path actually written, so callers (e.g. cli.py) can report
        it back to the user.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report_template.html")

    risk_score = calculate_risk_score(security_findings)
    risk_label = risk_level_label(risk_score)
    breakdown = severity_breakdown(security_findings)
    severity_groups = _group_security_findings_by_severity(security_findings)
    category_counts = _category_counts(security_findings)
    quality_groups = _group_quality_findings_by_check(quality_findings)

    html = template.render(
        source_label=source_label,
        scanned_file_count=scanned_file_count,
        total_security_findings=len(security_findings),
        total_quality_findings=len(quality_findings),
        risk_score=risk_score,
        risk_label=risk_label,
        breakdown=breakdown,
        severity_groups=severity_groups,
        severity_order=_SEVERITY_DISPLAY_ORDER,
        category_counts=category_counts,
        quality_groups=quality_groups,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    return output