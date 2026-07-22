"""
html_reporter.py

Renders a list of Finding objects (from the rules engine / taint tracker) into
a single self-contained HTML report using Jinja2.

Expected Finding schema
------------------------
Each finding can be either a dict or an object (dataclass, etc). The reporter
reads these fields, falling back gracefully if some are missing:

    rule_id          str   e.g. "SQL_INJECTION_001"
    category         str   e.g. "SQL Injection"
    severity         str   one of "critical" | "high" | "medium" | "low"
    file_path        str   relative path of the flagged file
    line_number      int
    message          str   human-readable explanation of the risk
    suggested_fix    str   (optional) remediation suggestion
    code_snippet     str   (optional) the offending line(s) of code
    severity_reason  str   (optional) why this severity was assigned
    reduced_severity bool  (optional) True if context lowered the severity
                           (e.g. finding is in a test file)
    reduced_reason   str   (optional) why severity was reduced

If your Finding class uses different field names, write a small adapter
function that maps your objects to dicts with these keys before calling
generate_report(), rather than changing this module.

Risk score
----------
A weighted 0-100 score summarizing overall codebase risk:

    weighted_sum = critical*10 + high*5 + medium*2 + low*1

The raw weighted_sum has no natural ceiling (a huge repo with many low-severity
findings would swamp a small repo with one critical finding), so it's
normalized against file count to produce a density-based score, then capped
at 100:

    density = weighted_sum / max(files_scanned, 1)
    risk_score = min(100, round(density * 20))

The '*20' scaling constant was chosen so that a single critical finding in a
50-file project (density = 10/50 = 0.2) lands around a score of 4 (low risk
sitting alone), while a project averaging ~1 high-severity finding per file
(density = 5) saturates near 100 (critical risk). Documented here so the
scaling can be revisited if it doesn't feel right against real repos in the
Phase 8 validation step.
"""

import datetime
import os
from collections import defaultdict, Counter

from jinja2 import Environment, FileSystemLoader, select_autoescape

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}

RISK_BANDS = [
    (75, "Critical Risk", "#b91c1c"),
    (45, "High Risk", "#d97706"),
    (20, "Moderate Risk", "#ca8a04"),
    (0, "Low Risk", "#16a34a"),
]

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
TEMPLATE_NAME = "report_template.html"


def _get(finding, field, default=None):
    """Read a field from a finding that may be a dict or an object."""
    if isinstance(finding, dict):
        return finding.get(field, default)
    return getattr(finding, field, default)


def _normalize_severity(value):
    value = (value or "low").strip().lower()
    return value if value in SEVERITY_WEIGHTS else "low"


def compute_risk_score(findings, files_scanned):
    """Return (score:int 0-100, band_label:str, band_color:str)."""
    weighted_sum = sum(
        SEVERITY_WEIGHTS[_normalize_severity(_get(f, "severity"))] for f in findings
    )
    density = weighted_sum / max(files_scanned, 1)
    score = min(100, round(density * 20))

    for threshold, label, color in RISK_BANDS:
        if score >= threshold:
            return score, label, color
    return score, "Low Risk", "#16a34a"  # unreachable fallback


def build_report_context(findings, project_name, files_scanned, scan_timestamp=None):
    """
    Turn a flat list of findings into the template context: severity groups,
    counts, category breakdown, and risk score.
    """
    findings_by_severity = defaultdict(list)
    severity_counts = Counter()
    category_counts = Counter()

    for f in findings:
        sev = _normalize_severity(_get(f, "severity"))
        severity_counts[sev] += 1
        category_counts[_get(f, "category", "Uncategorized")] += 1

        findings_by_severity[sev].append({
            "rule_id": _get(f, "rule_id", "UNKNOWN_RULE"),
            "category": _get(f, "category", "Uncategorized"),
            "file_path": _get(f, "file_path", "?"),
            "line_number": _get(f, "line_number", "?"),
            "message": _get(f, "message", ""),
            "suggested_fix": _get(f, "suggested_fix"),
            "code_snippet": _get(f, "code_snippet"),
            "severity_reason": _get(f, "severity_reason", ""),
            "reduced_severity": bool(_get(f, "reduced_severity", False)),
            "reduced_reason": _get(f, "reduced_reason", ""),
        })

    # Sort each severity group by file path then line number for stable, readable output
    for sev in findings_by_severity:
        findings_by_severity[sev].sort(
            key=lambda x: (str(x["file_path"]), _sort_line(x["line_number"]))
        )

    sorted_categories = category_counts.most_common()
    max_category_count = max((c for _, c in sorted_categories), default=1)

    risk_score, risk_band_label, risk_band_color = compute_risk_score(findings, files_scanned)

    return {
        "project_name": project_name,
        "scan_timestamp": scan_timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "category_counts": sorted_categories,
        "max_category_count": max_category_count,
        "findings_by_severity": findings_by_severity,
        "risk_score": risk_score,
        "risk_band_label": risk_band_label,
        "risk_band_color": risk_band_color,
    }


def _sort_line(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def generate_report(findings, project_name, files_scanned, output_path,
                     scan_timestamp=None):
    """
    Render findings to an HTML file at output_path.

    Parameters
    ----------
    findings : list[dict | object]   flat list of findings from the rules engine
    project_name : str               display name for the header
    files_scanned : int              used for risk-score density normalization
    output_path : str                where to write the .html file
    scan_timestamp : str, optional   defaults to now()

    Returns
    -------
    str  the output_path that was written
    """
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template(TEMPLATE_NAME)

    context = build_report_context(findings, project_name, files_scanned, scan_timestamp)
    html = template.render(**context)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path