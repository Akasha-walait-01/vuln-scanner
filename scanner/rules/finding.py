"""
finding.py
----------
Shared result type for every vulnerability rule (Phase 4) -- mirrors
the same "one common shape" idea as scanner/analysis/finding.py, but
extended with the fields a *security* finding needs that a code-quality
finding doesn't: a CWE ID (industry-standard vulnerability
classification), a severity level, and a suggested fix.

Why CWE IDs: CWE (Common Weakness Enumeration) is the industry-standard
taxonomy for vulnerability classes -- e.g. CWE-89 always means "SQL
Injection" everywhere, in every tool, every report. Attaching the CWE ID
lets our report speak the same language as real-world SAST tools
(Semgrep, Bandit, Snyk, etc.), even though this scanner's own detection
logic is 100% custom-written.

Why `confidence` is separate from `severity`: severity answers "how bad
would this be if it's real" (e.g. SQL injection is always Critical
IMPACT). Confidence answers "how sure are we this is real" (e.g. a
plain heuristic match is lower-confidence than one confirmed by taint
tracking in Phase 6). Keeping them separate means Phase 6's taint layer
can upgrade confidence without needing to touch severity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Ordered low -> critical. Inherits from str so it prints cleanly
    and compares easily (e.g. in the HTML report / sorting by severity)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Used to sort findings critical-first in the Phase 7 report.
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class VulnerabilityFinding:
    """One security issue found by a Phase 4 rule."""

    rule_id: str            # e.g. "sql_injection" -- matches the rule's module name
    cwe_id: str              # e.g. "CWE-89"
    severity: Severity
    file_path: Path
    line: int
    message: str             # what the problem is
    fix_suggestion: str      # what to do about it
    code_snippet: str = ""   # the actual offending line, for the report
    confidence: Confidence = Confidence.MEDIUM
    function_name: str = ""

    def __repr__(self) -> str:
        return (
            f"VulnerabilityFinding[{self.rule_id}/{self.cwe_id}]"
            f"({self.severity.value}, {self.file_path}:{self.line})"
        )