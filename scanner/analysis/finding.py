"""
finding.py
----------
Shared result type for every code-quality analysis module (complexity,
unused_vars, nesting_depth, dead_code).

Why a shared type: without this, each of the 4 modules would invent its
own result shape, and Phase 7 (the reporter) would need special-case
code for each one. With ONE common AnalysisFinding, the CLI/reporter
can loop over all 4 modules' output identically:

    for finding in all_findings:
        print(finding.file_path, finding.line, finding.message)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class AnalysisFinding:
    """One code-quality issue found by a Phase 3 analysis module."""

    check: str          # which module produced this: "complexity", "unused_vars", "nesting_depth", "dead_code"
    file_path: Path      # relative path of the file (from ScannedFile.relative_path)
    line: int            # 1-indexed line number
    message: str         # human-readable explanation of the issue
    function_name: str = ""   # name of the enclosing function, if applicable
    metric_value: int = 0     # the raw number behind the finding (complexity score, nesting depth, etc.)

    def __repr__(self) -> str:
        return f"AnalysisFinding[{self.check}]({self.file_path}:{self.line} - {self.message})"