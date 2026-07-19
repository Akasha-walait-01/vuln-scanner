"""
base_rule.py
------------
The common interface every one of the 8 vulnerability rules extends.
This is deliberately written FIRST, before any individual rule, so all
8 rules stay consistent -- same method signature, same way of building
a finding, same metadata shape (rule_id, cwe_id, default_severity).

Why an abstract base class (not just 8 independent functions): the
rule engine (whatever eventually calls all 8 rules) needs to treat them
uniformly -- loop over a list of Rule instances and call .check() on
each, without caring which specific rule it is. That uniformity is
exactly what an ABC with one abstract method buys us.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding


class Rule(ABC):
    """Base class every vulnerability rule must extend.

    Subclasses must set the three class attributes (rule_id, cwe_id,
    default_severity) and implement check().
    """

    # --- Required metadata, set by every subclass ---
    rule_id: str = ""              # e.g. "sql_injection"
    cwe_id: str = ""                # e.g. "CWE-89"
    default_severity: Severity = Severity.MEDIUM
    description: str = ""           # one-line human description, used in reports/docs

    @abstractmethod
    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        """Scan one parsed file's AST and return every finding for this
        rule. Must return an empty list (not raise) if nothing is found
        or if parsed_file failed to parse -- a broken/unparsed file is
        not this rule's problem to report on.
        """
        raise NotImplementedError

    def _make_finding(
        self,
        parsed_file: ParsedFile,
        line: int,
        message: str,
        fix_suggestion: str,
        severity: Optional[Severity] = None,
        confidence: Confidence = Confidence.MEDIUM,
        function_name: str = "",
    ) -> VulnerabilityFinding:
        """Helper every subclass uses to build a finding consistently --
        so no rule has to remember to fill in rule_id/cwe_id/snippet by
        hand every time (and risk copy-paste mistakes)."""
        return VulnerabilityFinding(
            rule_id=self.rule_id,
            cwe_id=self.cwe_id,
            severity=severity or self.default_severity,
            file_path=parsed_file.relative_path,
            line=line,
            message=message,
            fix_suggestion=fix_suggestion,
            code_snippet=parsed_file.line(line).strip(),
            confidence=confidence,
            function_name=function_name,
        )

    def _is_test_file(self, parsed_file: ParsedFile) -> bool:
        """Shared false-positive-reduction helper (per the brief's
        Phase 6 requirement, but useful to every rule from day one):
        a hardcoded string, weak-crypto call, etc. inside a test file
        is far less concerning than the same thing in production code.
        Individual rules can use this to lower severity/confidence
        instead of dropping the finding entirely -- test files CAN
        still have real bugs worth knowing about, just usually lower-
        stakes ones."""
        path_str = str(parsed_file.relative_path).replace("\\", "/")
        return (
            "/tests/" in f"/{path_str}"
            or path_str.startswith("tests/")
            or path_str.split("/")[-1].startswith("test_")
            or path_str.split("/")[-1].endswith("_test.py")
        )