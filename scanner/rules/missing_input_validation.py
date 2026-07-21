"""
missing_input_validation.py
-------------------------------
Rule 6/8 -- Missing Input Validation (CWE-20, Severity: Medium)

Detection rule: a function that BOTH (a) reads raw user-facing input
(request.args.get(), request.form.get(), request.GET/POST.get(),
Python's input(), etc.) AND (b) passes something to a sensitive
operation (open(), a DB .execute(), os.system/os.popen, eval/exec) --
with NO validation-looking construct (isinstance, len(), a regex
match/search, a `.isdigit()`-style string check, or an `in` membership
check) ANYWHERE in that function.

Why this is a FUNCTION-LEVEL heuristic, not real taint tracking: proving
"this specific tainted value flows unvalidated into this specific sink"
requires tracing data flow through the function -- assignments,
reassignments, calls to helper functions, etc. That's exactly what
Phase 6 (taint_tracker.py) adds. This Phase 4 rule takes the coarser,
honest approach instead: "does this function receive raw input AND
touch a sensitive sink, with not a single validation-shaped construct
anywhere in it?" That's weaker evidence than confirmed taint, which is
why this rule's confidence is LOW/MEDIUM (never HIGH) and its severity
is Medium rather than Critical/High -- it's a "worth a human look"
signal, not a confirmed vulnerability. Phase 6 is expected to sharpen
this significantly for at least one vulnerability class.

Why validation is checked "anywhere in the function" rather than
"between the input source and the sink": tracking precise ordering
and reassignment would again require real data-flow analysis. Checking
"is there ANY validation-shaped construct in this function at all" is a
deliberately conservative choice that minimizes false positives at some
cost to precision -- a function that validates a different variable
would also (incorrectly) count as "having validation" here, which is a
documented limitation, not an oversight.

Severity: Medium -- justified because this is the weakest-evidence rule
of the 8 (a structural absence, not a confirmed dangerous pattern like
the other rules), and because "missing validation" alone isn't itself
exploitable -- it's a missing SAFEGUARD, not a vulnerability by itself.
"""

from __future__ import annotations

import ast
from typing import List, Union

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# Attribute names on a `request`-like object that hand back raw,
# attacker-controllable input in common Python web frameworks
# (Flask/Django/FastAPI-style request objects).
_REQUEST_INPUT_ATTRS = {"args", "form", "values", "GET", "POST", "json", "query_params", "COOKIES", "headers"}

_SENSITIVE_SINK_ATTR_NAMES = {"execute", "executemany", "system", "popen"}


def _is_user_input_call(node: ast.expr) -> bool:
    """True for input()/request.<attr>.get(...) style calls that hand
    back raw, unvalidated user-controlled data."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
        return True

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr in _REQUEST_INPUT_ATTRS
    ):
        return True

    return False


def _is_sensitive_sink(node: ast.expr) -> bool:
    """True for calls into operations where unvalidated input causes
    real problems: opening a file, running a DB query, or invoking a
    shell/eval."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in {"open", "eval", "exec"}:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _SENSITIVE_SINK_ATTR_NAMES:
            return True
    return False


def _looks_like_validation(node: ast.expr) -> bool:
    """True for constructs commonly used to validate input: isinstance
    checks, length checks, regex match/search, string-content checks
    (.isdigit() etc.), or an `in` / `not in` membership test (e.g.
    checking against a whitelist)."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in {"isinstance", "len"}:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "match", "fullmatch", "search",  # re.match/fullmatch/search
            "isdigit", "isalpha", "isalnum", "isnumeric",  # str content checks
        }:
            return True
    if isinstance(node, ast.Compare):
        if any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            return True
    return False


def _has_any_validation(function_node: FunctionNode) -> bool:
    return any(_looks_like_validation(n) for n in ast.walk(function_node))


class MissingInputValidationRule(Rule):
    rule_id = "missing_input_validation"
    cwe_id = "CWE-20"
    default_severity = Severity.MEDIUM
    description = "Function reads raw user input and reaches a sensitive operation with no validation-shaped construct anywhere in it."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            has_input_source = False
            sink_line = None

            for sub in ast.walk(node):
                if _is_user_input_call(sub):
                    has_input_source = True
                if _is_sensitive_sink(sub) and sink_line is None:
                    sink_line = sub.lineno

            if has_input_source and sink_line is not None and not _has_any_validation(node):
                severity = Severity.LOW if is_test else self.default_severity
                findings.append(
                    self._make_finding(
                        parsed_file=parsed_file,
                        line=sink_line,
                        message=(
                            f"Function '{node.name}' reads raw request/user input and reaches a "
                            f"sensitive operation, with no validation (type/length/regex/whitelist "
                            f"check) found anywhere in the function."
                        ),
                        fix_suggestion=(
                            "Validate the input before using it -- check its type, length, and "
                            "format/content (e.g. a regex or whitelist check) before passing it to "
                            "a file, database, or shell operation."
                        ),
                        severity=severity,
                        confidence=Confidence.LOW,
                        function_name=node.name,
                    )
                )

        return findings