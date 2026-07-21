"""
path_traversal.py
--------------------
Rule 7/8 -- Path Traversal (CWE-22, Severity: High)

Detection rule: a function that reads raw user input AND uses it (via
a same-named variable) as an argument to a filesystem operation --
open(), os.path.join(), or pathlib's Path() -- with no path-safety
construct anywhere in the function: no ".." containment check, no
os.path.abspath()/realpath()/normpath()/commonpath() canonicalization,
and no .startswith() check against a known base directory.

Why this matters: if a filename/path comes straight from user input
(e.g. `open(request.args.get("file"))`), an attacker can supply a value
like `../../etc/passwd` or `../../../app/config.py` to escape the
intended directory and read (or, with a write-mode open, overwrite)
files anywhere the process has permission to touch.

Design decisions (same conservative approach as missing_input_validation.py,
and for the same reason -- see that file's docstring for the full
rationale): this is a FUNCTION-LEVEL heuristic ("does this function
receive raw input, touch a path-sink, and have zero safety constructs
anywhere"), not confirmed data-flow. Confidence is always LOW/MEDIUM,
never HIGH, and this rule shares the `is_user_input_call()` detector
with missing_input_validation.py (factored into ast_utils.py) so both
rules recognize the same input sources consistently.

Severity: High -- justified because a successful path traversal can
expose sensitive files (source code, credentials, `/etc/passwd`) or, in
write scenarios, overwrite arbitrary files -- a serious, direct impact,
though it requires the attacker to know or guess a useful target path
(unlike SQL/command injection, which can extract that information as
part of the attack itself). This matches CWE-22's typical classification.
"""

from __future__ import annotations

import ast
from typing import List, Union

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.ast_utils import is_user_input_call
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

_PATH_SAFETY_CALL_ATTRS = {"abspath", "realpath", "normpath", "commonpath", "resolve", "startswith"}


def _is_path_sink(node: ast.expr) -> bool:
    """True for open(...), os.path.join(...), and pathlib Path(...)
    calls -- the three common ways a filesystem path gets used."""
    if not isinstance(node, ast.Call):
        return False

    if isinstance(node.func, ast.Name) and node.func.id in {"open", "Path"}:
        return True

    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "path"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "os"
    ):
        return True

    return False


def _looks_like_path_safety_check(node: ast.expr) -> bool:
    """True for canonicalization/containment checks commonly used to
    stop path traversal: os.path.abspath/realpath/normpath/commonpath,
    Path.resolve(), a `.startswith(base_dir)` check, or a literal `".."`
    containment test."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in _PATH_SAFETY_CALL_ATTRS:
            return True

    if isinstance(node, ast.Compare):
        # ".." in path  /  ".." not in path
        operands = [node.left] + list(node.comparators)
        has_dotdot_literal = any(
            isinstance(operand, ast.Constant) and operand.value == ".." for operand in operands
        )
        has_membership_op = any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
        if has_dotdot_literal and has_membership_op:
            return True

    return False


def _has_any_path_safety_check(function_node: FunctionNode) -> bool:
    return any(_looks_like_path_safety_check(n) for n in ast.walk(function_node))


class PathTraversalRule(Rule):
    rule_id = "path_traversal"
    cwe_id = "CWE-22"
    default_severity = Severity.HIGH
    description = "User-controlled filename/path reaches open()/os.path.join()/Path() with no canonicalization or '..' check."

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
                if is_user_input_call(sub):
                    has_input_source = True
                if _is_path_sink(sub) and sink_line is None:
                    sink_line = sub.lineno

            if has_input_source and sink_line is not None and not _has_any_path_safety_check(node):
                severity = Severity.LOW if is_test else self.default_severity
                findings.append(
                    self._make_finding(
                        parsed_file=parsed_file,
                        line=sink_line,
                        message=(
                            f"Function '{node.name}' reads raw request/user input and passes a "
                            f"path to open()/os.path.join()/Path(), with no '..' check or path "
                            f"canonicalization found anywhere in the function."
                        ),
                        fix_suggestion=(
                            "Canonicalize the path (os.path.realpath() or Path.resolve()) and "
                            "verify it's still inside the intended base directory (e.g. with "
                            "os.path.commonpath([base, resolved]) == base) before opening it -- "
                            "don't rely on just rejecting '..' substrings, which can be bypassed."
                        ),
                        severity=severity,
                        confidence=Confidence.LOW,
                        function_name=node.name,
                    )
                )

        return findings