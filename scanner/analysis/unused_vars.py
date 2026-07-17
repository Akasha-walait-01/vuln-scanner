"""
unused_vars.py
--------------
Detects variables that are assigned a value but never read afterward --
a common sign of leftover debug code, copy-paste mistakes, or logic
that was refactored away but left its assignment behind.

Scope: per-function only (not module-level). Module-level "unused"
names are routinely re-exported via imports elsewhere, used by other
tools, or intentionally public -- flagging them produces far more noise
than signal. Function-local variables have a much clearer, self-
contained scope, so that's where this check focuses.

Design decisions:
- Only simple `x = value` assignments are tracked (a single Name
  target). Tuple-unpacking assignments (`a, b = pair()`) are
  deliberately skipped: it's extremely common to unpack a value and
  only need part of it (e.g. `_, count = divmod(...)`), and flagging
  every one of those would be mostly false positives.
- A name is counted as "used" if it's read (ast.Load context) ANYWHERE
  in the function body, including inside a nested function/lambda --
  a closure reading an outer variable is a legitimate use of it.
- Names starting with `_` (e.g. `_`, `_unused`) are never flagged --
  that's the common Python convention for "I know I'm not using this."
- Only the LAST assignment to a name that's never subsequently read is
  flagged (if a name is reassigned multiple times, only the final,
  truly-dead assignment matters; earlier ones may have been read before
  being overwritten, which is normal, valid code).
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Union

from scanner.analysis.finding import AnalysisFinding
from scanner.parser.ast_parser import ParsedFile

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]


class _AssignmentCollector(ast.NodeVisitor):
    """Collects simple `name = value` assignments made directly within
    a function's own scope (does NOT descend into nested function
    definitions -- those are a separate scope with their own vars)."""

    def __init__(self) -> None:
        self.assignments: Dict[str, int] = {}  # name -> most recent assignment lineno

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if not name.startswith("_"):
                self.assignments[name] = node.lineno
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            name = node.target.id
            if not name.startswith("_"):
                self.assignments[name] = node.lineno
        self.generic_visit(node)

    # Nested scopes have their own variables -- don't collect their
    # assignments as if they belonged to the outer function.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass


class _UsageCollector(ast.NodeVisitor):
    """Collects every name that is READ (Load context) anywhere in the
    subtree -- including inside nested functions/lambdas, since a
    closure reading an outer-scope variable is a real use of it."""

    def __init__(self) -> None:
        self.used: Set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.used.add(node.id)
        self.generic_visit(node)


def find_unused_vars(parsed_file: ParsedFile) -> List[AnalysisFinding]:
    """Walk every function in a parsed file and flag simple variable
    assignments that are never read afterward within that function."""
    findings: List[AnalysisFinding] = []
    if not parsed_file.ok:
        return findings

    for node in ast.walk(parsed_file.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        assign_collector = _AssignmentCollector()
        for stmt in node.body:
            assign_collector.visit(stmt)

        usage_collector = _UsageCollector()
        for stmt in node.body:
            usage_collector.visit(stmt)

        for name, lineno in assign_collector.assignments.items():
            if name not in usage_collector.used:
                findings.append(
                    AnalysisFinding(
                        check="unused_vars",
                        file_path=parsed_file.relative_path,
                        line=lineno,
                        message=(
                            f"Variable '{name}' is assigned but never used "
                            f"in function '{node.name}'."
                        ),
                        function_name=node.name,
                    )
                )
    return findings