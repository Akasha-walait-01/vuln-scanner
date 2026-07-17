"""
complexity.py
-------------
Cyclomatic complexity calculator using the McCabe formula.

The idea: start at 1 (one straight-line path through the function with
no branches), then add 1 for every "decision point" -- every place
where execution can branch onto a different path. The final number is
(roughly) how many independent paths a test suite would need to cover
the function fully -- a good proxy for "how hard is this to reason
about and test."

Decision points counted:
- if / elif                    (ast.If)
- for / async for               (ast.For / ast.AsyncFor)
- while                          (ast.While)
- except clause                 (ast.ExceptHandler)
- ternary expression             (ast.IfExp)   e.g. `x if cond else y`
- assert                         (ast.Assert)
- boolean operators              (ast.BoolOp)  each extra and/or operand
- comprehension `if` filters     (ast.comprehension.ifs)

Why NOT `with` or a bare `try`: neither introduces a branch -- code
after them runs unconditionally either way, so they don't add to how
many distinct paths exist. An `except` clause DOES branch (it's an
alternate path execution can take if something goes wrong), so that's
counted.

Why nested functions/lambdas are excluded from the parent's count:
complexity should measure how hard ONE function is to reason about. A
nested function is its own independently-testable unit -- folding its
branches into the outer function's score would double-count and
misrepresent the outer function's real complexity.
"""

from __future__ import annotations

import ast
from typing import List, Union

from scanner.analysis.finding import AnalysisFinding
from scanner.parser.ast_parser import ParsedFile

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# Functions at or below this score are considered reasonable to read
# and test. Above it, we flag them as "overly complex" per the brief.
# 10 is the McCabe-recommended common default used by most linters.
DEFAULT_COMPLEXITY_THRESHOLD = 10


class _ComplexityVisitor(ast.NodeVisitor):
    """Walks a single function's body and counts decision points.
    Stops at nested function/lambda boundaries -- those are scored
    separately when the caller encounters them on its own walk."""

    def __init__(self) -> None:
        self.complexity = 1  # baseline: one path through the function

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # `a and b and c` has 2 extra decision points (3 operands - 1
        # baseline path already counted).
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.complexity += len(node.ifs)
        self.generic_visit(node)

    # Nested scopes get their own independent score -- do NOT descend
    # into them from here.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass


def calculate_complexity(function_node: FunctionNode) -> int:
    """Return the McCabe cyclomatic complexity of a single function."""
    visitor = _ComplexityVisitor()
    for stmt in function_node.body:
        visitor.visit(stmt)
    return visitor.complexity


def find_complex_functions(
    parsed_file: ParsedFile,
    threshold: int = DEFAULT_COMPLEXITY_THRESHOLD,
) -> List[AnalysisFinding]:
    """Walk a parsed file and flag every function whose cyclomatic
    complexity exceeds `threshold`."""
    findings: List[AnalysisFinding] = []
    if not parsed_file.ok:
        return findings

    for node in ast.walk(parsed_file.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            score = calculate_complexity(node)
            if score > threshold:
                findings.append(
                    AnalysisFinding(
                        check="complexity",
                        file_path=parsed_file.relative_path,
                        line=node.lineno,
                        message=(
                            f"Function '{node.name}' has cyclomatic complexity "
                            f"{score} (threshold: {threshold}). Consider splitting "
                            f"it into smaller functions."
                        ),
                        function_name=node.name,
                        metric_value=score,
                    )
                )
    return findings