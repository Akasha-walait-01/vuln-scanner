"""
nesting_depth.py
----------------
Tracks how deeply nested control-flow blocks (if/for/while/try/with)
are within a function, and flags functions that exceed a configurable
depth threshold as hard to read and maintain.

Design decisions:
- Only control-flow statements that create a new indented block count
  toward depth: if, for, while, try (and its except/finally blocks),
  with. Simple statements (assignments, calls, etc.) never add depth.
- An `elif` chain is intentionally NOT counted as extra depth per
  branch. `elif` is represented in the AST as a nested `If` inside the
  previous `If`'s `orelse`, but conceptually a 5-branch if/elif/elif/
  elif/else chain is no harder to read than a 2-branch one -- what
  actually hurts readability is an `if` nested INSIDE another `if`'s
  body, which this correctly counts as +1 deeper.
- Nested function/class definitions get their own independent nesting
  score -- we don't count into them from the outer function, for the
  same reason as complexity.py: each function should be judged on its
  own structure, not penalized for what a helper function inside it
  does.
"""

from __future__ import annotations

import ast
from typing import List, Union

from scanner.analysis.finding import AnalysisFinding
from scanner.parser.ast_parser import ParsedFile

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# Functions whose nesting exceeds this are flagged as hard to follow.
DEFAULT_NESTING_THRESHOLD = 4


def _is_elif_chain_continuation(if_node: ast.If) -> bool:
    """True if this If's orelse is itself a single If -- i.e. this is
    an `elif`, not a fresh nested if. Used so elif chains don't
    artificially inflate depth."""
    return len(if_node.orelse) == 1 and isinstance(if_node.orelse[0], ast.If)


def _block_depth(stmts: list, current_depth: int) -> int:
    """Return the maximum nesting depth reached anywhere inside `stmts`,
    given that `stmts` itself is already at `current_depth`."""
    max_depth = current_depth

    for stmt in stmts:
        if isinstance(stmt, ast.If):
            max_depth = max(max_depth, _block_depth(stmt.body, current_depth + 1))
            if stmt.orelse:
                # elif -> same depth as this if (not deeper); else -> one deeper.
                next_depth = current_depth if _is_elif_chain_continuation(stmt) else current_depth + 1
                max_depth = max(max_depth, _block_depth(stmt.orelse, next_depth))

        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            max_depth = max(max_depth, _block_depth(stmt.body, current_depth + 1))
            if stmt.orelse:
                max_depth = max(max_depth, _block_depth(stmt.orelse, current_depth + 1))

        elif isinstance(stmt, ast.Try):
            max_depth = max(max_depth, _block_depth(stmt.body, current_depth + 1))
            for handler in stmt.handlers:
                max_depth = max(max_depth, _block_depth(handler.body, current_depth + 1))
            if stmt.orelse:
                max_depth = max(max_depth, _block_depth(stmt.orelse, current_depth + 1))
            if stmt.finalbody:
                max_depth = max(max_depth, _block_depth(stmt.finalbody, current_depth + 1))

        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            max_depth = max(max_depth, _block_depth(stmt.body, current_depth + 1))

        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested scope -- scored independently, don't fold into parent.
            continue

    return max_depth


def max_nesting_depth(function_node: FunctionNode) -> int:
    """Return the maximum control-flow nesting depth inside a single
    function (0 = no nested blocks at all, a flat function body)."""
    return _block_depth(function_node.body, 0)


def find_deep_nesting(
    parsed_file: ParsedFile,
    threshold: int = DEFAULT_NESTING_THRESHOLD,
) -> List[AnalysisFinding]:
    """Walk a parsed file and flag every function whose nesting depth
    exceeds `threshold`."""
    findings: List[AnalysisFinding] = []
    if not parsed_file.ok:
        return findings

    for node in ast.walk(parsed_file.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            depth = max_nesting_depth(node)
            if depth > threshold:
                findings.append(
                    AnalysisFinding(
                        check="nesting_depth",
                        file_path=parsed_file.relative_path,
                        line=node.lineno,
                        message=(
                            f"Function '{node.name}' has nesting depth {depth} "
                            f"(threshold: {threshold}). Consider extracting "
                            f"inner blocks into helper functions."
                        ),
                        function_name=node.name,
                        metric_value=depth,
                    )
                )
    return findings