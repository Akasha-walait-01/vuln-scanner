"""
dead_code.py
------------
Detects unreachable code:
1. Any statement that appears AFTER an unconditional
   return / raise / break / continue in the same block -- that
   statement can never execute.
2. The body of an `if <always-false-constant>:` block (e.g. `if False:`,
   `if 0:`) -- can never execute.
3. The `else` body of an `if <always-true-constant>:` block (e.g.
   `if True:` ... `else:` ...) -- the else branch can never execute.

Design decisions:
- We scan every block in the file, including inside nested functions,
  if-bodies, loop bodies, try/except/finally, and with-blocks -- dead
  code can hide anywhere, not just at the top level of a function.
- Only the FIRST unreachable statement per block is reported (not
  every single line after it). Once we know "everything after line 12
  is dead," listing every subsequent line individually is noise, not
  signal -- one clear finding pointing at where reachability was lost
  is more actionable.
- "Always false/true" detection is intentionally conservative: it only
  recognizes literal constants (`False`, `True`, `0`, `1`, `None`,
  `""`, etc.), NOT variables or function calls that might evaluate to a
  constant at runtime. Trying to prove a variable is always falsy would
  require real value-flow analysis (out of scope here) and risks false
  positives; a literal `if False:` is unambiguous.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.analysis.finding import AnalysisFinding
from scanner.parser.ast_parser import ParsedFile

# Statements that unconditionally end execution of the current block --
# nothing after one of these (in the same block) can ever run.
_TERMINAL_STATEMENTS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _is_always_false(test: ast.expr) -> bool:
    """True only for a literal constant that is falsy, e.g. `False`, `0`."""
    return isinstance(test, ast.Constant) and not test.value


def _is_always_true(test: ast.expr) -> bool:
    """True only for a literal constant that is truthy, e.g. `True`, `1`."""
    return isinstance(test, ast.Constant) and bool(test.value)


def _child_blocks(stmt: ast.stmt) -> List[list]:
    """Return every nested statement-list (body/orelse/finalbody/except
    handler bodies) that lives directly inside `stmt`, so the caller can
    recurse into it with a fresh reachability check."""
    blocks: List[list] = []

    if hasattr(stmt, "body") and isinstance(getattr(stmt, "body"), list):
        blocks.append(stmt.body)
    if hasattr(stmt, "orelse") and isinstance(getattr(stmt, "orelse"), list) and stmt.orelse:
        blocks.append(stmt.orelse)
    if hasattr(stmt, "finalbody") and isinstance(getattr(stmt, "finalbody"), list) and stmt.finalbody:
        blocks.append(stmt.finalbody)
    if isinstance(stmt, ast.Try):
        for handler in stmt.handlers:
            blocks.append(handler.body)

    return blocks


def _check_block(
    stmts: list,
    parsed_file: ParsedFile,
    findings: List[AnalysisFinding],
) -> None:
    """Scan one sequential block of statements for dead code, and
    recurse into every nested block found along the way."""
    unreachable_from: int | None = None  # lineno of the terminal statement, once hit

    for stmt in stmts:
        if unreachable_from is not None:
            findings.append(
                AnalysisFinding(
                    check="dead_code",
                    file_path=parsed_file.relative_path,
                    line=stmt.lineno,
                    message=(
                        f"Unreachable code: this statement can never execute "
                        f"because line {unreachable_from} unconditionally "
                        f"returns/raises/breaks/continues."
                    ),
                )
            )
            # Only report the first dead statement in this block -- stop
            # flagging further lines here, but keep scanning (below) in
            # case there's a different, separately-interesting issue
            # nested inside this unreachable statement.
            unreachable_from = None

        if isinstance(stmt, ast.If):
            if _is_always_false(stmt.test) and stmt.body:
                findings.append(
                    AnalysisFinding(
                        check="dead_code",
                        file_path=parsed_file.relative_path,
                        line=stmt.body[0].lineno,
                        message="Unreachable code: this 'if' condition is always False.",
                    )
                )
            elif _is_always_true(stmt.test) and stmt.orelse:
                findings.append(
                    AnalysisFinding(
                        check="dead_code",
                        file_path=parsed_file.relative_path,
                        line=stmt.orelse[0].lineno,
                        message="Unreachable code: this 'else' can never run because the 'if' condition is always True.",
                    )
                )

        for block in _child_blocks(stmt):
            _check_block(block, parsed_file, findings)

        if isinstance(stmt, _TERMINAL_STATEMENTS):
            unreachable_from = stmt.lineno


def find_dead_code(parsed_file: ParsedFile) -> List[AnalysisFinding]:
    """Scan an entire parsed file (every function, every nested block)
    for unreachable code."""
    findings: List[AnalysisFinding] = []
    if not parsed_file.ok:
        return findings

    _check_block(parsed_file.tree.body, parsed_file, findings)
    return findings