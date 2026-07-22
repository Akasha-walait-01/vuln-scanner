"""
taint_tracker.py
-------------------
Phase 6 -- Contextual Reasoning Layer: real intraprocedural (single-
function) data-flow tracing for COMMAND INJECTION (CWE-78), chosen per
the brief's suggestion ("command injection ya SQL injection").

Why this catches vulnerabilities Phase 4's command_injection.py MISSES:
Phase 4's rule flags os.system()/os.popen() ONLY when the argument is
built INLINE and dynamically (an f-string, concatenation, etc. -- see
is_dynamic_string() in ast_utils.py). It does NOT flag:

    def run(cmd):
        os.system(cmd)          # <-- Phase 4 rule misses this entirely!

...because `cmd` alone is just a bare variable reference, not a
dynamically-BUILT string. (Note: for subprocess.*(shell=True) calls
specifically, Phase 4's rule already flags them regardless of whether
the command argument is dynamic, since shell=True is itself the
dangerous configuration -- so this tracker's os.system/os.popen
bare-variable case is where the real, otherwise-total gap is; for
subprocess it mainly upgrades an already-flagged finding to
HIGH-confidence, traced evidence instead of a structural guess.)

This is exactly the gap the brief describes: "track whether user input
actually reaches a dangerous function call, rather than flagging every
occurrence of that function" -- Phase 4 already avoids flagging EVERY
occurrence (that's the whole point of its is_dynamic_string check), but
it can't yet trace a value back through assignments to see where it
originally came from. That's what this module adds.

How the tracing works (per the brief's exact steps):
1. Every function PARAMETER is marked as a "tainted source" -- the
   brief specifies parameters specifically (not, say, request.get()
   calls, which the Phase 4 rules already handle separately). This is
   a deliberate scope choice: a function-level scanner has no call
   graph, so it can't know whether a parameter's caller passed
   attacker-controlled data -- treating every parameter as
   potentially-tainted is the conservative, honest assumption.
2. Walking the function body top-to-bottom, taint PROPAGATES through
   simple assignment: if the right-hand side of `x = ...` references
   any currently-tainted name, `x` becomes tainted too. If the RHS is
   completely clean (e.g. a fixed literal), `x` is marked clean again
   -- taint is "killed" by reassignment, so a variable that starts
   tainted but is later overwritten with a safe value stops being
   flagged.
3. A finding is only raised when a tainted variable reaches a
   dangerous SINK (os.system/os.popen, or subprocess.*(shell=True)).

Known limitation (documented honestly, not hidden): this is
FLOW-INSENSITIVE across branches -- if/for/while/try bodies are all
walked with the SAME shared taint set, rather than forking and merging
state per-branch. A variable tainted only inside one `if` branch is
treated as tainted afterward too, even on paths that didn't take that
branch. This can cause occasional false positives, but avoiding false
NEGATIVES (missing a real taint path) was prioritized, since missing a
genuine command-injection path is the worse failure mode for a
security scanner. This limitation is written up in the design document
(Phase 9).

Note on "skip strings inside comments" (brief's Phase 6 checklist):
this requires NO extra code here. Python's `ast` module never creates
AST nodes for comments in the first place -- they're discarded by the
tokenizer before parsing even happens. Since every rule and this
tracker only ever walks the AST (never the raw source text), comment
content is structurally invisible to the whole scanner by construction
-- there's nothing to "skip" because it was never there to begin with.
"""

from __future__ import annotations

import ast
from typing import List, Set, Union

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.ast_utils import get_keyword_bool, is_attribute_call
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

_OS_SHELL_FUNCS = {"system", "popen"}
_SUBPROCESS_FUNCS = {"call", "run", "Popen", "check_call", "check_output"}

# Statement types that introduce a nested block. Everything else is a
# "simple" statement that can safely be fully ast.walk()-ed for sink
# calls without risking double-visiting a nested block's statements.
_COMPOUND_STMT_TYPES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)


def _is_dangerous_sink(node: ast.expr) -> bool:
    """True for os.system()/os.popen(), or subprocess.*(shell=True) --
    the same sink definitions command_injection.py uses, kept
    independent here so this module stays self-contained and its
    detection logic is fully traceable on its own."""
    if is_attribute_call(node, "os", _OS_SHELL_FUNCS):
        return True
    if is_attribute_call(node, "subprocess", _SUBPROCESS_FUNCS) and get_keyword_bool(node, "shell"):
        return True
    return False


def _expr_references_tainted(node: ast.expr, tainted: Set[str]) -> bool:
    """True if any Name inside this expression subtree is currently
    tainted -- covers a bare variable (`cmd`), a dynamically-built
    string referencing one (`f"cat {cmd}"`, `"cat " + cmd`), or a
    tainted value passed through another call."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
    return False


def _child_blocks(stmt: ast.stmt) -> List[list]:
    """Every nested statement-list directly inside `stmt` (body/orelse/
    finalbody/except-handler bodies), so the tracer can descend into
    it with the same shared taint set."""
    blocks: List[list] = []
    if hasattr(stmt, "body") and isinstance(stmt.body, list):
        blocks.append(stmt.body)
    if hasattr(stmt, "orelse") and isinstance(stmt.orelse, list) and stmt.orelse:
        blocks.append(stmt.orelse)
    if hasattr(stmt, "finalbody") and isinstance(stmt.finalbody, list) and stmt.finalbody:
        blocks.append(stmt.finalbody)
    if isinstance(stmt, ast.Try):
        for handler in stmt.handlers:
            blocks.append(handler.body)
    return blocks


class TaintFinding:
    """Internal record before conversion to a VulnerabilityFinding --
    keeps the sink call node and which tainted variable reached it, for
    a clear, specific message."""

    __slots__ = ("node", "tainted_name", "function_name")

    def __init__(self, node: ast.Call, tainted_name: str, function_name: str):
        self.node = node
        self.tainted_name = tainted_name
        self.function_name = function_name


def _first_tainted_name(node: ast.expr, tainted: Set[str]) -> str:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return sub.id
    return "?"


def _trace_function(function_node: FunctionNode) -> List[TaintFinding]:
    """Run the taint trace across one function's body and return every
    point where a tainted variable reached a dangerous sink."""
    args = function_node.args
    tainted: Set[str] = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}

    results: List[TaintFinding] = []
    _walk_statements(function_node.body, tainted, results, function_node.name)
    return results


def _walk_statements(stmts: list, tainted: Set[str], results: List[TaintFinding], function_name: str) -> None:
    for stmt in stmts:
        # --- Taint propagation through assignment ---
        if isinstance(stmt, ast.Assign):
            rhs_tainted = _expr_references_tainted(stmt.value, tainted)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    if rhs_tainted:
                        tainted.add(target.id)
                    else:
                        tainted.discard(target.id)  # reassigned clean -- taint killed
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            if _expr_references_tainted(stmt.value, tainted) or stmt.target.id in tainted:
                tainted.add(stmt.target.id)

        # --- Sink detection (only safe on simple statements -- see
        # _COMPOUND_STMT_TYPES note above) ---
        if not isinstance(stmt, _COMPOUND_STMT_TYPES):
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call) and _is_dangerous_sink(node):
                    for arg in node.args:
                        if _expr_references_tainted(arg, tainted):
                            tainted_name = _first_tainted_name(arg, tainted)
                            results.append(TaintFinding(node, tainted_name, function_name))
                            break
        else:
            for block in _child_blocks(stmt):
                _walk_statements(block, tainted, results, function_name)


class CommandInjectionTaintTracker(Rule):
    """Phase 6 taint tracker for command injection. Extends the same
    Rule interface as the Phase 4 rules so it can be run and reported
    on identically -- from the reporter's point of view, this is just
    another source of VulnerabilityFinding objects."""

    rule_id = "command_injection_taint"
    cwe_id = "CWE-78"
    default_severity = Severity.CRITICAL
    description = "Data-flow-confirmed: a function parameter reaches os.system()/os.popen()/subprocess(shell=True) through traced assignments."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for taint_finding in _trace_function(node):
                severity = Severity.LOW if is_test else self.default_severity
                # This is our HIGHEST-confidence rule in the whole
                # scanner -- unlike the Phase 4 structural rules, this
                # isn't a pattern guess, it's a traced path from a
                # concrete source (the parameter) to a concrete sink.
                confidence = Confidence.LOW if is_test else Confidence.HIGH

                findings.append(
                    self._make_finding(
                        parsed_file=parsed_file,
                        line=taint_finding.node.lineno,
                        message=(
                            f"A tainted value (originating from a parameter of function "
                            f"'{taint_finding.function_name}') reaches a shell command sink via "
                            f"variable '{taint_finding.tainted_name}' -- confirmed data-flow path, "
                            f"not just a structural pattern match."
                        ),
                        fix_suggestion=(
                            "Avoid the shell entirely: pass the command as a list of arguments to "
                            "subprocess.run() without shell=True, so the OS executes the program "
                            "directly and this parameter's value can't be interpreted as shell syntax."
                        ),
                        severity=severity,
                        confidence=confidence,
                        function_name=taint_finding.function_name,
                    )
                )

        return findings