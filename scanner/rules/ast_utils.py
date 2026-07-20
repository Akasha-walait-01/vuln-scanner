"""
ast_utils.py
------------
Small AST-pattern helpers shared across multiple Phase 4 rules. This is
NOT a rule itself -- it's just the "is this expression built
dynamically at runtime" check that both sql_injection.py and
command_injection.py need (a query string and a shell command string
are both "dangerous if dynamically assembled" in the same structural
way), factored out so it's written once and stays consistent.
"""

from __future__ import annotations

import ast


def looks_stringy(node: ast.expr) -> bool:
    """True if `node` is a string literal or itself a dynamically-built
    string expression -- used to decide whether a BinOp's operand is
    plausibly part of building a string (vs. e.g. plain arithmetic like
    `x + 1`, which should NOT be treated as string-building)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    return isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call))


def is_dynamic_string(node: ast.expr) -> bool:
    """True if `node` builds a string at runtime via f-string,
    concatenation (+), %-formatting, or .format() -- the four common
    ways a string gets assembled from pieces instead of being a fixed
    literal."""
    if isinstance(node, ast.JoinedStr):
        return True

    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod):
            return True
        if isinstance(node.op, ast.Add):
            return looks_stringy(node.left) or looks_stringy(node.right)

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True

    return False


def is_attribute_call(node: ast.expr, module_name: str, method_names: set) -> bool:
    """True if `node` is a call shaped like `module_name.method(...)`,
    e.g. is_attribute_call(node, "os", {"system", "popen"}) matches
    `os.system(...)` and `os.popen(...)`."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in method_names
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == module_name
    )


def get_keyword_bool(node: ast.Call, keyword_name: str) -> bool:
    """Return True if `node` has `keyword_name=True` as a literal
    keyword argument, e.g. get_keyword_bool(call, "shell") checks for
    `shell=True` in a subprocess.run(..., shell=True) call."""
    for kw in node.keywords:
        if kw.arg == keyword_name and isinstance(kw.value, ast.Constant):
            return kw.value.value is True
    return False