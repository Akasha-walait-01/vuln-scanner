"""
sql_injection.py
-----------------
Rule 1/8 -- SQL Injection (CWE-89, Severity: Critical)

Detection rule: a call to a database-execution method (execute,
executemany, executescript, raw, query -- the common method names
across sqlite3, psycopg2, MySQLdb, Django's .raw(), SQLAlchemy, etc.)
where the query argument is built DYNAMICALLY at runtime -- via an
f-string, string concatenation (+), %-formatting, or .format() --
instead of being a plain string literal or a properly parameterized
query (e.g. `cursor.execute("SELECT * FROM t WHERE id = %s", (id,))`).

Why this AST pattern (not just "flag every .execute() call"): a plain
`cursor.execute("SELECT * FROM users")` is completely safe -- it's a
fixed string, nothing to inject. The danger is specifically when the
query STRING ITSELF is assembled from pieces at runtime, because if any
of those pieces come from user input, an attacker can inject SQL
syntax into the query structure. Flagging every .execute() call
regardless of how the query was built would bury real risks in noise.

Why NOT full taint tracking here (that's Phase 6): this rule is a
STRUCTURAL check -- "is this query dynamically built at all" -- without
yet tracing whether the dynamic piece specifically originated from user
input (a function parameter, a request object, etc.). That refinement
is exactly what Phase 6's taint tracker adds on top of this rule later
to cut false positives further (e.g. a query built from a hardcoded
constant + a config value is technically "dynamic" but not exploitable).

Severity: Critical -- justified because a successful SQL injection can
lead to full database compromise (read/write/delete any data, and
depending on DB permissions, sometimes command execution on the DB
server itself). This matches OWASP/CWE-89's standard classification.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

# Method names commonly used to execute a SQL query across popular
# Python DB libraries (sqlite3, psycopg2, MySQLdb/PyMySQL, Django ORM's
# .raw(), SQLAlchemy's .execute()/.query()).
_SQL_SINK_METHODS = {"execute", "executemany", "executescript", "raw", "query"}


def _looks_stringy(node: ast.expr) -> bool:
    """True if `node` is a string literal or itself a dynamically-built
    string expression -- used to decide whether a BinOp's operand is
    plausibly part of building a SQL string (vs. e.g. plain arithmetic
    like `x + 1`, which visit_BinOp should NOT flag)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    return isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call))


def _is_dynamic_string(node: ast.expr) -> bool:
    """True if `node` builds a string at runtime via f-string,
    concatenation, %-formatting, or .format() -- the four common ways
    a SQL query gets assembled unsafely instead of parameterized."""
    if isinstance(node, ast.JoinedStr):
        # An f-string, e.g. f"SELECT * FROM users WHERE id = {user_id}"
        return True

    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod):
            # Old-style %-formatting: "SELECT ... WHERE id = %s" % user_id
            return True
        if isinstance(node.op, ast.Add):
            # String concatenation: "SELECT ... " + user_id
            return _looks_stringy(node.left) or _looks_stringy(node.right)

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            # "SELECT ... WHERE id = {}".format(user_id)
            return True

    return False


class SqlInjectionRule(Rule):
    rule_id = "sql_injection"
    cwe_id = "CWE-89"
    default_severity = Severity.CRITICAL
    description = "SQL query built via string concatenation/f-string/%/`.format()` instead of parameterized query."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        for node in ast.walk(parsed_file.tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _SQL_SINK_METHODS:
                continue
            if not node.args:
                continue

            query_arg = node.args[0]
            if _is_dynamic_string(query_arg):
                confidence = (
                    Confidence.LOW if self._is_test_file(parsed_file) else Confidence.MEDIUM
                )
                severity = Severity.LOW if self._is_test_file(parsed_file) else self.default_severity
                findings.append(
                    self._make_finding(
                        parsed_file=parsed_file,
                        line=node.lineno,
                        message=(
                            f"SQL query passed to '.{node.func.attr}()' is built "
                            f"dynamically (f-string/concatenation/%/`.format()`) "
                            f"instead of using parameterized placeholders."
                        ),
                        fix_suggestion=(
                            "Use a parameterized query instead, e.g. "
                            "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,)) "
                            "so the database driver escapes the value safely, rather than "
                            "building the query string yourself."
                        ),
                        severity=severity,
                        confidence=confidence,
                    )
                )

        return findings