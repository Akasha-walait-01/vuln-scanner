"""
eval_exec_misuse.py
----------------------
Rule 8/8 -- Insecure Use of eval()/exec() (CWE-95, Severity: Critical)

Detection rule: any call to eval(), exec(), or compile() -- but with
severity/confidence GRADED by whether the argument is a hardcoded
string literal or something built/received at runtime:

- Argument is a plain string literal (e.g. `eval("1 + 1")`): still
  flagged (calling eval/exec at all is a code smell worth a second
  look, and matches how real SAST tools like Bandit treat it -- B307),
  but at LOW severity/confidence, since a fixed literal can't be
  influenced by an attacker.

- Argument is anything else -- a variable, a function call, string
  concatenation, an f-string, an attribute access (e.g. `eval(expr)`,
  `exec(user_code)`, `eval(f"{x} + {y}")`): flagged at CRITICAL
  severity/HIGH confidence. There is essentially no legitimate reason
  for application code to eval/exec a dynamically-assembled string, and
  if ANY part of that string can be influenced by user input, this is
  arbitrary code execution.

Why NOT require confirmed taint (a user-input source) before flagging
the dynamic case: unlike missing_input_validation.py and
path_traversal.py, eval/exec of a non-literal string is dangerous
regardless of where the string ultimately came from -- eval'ing
dynamically-built code is inherently fragile and risky application
design, not just an input-validation gap. So this rule flags the
PATTERN itself at high confidence, without needing to first prove a
request/input() source feeds it (though when one is present, as in the
classic `eval(input(...))` case, that's exactly the case this rule is
built to catch).

Why NOT flag ast.literal_eval(): it's the SAFE alternative -- it only
parses Python literals (numbers, strings, lists, dicts, etc.), never
executes arbitrary code, and is the correct recommendation this rule
points people toward.

Severity: Critical (for the dynamic case) -- justified because
successful exploitation is immediate arbitrary code execution in the
same process, identical in severity to insecure deserialization and
command injection. This matches CWE-95's typical classification.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

_EVAL_EXEC_FUNCS = {"eval", "exec", "compile"}


class EvalExecMisuseRule(Rule):
    rule_id = "eval_exec_misuse"
    cwe_id = "CWE-95"
    default_severity = Severity.CRITICAL
    description = "eval()/exec()/compile() called on a dynamically-built string instead of a fixed literal."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id not in _EVAL_EXEC_FUNCS:
                continue
            if not node.args:
                continue

            func_name = node.func.id
            argument = node.args[0]
            is_hardcoded_literal = isinstance(argument, ast.Constant) and isinstance(argument.value, str)

            if is_test:
                severity = Severity.LOW
                confidence = Confidence.LOW
            elif is_hardcoded_literal:
                severity = Severity.LOW
                confidence = Confidence.LOW
            else:
                severity = self.default_severity
                confidence = Confidence.HIGH

            if is_hardcoded_literal:
                message = f"'{func_name}()' is called -- even on a fixed literal, this is generally discouraged."
                fix_suggestion = (
                    "If this string is truly fixed, consider whether eval/exec is needed at all "
                    "(most fixed logic can be written directly in Python). If you need to parse a "
                    "literal value, use ast.literal_eval() instead, which never executes code."
                )
            else:
                message = (
                    f"'{func_name}()' is called on a dynamically-built string, not a fixed literal -- "
                    f"if any part of it can be influenced by user input, this is arbitrary code execution."
                )
                fix_suggestion = (
                    "Avoid eval()/exec() on dynamic content entirely. For parsing simple literal "
                    "data (numbers, lists, dicts), use ast.literal_eval() instead, which never "
                    "executes arbitrary code. For anything more complex, replace the eval'd logic "
                    "with explicit code paths (e.g. a dictionary dispatch instead of eval'ing a "
                    "function name)."
                )

            findings.append(
                self._make_finding(
                    parsed_file=parsed_file,
                    line=node.lineno,
                    message=message,
                    fix_suggestion=fix_suggestion,
                    severity=severity,
                    confidence=confidence,
                )
            )

        return findings