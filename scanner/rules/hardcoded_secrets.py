"""
hardcoded_secrets.py
----------------------
Rule 3/8 -- Hardcoded Secrets/Credentials (CWE-798, Severity: High)

Detection rule: a plain string literal assigned to a variable (or dict
key) whose name looks like a secret -- password, secret, token,
api_key, private_key, credential, etc. -- rather than being loaded from
an environment variable, a secrets manager, or a config file at
runtime.

Three shapes are covered:
1. Simple assignment:  `password = "hunter2"`
2. Dict literal key:    `config = {"api_key": "sk_live_abc123"}`
3. Function default:    `def connect(token="hardcoded_default_token"):`

Why match on VARIABLE NAME, not value content: there's no reliable way
to look at a string and know "this looks like a real secret" (a real
API key, a random password, and a placeholder string all look the same
structurally -- just characters). The name the developer gave the
variable is the actual signal: nobody names a variable `api_key` unless
it's meant to hold one.

False-positive reduction built in:
- Only flags when the value is a non-empty STRING LITERAL. This means
  `password = get_password()`, `password = os.environ["DB_PASSWORD"]`,
  and `password = None` are all correctly left alone -- those are the
  SAFE ways to obtain a secret at runtime, not the vulnerable pattern.
- Variable names containing "hash" (e.g. `password_hash`) are excluded
  -- a hash is a one-way derived value, not the secret itself; storing
  a hash is normal and expected, not a hardcoded-secret issue.
- Findings inside test files get reduced severity (per base_rule's
  shared `_is_test_file` helper) -- a fake password in a unit test
  fixture is far less concerning than one in production code, though
  it's still worth a low-severity note in case it's not actually fake.

Severity: High (not Critical) -- justified because a hardcoded secret
is a serious exposure (especially if the code is later open-sourced or
the repo is breached), but unlike SQL/command injection it doesn't
grant IMMEDIATE remote code execution by itself -- the secret still
has to be found and used. This matches CWE-798's typical classification
just below the Critical-tier injection/RCE vulnerabilities.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

# Substrings (checked against the lowercased variable/key name) that
# indicate "this is meant to hold a secret."
_SECRET_NAME_MARKERS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "auth_token",
    "credential",
    "client_secret",
    "secret_key",
)

# Excluded even if a marker matches -- these hold a DERIVED value, not
# the plaintext secret itself, so hardcoding them is normal/expected.
_SAFE_NAME_MARKERS = ("hash", "hashed")


def _looks_like_secret_name(name: str) -> bool:
    lowered = name.lower()
    if any(safe in lowered for safe in _SAFE_NAME_MARKERS):
        return False
    return any(marker in lowered for marker in _SECRET_NAME_MARKERS)


def _is_nonempty_string_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value != ""


class HardcodedSecretsRule(Rule):
    rule_id = "hardcoded_secrets"
    cwe_id = "CWE-798"
    default_severity = Severity.HIGH
    description = "Literal secret (password/token/api_key/etc.) assigned directly in source code."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            # Shape 1: name = "literal"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _looks_like_secret_name(target.id):
                        if _is_nonempty_string_literal(node.value):
                            findings.append(self._flag(parsed_file, node.lineno, target.id, is_test))

            elif isinstance(node, ast.AnnAssign):
                if (
                    isinstance(node.target, ast.Name)
                    and node.value is not None
                    and _looks_like_secret_name(node.target.id)
                    and _is_nonempty_string_literal(node.value)
                ):
                    findings.append(self._flag(parsed_file, node.lineno, node.target.id, is_test))

            # Shape 2: {"key": "literal"} dict entries
            elif isinstance(node, ast.Dict):
                for key_node, value_node in zip(node.keys, node.values):
                    if (
                        isinstance(key_node, ast.Constant)
                        and isinstance(key_node.value, str)
                        and _looks_like_secret_name(key_node.value)
                        and _is_nonempty_string_literal(value_node)
                    ):
                        findings.append(
                            self._flag(parsed_file, value_node.lineno, key_node.value, is_test)
                        )

            # Shape 3: def f(token="hardcoded_default"): -- a hardcoded
            # default value for a secret-shaped parameter.
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                # ast pairs `defaults` with the LAST N positional args --
                # zip from the right to line them up correctly.
                positional = args.posonlyargs + args.args
                for arg, default in zip(reversed(positional), reversed(args.defaults)):
                    if _looks_like_secret_name(arg.arg) and _is_nonempty_string_literal(default):
                        findings.append(self._flag(parsed_file, default.lineno, arg.arg, is_test))
                for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                    if (
                        default is not None
                        and _looks_like_secret_name(arg.arg)
                        and _is_nonempty_string_literal(default)
                    ):
                        findings.append(self._flag(parsed_file, default.lineno, arg.arg, is_test))

        return findings

    def _flag(self, parsed_file: ParsedFile, line: int, name: str, is_test: bool) -> VulnerabilityFinding:
        severity = Severity.LOW if is_test else self.default_severity
        confidence = Confidence.LOW if is_test else Confidence.MEDIUM
        return self._make_finding(
            parsed_file=parsed_file,
            line=line,
            message=f"'{name}' is assigned a hardcoded string literal, which looks like a secret.",
            fix_suggestion=(
                "Load this value at runtime instead of hardcoding it -- e.g. "
                "os.environ['API_KEY'], a .env file loaded via a secrets library, "
                "or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.). "
                "Never commit real credentials to source control."
            ),
            severity=severity,
            confidence=confidence,
        )