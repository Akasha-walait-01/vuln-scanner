"""
command_injection.py
----------------------
Rule 2/8 -- Command Injection (CWE-78, Severity: Critical)

Detection rule covers TWO distinct dangerous patterns in Python:

1. `os.system(cmd)` / `os.popen(cmd)` where `cmd` is built dynamically
   at runtime (f-string / concatenation / % / .format()) -- these two
   functions ALWAYS run their argument through the system shell, so
   any dynamically-assembled command is a direct injection risk.

2. `subprocess.{call,run,Popen,check_call,check_output}(cmd, shell=True)`
   -- `shell=True` is flagged on its own (regardless of whether `cmd`
   looks dynamic), because `shell=True` is itself the dangerous
   configuration: it tells subprocess to hand the string to `/bin/sh`
   for interpretation, so shell metacharacters in `cmd` (`;`, `|`,
   `&&`, backticks, etc.) become executable -- this matches how
   real-world SAST tools like Bandit treat shell=True (rule B602/B603).
   If `cmd` is ALSO dynamically built, confidence is raised further,
   since that's the complete, classic vulnerable pattern.

Why NOT flag every subprocess call: `subprocess.run(["ls", "-la"])`
(a LIST of arguments, no shell=True) is the SAFE, recommended way to
run external commands in Python -- the OS executes the program
directly, no shell parsing happens, so there's no injection surface at
all. Flagging that would be pure noise.

Severity: Critical -- a successful command injection gives an attacker
arbitrary command execution with the same privileges as the running
Python process, which is typically a full compromise of the host.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.ast_utils import get_keyword_bool, is_attribute_call, is_dynamic_string
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

_OS_SHELL_FUNCS = {"system", "popen"}
_SUBPROCESS_FUNCS = {"call", "run", "Popen", "check_call", "check_output"}


class CommandInjectionRule(Rule):
    rule_id = "command_injection"
    cwe_id = "CWE-78"
    default_severity = Severity.CRITICAL
    description = "Unsanitized/dynamic input reaches os.system(), os.popen(), or subprocess.*(shell=True)."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            if not isinstance(node, ast.Call):
                continue

            # --- Pattern 1: os.system() / os.popen() with a dynamic command ---
            if is_attribute_call(node, "os", _OS_SHELL_FUNCS) and node.args:
                if is_dynamic_string(node.args[0]):
                    findings.append(self._flag(parsed_file, node, is_test, dynamic_cmd=True))
                continue

            # --- Pattern 2: subprocess.*(..., shell=True) ---
            if is_attribute_call(node, "subprocess", _SUBPROCESS_FUNCS):
                if get_keyword_bool(node, "shell"):
                    dynamic_cmd = bool(node.args) and is_dynamic_string(node.args[0])
                    findings.append(self._flag(parsed_file, node, is_test, dynamic_cmd=dynamic_cmd))

        return findings

    def _flag(
        self,
        parsed_file: ParsedFile,
        node: ast.Call,
        is_test: bool,
        dynamic_cmd: bool,
    ) -> VulnerabilityFinding:
        func_repr = ast.unparse(node.func) if hasattr(ast, "unparse") else node.func.attr

        if is_test:
            severity = Severity.LOW
            confidence = Confidence.LOW
        elif dynamic_cmd:
            severity = self.default_severity
            confidence = Confidence.HIGH
        else:
            # shell=True alone, command not obviously dynamic here -- still
            # dangerous configuration, but we can't yet confirm the command
            # is attacker-influenced without taint tracking (Phase 6).
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM

        return self._make_finding(
            parsed_file=parsed_file,
            line=node.lineno,
            message=(
                f"'{func_repr}(...)' executes a command through the system shell"
                + (" using a dynamically-built command string." if dynamic_cmd else " (shell=True).")
            ),
            fix_suggestion=(
                "Avoid the shell entirely: pass the command as a list of "
                "arguments to subprocess.run() (e.g. subprocess.run([\"ls\", \"-la\", path])) "
                "without shell=True, so the OS executes the program directly and "
                "shell metacharacters in any argument can't be interpreted."
            ),
            severity=severity,
            confidence=confidence,
        )