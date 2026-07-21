"""
insecure_deserialization.py
------------------------------
Rule 4/8 -- Insecure Deserialization (CWE-502, Severity: Critical)

Detection rule covers two distinct dangerous deserializers:

1. `pickle.load()` / `pickle.loads()` (and the `cPickle`/`dill`
   equivalents) -- ALWAYS flagged, unconditionally. Unlike the other
   rules in this file, there is no "safe" way to call pickle.loads() on
   data that isn't 100% trusted: Python's pickle format can embed
   arbitrary object-construction instructions, so deserializing a
   malicious pickle payload can execute arbitrary code during the
   deserialization itself -- there's no safe-mode flag to opt out of
   this. This matches how real SAST tools (Bandit's B301) treat it: the
   mere presence of pickle.load(s) on non-hardcoded input is the risk.

2. `yaml.load(data)` WITHOUT an explicit safe Loader -- PyYAML's
   default/full loader can also construct arbitrary Python objects from
   the YAML content. `yaml.safe_load()` and `yaml.load(data,
   Loader=yaml.SafeLoader)` are the safe forms and are NOT flagged.
   `yaml.unsafe_load()` is always flagged (the name says it outright).

Why NOT flag every pickle.dump()/yaml.dump(): serializing (writing) data
isn't the risk -- deserializing (reading/reconstructing objects from)
UNTRUSTED data is. dump()/dumps() are safe and excluded entirely.

Severity: Critical -- justified because successful exploitation is
typically Remote Code Execution (RCE) during the deserialization call
itself, before any application logic even runs -- one of the most
severe outcomes possible, matching CWE-502's standard classification.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

_PICKLE_MODULES = {"pickle", "cPickle", "dill"}
_PICKLE_FUNCS = {"load", "loads"}

_YAML_MODULE = "yaml"
_YAML_SAFE_LOADER_NAMES = {"SafeLoader", "CSafeLoader"}


def _is_module_call(node: ast.expr, modules: set, funcs: set) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in funcs
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in modules
    )


def _yaml_load_has_safe_loader(node: ast.Call) -> bool:
    """True if a yaml.load(...) call explicitly passes a safe Loader,
    e.g. yaml.load(data, Loader=yaml.SafeLoader)."""
    for kw in node.keywords:
        if kw.arg != "Loader":
            continue
        # Loader=yaml.SafeLoader looks like an Attribute access.
        if isinstance(kw.value, ast.Attribute) and kw.value.attr in _YAML_SAFE_LOADER_NAMES:
            return True
        # Loader=SafeLoader (imported directly via `from yaml import SafeLoader`).
        if isinstance(kw.value, ast.Name) and kw.value.id in _YAML_SAFE_LOADER_NAMES:
            return True
    return False


class InsecureDeserializationRule(Rule):
    rule_id = "insecure_deserialization"
    cwe_id = "CWE-502"
    default_severity = Severity.CRITICAL
    description = "Untrusted data passed to pickle.load(s)() or yaml.load() without a safe Loader."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            if not isinstance(node, ast.Call):
                continue

            # --- pickle.load() / pickle.loads() -- always unsafe ---
            if _is_module_call(node, _PICKLE_MODULES, _PICKLE_FUNCS):
                findings.append(
                    self._flag(
                        parsed_file,
                        node,
                        is_test,
                        message=(
                            f"'{node.func.value.id}.{node.func.attr}()' deserializes data using "
                            f"pickle, which can execute arbitrary code if the data is not fully trusted."
                        ),
                        fix_suggestion=(
                            "Avoid pickle for any data that could come from outside your own "
                            "process (files, network, user upload). Use a safe format instead, "
                            "e.g. json.loads() for plain data, or a schema-validated format."
                        ),
                    )
                )
                continue

            # --- yaml.load() without a safe Loader ---
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == _YAML_MODULE and node.func.attr == "unsafe_load":
                    findings.append(
                        self._flag(
                            parsed_file,
                            node,
                            is_test,
                            message="'yaml.unsafe_load()' can construct arbitrary Python objects from YAML content.",
                            fix_suggestion="Use yaml.safe_load() instead, which only builds plain Python data types.",
                        )
                    )
                elif node.func.value.id == _YAML_MODULE and node.func.attr == "load":
                    if not _yaml_load_has_safe_loader(node):
                        findings.append(
                            self._flag(
                                parsed_file,
                                node,
                                is_test,
                                message="'yaml.load()' is called without an explicit safe Loader.",
                                fix_suggestion=(
                                    "Use yaml.safe_load(data) instead of yaml.load(data), or pass "
                                    "Loader=yaml.SafeLoader explicitly if you need yaml.load()."
                                ),
                            )
                        )

        return findings

    def _flag(
        self,
        parsed_file: ParsedFile,
        node: ast.Call,
        is_test: bool,
        message: str,
        fix_suggestion: str,
    ) -> VulnerabilityFinding:
        severity = Severity.LOW if is_test else self.default_severity
        confidence = Confidence.LOW if is_test else Confidence.HIGH
        return self._make_finding(
            parsed_file=parsed_file,
            line=node.lineno,
            message=message,
            fix_suggestion=fix_suggestion,
            severity=severity,
            confidence=confidence,
        )