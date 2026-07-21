"""
weak_crypto.py
----------------
Rule 5/8 -- Weak/Broken Cryptography (CWE-327, Severity: High)

Detection rule covers four distinct weak-crypto patterns:

1. Weak hash algorithms: `hashlib.md5(...)` / `hashlib.sha1(...)`.
   Both are cryptographically broken for security purposes (collision
   attacks are practical against both) -- fine for a non-security
   checksum, but flagged here because this scanner can't tell WHY a
   hash was computed, and the safe default is to flag every use.

2. Weak/broken ciphers: `DES.new(...)`, `DES3.new(...)`, `ARC4.new(...)`
   (from pycryptodome/PyCryptodome's `Crypto.Cipher` module) -- DES has
   a 56-bit key, brute-forceable for decades now; RC4 has known
   statistical biases that break it in practice.

3. ECB cipher mode: any `*.new(key, MODE_ECB, ...)` call -- ECB
   encrypts identical plaintext blocks to identical ciphertext blocks,
   leaking structural information about the plaintext (the classic
   "ECB penguin" image example) regardless of which cipher is used.

4. Insecure randomness for security-sensitive values: `random.*()`
   (Python's Mersenne Twister -- statistically predictable, NOT
   cryptographically secure) assigned to a variable whose name looks
   like a token/password/key/secret. `secrets.*()` or `os.urandom()`
   are the correct choice for anything security-sensitive and are
   never flagged.

Why NOT flag hashlib.sha256/sha3/blake2, or `random` used for
non-security purposes (e.g. shuffling a game board): those are exactly
the SAFE, correct uses -- flagging them would be pure noise.

Severity: High -- justified because weak crypto is a serious exposure
(passwords crackable, encrypted data readable, tokens guessable), but
unlike SQL/command injection or insecure deserialization it doesn't
grant immediate code execution -- exploitation still requires
additional effort (e.g. actually running a collision/brute-force
attack). This matches CWE-327's typical classification.
"""

from __future__ import annotations

import ast
from typing import List

from scanner.parser.ast_parser import ParsedFile
from scanner.rules.ast_utils import is_attribute_call
from scanner.rules.base_rule import Rule
from scanner.rules.finding import Confidence, Severity, VulnerabilityFinding

_WEAK_HASH_FUNCS = {"md5", "sha1"}
_WEAK_CIPHER_MODULES = {"DES", "DES3", "ARC4", "RC4"}
_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "uniform", "getrandbits", "shuffle", "sample"}

# Reuse the same "looks like a secret name" idea from hardcoded_secrets.py --
# a random.* value assigned to one of these is a security-sensitive use.
_SECURITY_SENSITIVE_MARKERS = ("token", "password", "passwd", "secret", "key", "otp", "session_id", "csrf")


def _is_security_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _SECURITY_SENSITIVE_MARKERS)


def _has_ecb_mode_argument(node: ast.Call) -> bool:
    """True if any positional or keyword argument references something
    ending in MODE_ECB, e.g. AES.new(key, AES.MODE_ECB) or
    AES.new(key, mode=AES.MODE_ECB)."""
    all_args = list(node.args) + [kw.value for kw in node.keywords]
    for arg in all_args:
        if isinstance(arg, ast.Attribute) and arg.attr == "MODE_ECB":
            return True
    return False


class WeakCryptoRule(Rule):
    rule_id = "weak_crypto"
    cwe_id = "CWE-327"
    default_severity = Severity.HIGH
    description = "Weak/broken cryptographic function (MD5/SHA1/DES/RC4/ECB) or insecure randomness for a security-sensitive value."

    def check(self, parsed_file: ParsedFile) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not parsed_file.ok:
            return findings

        is_test = self._is_test_file(parsed_file)

        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Call):
                # --- Pattern 1: hashlib.md5() / hashlib.sha1() ---
                if is_attribute_call(node, "hashlib", _WEAK_HASH_FUNCS):
                    findings.append(
                        self._flag(
                            parsed_file,
                            node.lineno,
                            is_test,
                            message=f"'hashlib.{node.func.attr}()' is a cryptographically broken hash algorithm.",
                            fix_suggestion="Use hashlib.sha256() or hashlib.blake2b() instead. For passwords specifically, use a dedicated password-hashing function (e.g. bcrypt, scrypt, or argon2) rather than a general-purpose hash.",
                        )
                    )

                # --- Pattern 2: DES/DES3/ARC4/RC4 cipher construction ---
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "new"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in _WEAK_CIPHER_MODULES
                ):
                    cipher_name = node.func.value.id
                    findings.append(
                        self._flag(
                            parsed_file,
                            node.lineno,
                            is_test,
                            message=f"'{cipher_name}.new()' uses the {cipher_name} cipher, which is considered broken/weak by modern standards.",
                            fix_suggestion="Use AES (e.g. AES-256 in GCM mode) instead -- it's the current standard, fast, and has no known practical break.",
                        )
                    )

                # --- Pattern 3: ECB mode (any cipher) ---
                elif _has_ecb_mode_argument(node):
                    findings.append(
                        self._flag(
                            parsed_file,
                            node.lineno,
                            is_test,
                            message="Cipher is constructed with ECB mode, which leaks patterns in the plaintext (identical blocks encrypt to identical ciphertext).",
                            fix_suggestion="Use GCM or CBC mode with a random IV instead of ECB -- GCM is recommended since it also provides integrity/authentication.",
                        )
                    )

            # --- Pattern 4: random.*() assigned to a security-sensitive name ---
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and _is_security_sensitive_name(target.id)
                        and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Attribute)
                        and node.value.func.attr in _RANDOM_FUNCS
                        and isinstance(node.value.func.value, ast.Name)
                        and node.value.func.value.id == "random"
                    ):
                        findings.append(
                            self._flag(
                                parsed_file,
                                node.lineno,
                                is_test,
                                message=(
                                    f"'{target.id}' is generated with 'random.{node.value.func.attr}()', "
                                    f"which is NOT cryptographically secure, but is assigned to a "
                                    f"security-sensitive-looking variable."
                                ),
                                fix_suggestion=(
                                    "Use the `secrets` module instead (e.g. secrets.token_urlsafe(), "
                                    "secrets.token_hex()) or os.urandom() for anything security-sensitive "
                                    "-- the `random` module is predictable and unsuitable for tokens, "
                                    "passwords, or session IDs."
                                ),
                            )
                        )

        return findings

    def _flag(
        self,
        parsed_file: ParsedFile,
        line: int,
        is_test: bool,
        message: str,
        fix_suggestion: str,
    ) -> VulnerabilityFinding:
        severity = Severity.LOW if is_test else self.default_severity
        confidence = Confidence.LOW if is_test else Confidence.MEDIUM
        return self._make_finding(
            parsed_file=parsed_file,
            line=line,
            message=message,
            fix_suggestion=fix_suggestion,
            severity=severity,
            confidence=confidence,
        )