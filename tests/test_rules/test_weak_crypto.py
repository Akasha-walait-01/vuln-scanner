"""
test_weak_crypto.py
----------------------
Unit tests for scanner/rules/weak_crypto.py (CWE-327).
"""

import unittest

from scanner.rules.weak_crypto import WeakCryptoRule
from scanner.rules.finding import Severity
from tests.test_rules.helpers import parse_source


class TestWeakCryptoRule(unittest.TestCase):
    def setUp(self):
        self.rule = WeakCryptoRule()

    def test_md5_is_flagged(self):
        pf = parse_source(
            """
import hashlib
def f(data):
    return hashlib.md5(data).hexdigest()
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-327")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sha1_is_flagged(self):
        pf = parse_source(
            """
import hashlib
def f(data):
    return hashlib.sha1(data).hexdigest()
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_des_cipher_is_flagged(self):
        pf = parse_source(
            """
from Crypto.Cipher import DES
def f(key):
    return DES.new(key)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_arc4_cipher_is_flagged(self):
        pf = parse_source(
            """
from Crypto.Cipher import ARC4
def f(key):
    return ARC4.new(key)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_ecb_mode_is_flagged(self):
        pf = parse_source(
            """
from Crypto.Cipher import AES
def f(key):
    return AES.new(key, AES.MODE_ECB)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_random_for_security_sensitive_name_is_flagged(self):
        pf = parse_source(
            """
import random
def f():
    session_token = random.random()
    return session_token
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)

    def test_sha256_not_flagged(self):
        pf = parse_source(
            """
import hashlib
def f(data):
    return hashlib.sha256(data).hexdigest()
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_secrets_module_not_flagged(self):
        pf = parse_source(
            """
import secrets
def f():
    token = secrets.token_urlsafe()
    return token
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_random_for_non_security_name_not_flagged(self):
        pf = parse_source(
            """
import random
def f():
    dice_roll = random.randint(1, 6)
    return dice_roll
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_aes_gcm_mode_not_flagged(self):
        pf = parse_source(
            """
from Crypto.Cipher import AES
def f(key, nonce):
    return AES.new(key, AES.MODE_GCM, nonce=nonce)
"""
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 0)

    def test_finding_in_test_file_gets_reduced_severity(self):
        pf = parse_source(
            """
import hashlib
def f(data):
    return hashlib.md5(data).hexdigest()
""",
            filename="tests/test_something.py",
        )
        findings = self.rule.check(pf)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()