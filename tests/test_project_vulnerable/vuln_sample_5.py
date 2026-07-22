"""
vuln_sample_5.py -- Intentional vulnerability: Weak Cryptography (CWE-327)

Deliberately vulnerable: user passwords are hashed with plain MD5
before storage -- MD5 is cryptographically broken and unsuitable for
password storage (no salt, fast to brute-force).
Expected to be caught by: scanner/rules/weak_crypto.py
"""

import hashlib


def hash_password_for_storage(password):
    return hashlib.md5(password.encode()).hexdigest()