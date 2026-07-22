"""
vuln_sample_3.py -- Intentional vulnerability: Hardcoded Secrets (CWE-798)

Deliberately vulnerable: a real-looking API key and database password
are hardcoded as string literals.
Expected to be caught by: scanner/rules/hardcoded_secrets.py
"""

DATABASE_PASSWORD = "Sup3rSecretDBPass!23"
STRIPE_API_KEY = "example-fake-api-key-do-not-use-1234"

def connect_to_database():
    return f"connecting with password {DATABASE_PASSWORD}"