"""
vuln_sample_1.py -- Intentional vulnerability: SQL Injection (CWE-89)

Deliberately vulnerable: the query is built with an f-string directly
from a function parameter, instead of a parameterized query.
Expected to be caught by: scanner/rules/sql_injection.py
"""


def get_user_by_id(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()