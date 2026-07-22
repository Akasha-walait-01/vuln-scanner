"""
vuln_sample_4.py -- Intentional vulnerability: Insecure Deserialization (CWE-502)

Deliberately vulnerable: pickle.loads() is called directly on data
received from a network socket -- classic RCE-via-deserialization setup.
Expected to be caught by: scanner/rules/insecure_deserialization.py
"""

import pickle


def load_session_from_network(connection):
    raw_data = connection.recv(4096)
    session = pickle.loads(raw_data)
    return session