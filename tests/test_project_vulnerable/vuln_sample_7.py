"""
vuln_sample_7.py -- Intentional vulnerability: Path Traversal (CWE-22)

Deliberately vulnerable: a filename from the request is joined onto a
base upload directory and opened, with no '..' check or path
canonicalization -- an attacker can supply "../../etc/passwd" to
escape the uploads directory.
Expected to be caught by: scanner/rules/path_traversal.py
"""

import os


def download_uploaded_file(request):
    filename = request.args.get("filename")
    full_path = os.path.join("/var/uploads", filename)
    return open(full_path, "rb").read()