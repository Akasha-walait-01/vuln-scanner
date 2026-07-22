"""
vuln_sample_2.py -- Intentional vulnerability: Command Injection (CWE-78)

Deliberately vulnerable: `cmd` is a bare function parameter passed
straight into os.system() -- no dynamic string-building involved, so
this specifically tests the Phase 6 DATA-FLOW tracer, not just the
Phase 4 structural pattern rule.
Expected to be caught by: scanner/taint/taint_tracker.py
(CommandInjectionTaintTracker)
"""

import os


def run_diagnostic(cmd):
    os.system(cmd)