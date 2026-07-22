# test_project_vulnerable

Deliberately vulnerable sample project used for Phase 8 validation
(the brief's False Negative check: "Deliberately introduce at least 5
known-vulnerable code snippets... confirm your scanner catches them").

Each file contains exactly ONE intentionally-planted vulnerability from
a different category, with a docstring explaining what it is and which
rule is expected to catch it.

| File | Vulnerability | CWE | Rule expected to catch it |
|------|----------------|-----|----------------------------|
| `vuln_sample_1.py` | SQL Injection | CWE-89 | `sql_injection.py` |
| `vuln_sample_2.py` | Command Injection (via data-flow, bare parameter) | CWE-78 | `taint_tracker.py` |
| `vuln_sample_3.py` | Hardcoded Secrets | CWE-798 | `hardcoded_secrets.py` |
| `vuln_sample_4.py` | Insecure Deserialization | CWE-502 | `insecure_deserialization.py` |
| `vuln_sample_5.py` | Weak Cryptography | CWE-327 | `weak_crypto.py` |
| `vuln_sample_6.py` | eval()/exec() Misuse | CWE-95 | `eval_exec_misuse.py` |
| `vuln_sample_7.py` | Path Traversal | CWE-22 | `path_traversal.py` |
| `vuln_sample_8.py` | Missing Input Validation | CWE-20 | `missing_input_validation.py` |

8 vulnerabilities across all 8 rule categories (brief only requires
5+; all 8 are included here for complete coverage and to double as
demo material for the Phase 9 video).

Results of running the scanner against this project are documented in
`validation/fp_fn_analysis.md`.