"""
vuln_sample_6.py -- Intentional vulnerability: eval()/exec() Misuse (CWE-95)

Deliberately vulnerable: a user-supplied math expression is passed
straight to eval() -- allows arbitrary code execution (e.g. a user
could submit "__import__('os').system('rm -rf /')" instead of a
harmless expression).
Expected to be caught by: scanner/rules/eval_exec_misuse.py
"""


def calculate(expression):
    result = eval(expression)
    return result