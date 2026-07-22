"""
vuln_sample_8.py -- Intentional vulnerability: Missing Input Validation (CWE-20)

Deliberately vulnerable: a user-supplied report name is used directly
to open a file, with zero type/length/format checking anywhere in the
function.
Expected to be caught by: scanner/rules/missing_input_validation.py
"""


def open_report(request):
    report_name = request.form.get("report_name")
    return open(report_name)