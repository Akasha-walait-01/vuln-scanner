"""
pdf_reporter.py

Optional PDF output. Reuses html_reporter's Jinja2 rendering and converts the
resulting HTML to PDF with WeasyPrint (pure-Python, no external binary
dependency like wkhtmltopdf, so it stays consistent with the "runs entirely
offline/locally" non-functional requirement).

If weasyprint isn't installed, this module raises a clear ImportError with
install instructions rather than failing silently or crashing on import for
callers that only want the HTML reporter.
"""

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .html_reporter import build_report_context, TEMPLATE_DIR, TEMPLATE_NAME


def generate_pdf_report(findings, project_name, files_scanned, output_path,
                         scan_timestamp=None):
    """
    Render findings straight to a PDF file at output_path.

    Same parameters as html_reporter.generate_report(). Returns output_path.
    """
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise ImportError(
            "PDF export requires weasyprint. Install it with:\n"
            "    pip install weasyprint\n"
            "(WeasyPrint also needs some system libraries - see "
            "https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation "
            "if the pip install alone doesn't work on your platform)."
        ) from exc

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template(TEMPLATE_NAME)

    context = build_report_context(findings, project_name, files_scanned, scan_timestamp)
    html_string = template.render(**context)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    HTML(string=html_string).write_pdf(output_path)

    return output_path