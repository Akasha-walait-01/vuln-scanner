"""
pdf_reporter.py
-----------------
Optional (per the brief: "Optional agar PDF bhi chahiye") -- converts
the same rendered HTML report into a PDF, using weasyprint.

Design decision: this does NOT reimplement the report layout in a
separate PDF-drawing library (e.g. reportlab). It reuses the exact same
Jinja2-rendered HTML that html_reporter.py produces and converts THAT
to PDF -- one source of truth for the report's content/structure, so
the two output formats can never drift out of sync with each other.

weasyprint is an optional dependency (not in the base requirements.txt)
since the brief marks PDF export as optional, and weasyprint has extra
system-level dependencies (Pango/Cairo) beyond a plain `pip install` on
some platforms. If it isn't installed, this module raises a clear,
actionable error instead of a confusing import traceback.
"""

from __future__ import annotations

from pathlib import Path

from scanner.reporter.html_reporter import generate_html_report


def generate_pdf_report(*args, output_path: str, **kwargs) -> Path:
    """Same arguments as generate_html_report(), except `output_path`
    should end in .pdf. Internally renders the HTML report to a temp
    location, then converts it to PDF with weasyprint.

    Raises:
        ImportError: if weasyprint isn't installed, with instructions.
    """
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise ImportError(
            "PDF export requires the optional 'weasyprint' package. "
            "Install it with: pip install weasyprint"
        ) from exc

    pdf_path = Path(output_path)
    html_path = pdf_path.with_suffix(".html")

    generate_html_report(*args, output_path=str(html_path), **kwargs)

    HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    return pdf_path