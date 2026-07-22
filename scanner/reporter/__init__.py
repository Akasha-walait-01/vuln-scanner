from .html_reporter import generate_report, build_report_context, compute_risk_score

__all__ = ["generate_report", "build_report_context", "compute_risk_score"]

# pdf_reporter is intentionally NOT imported here - it depends on weasyprint,
# which is optional. Import it directly where needed:
#   from scanner.reporter.pdf_reporter import generate_pdf_report