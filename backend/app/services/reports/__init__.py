"""Phase 4 Report Generation Services.

This package provides report generation in multiple formats:
- JSON: Machine-readable forensic report
- HTML: Human-readable web report
- PDF: Printable forensic report (optional)

IMPORTANT: Report generation is independent of core forensics.
If PDF generation fails, JSON and HTML remain available.
"""
from app.services.reports.report_generator import ReportGenerator, ReportFormat

__all__ = [
    "ReportGenerator",
    "ReportFormat",
]
