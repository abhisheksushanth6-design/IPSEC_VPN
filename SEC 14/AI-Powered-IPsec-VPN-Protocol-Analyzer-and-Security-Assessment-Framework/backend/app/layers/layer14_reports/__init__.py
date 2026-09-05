"""Layer 14 — Report Generation (PDF) package.

Status: OPERATIONAL.

Provides professional, multi-page cybersecurity assessment reports
consolidating outputs from all analytical layers 01-13.
"""

from app.layers.layer14_reports.schemas import (
    ReportGenerateRequest,
    ReportMetadataDTO,
    SecurityAssessmentReportData,
)
from app.layers.layer14_reports.service import ReportService, report_service

LAYER_NUMBER = 14
LAYER_NAME = "Report Generation (PDF)"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "ReportGenerateRequest",
    "ReportMetadataDTO",
    "SecurityAssessmentReportData",
    "ReportService",
    "report_service",
]
