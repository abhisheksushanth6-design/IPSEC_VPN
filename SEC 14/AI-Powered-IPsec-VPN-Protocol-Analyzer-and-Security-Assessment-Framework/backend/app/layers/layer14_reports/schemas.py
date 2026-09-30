"""Pydantic schemas for Layer 14 — Report Generation (PDF).

Defines the contracts for report generation requests, report metadata,
and the normalized assessment data model passed to the PDF renderer.
"""

from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field

ReportType = Literal["FULL", "SESSION", "VULNERABILITY", "EXECUTIVE", "TECHNICAL"]
ReportStatus = Literal["PENDING", "COMPLETED", "FAILED"]


class ReportGenerateRequest(BaseModel):
    """Payload to trigger report generation."""

    model_config = ConfigDict(extra="forbid")

    report_type: ReportType = Field(
        "FULL",
        description="Type of assessment report to produce (FULL, SESSION, VULNERABILITY, EXECUTIVE, TECHNICAL).",
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional session ID if scoping the report to a single IPsec session.",
    )
    title: Optional[str] = Field(
        None,
        description="Custom title for the generated security report.",
    )


class ReportMetadataDTO(BaseModel):
    """Summary metadata representing a persisted report."""

    model_config = ConfigDict(extra="forbid")

    id: str
    report_type: str
    title: str
    filename: str
    file_size_bytes: int
    page_count: int
    status: str
    error_message: Optional[str] = None
    generated_at: str
    download_url: str


class SecurityAssessmentReportData(BaseModel):
    """Normalized assessment data compiled from layers 01-13 for PDF rendering."""

    model_config = ConfigDict(extra="forbid")

    metadata: dict[str, Any]
    environment: dict[str, Any]
    capture: dict[str, Any]
    protocol: dict[str, Any]
    sa_lifecycle: dict[str, Any]
    session_analysis: Optional[dict[str, Any]] = None
    features: dict[str, Any]
    baseline: dict[str, Any]
    drift: dict[str, Any]
    ml_anomaly: dict[str, Any]
    vulnerabilities: dict[str, Any]
    risk: dict[str, Any]
    traffic_classification: Optional[dict[str, Any]] = None
    metadata_exposure: Optional[dict[str, Any]] = None
    threat_matrix: Optional[dict[str, Any]] = None
    sih_security_assessment: Optional[dict[str, Any]] = None
    data_provenance: Optional[dict[str, str]] = None
    recommendations: list[dict[str, Any]]
    appendix: dict[str, Any]
