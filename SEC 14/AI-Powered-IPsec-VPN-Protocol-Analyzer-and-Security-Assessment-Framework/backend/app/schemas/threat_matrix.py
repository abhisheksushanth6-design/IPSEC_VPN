"""Pydantic schemas for Standalone Threat Matrix."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatMatrixItemSchema(BaseModel):
    id: str
    capture_id: str
    session_id: Optional[str] = None
    matrix_id: str = Field(..., description="e.g. TM-IPSEC-001")
    name: str
    category: str
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    nist_control: Optional[str] = None
    rfc_reference: Optional[str] = None
    status: str = Field(..., description="DETECTED, VULNERABLE, MITIGATED, NOT_APPLICABLE")
    evidence: List[str] = Field(default_factory=list)
    remediation: str
    created_at: str

    class Config:
        from_attributes = True


class ThreatMatrixSummarySchema(BaseModel):
    capture_id: str
    total_threats: int
    detected_count: int
    vulnerable_count: int
    mitigated_count: int
    not_applicable_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    compliance_score: float = Field(..., ge=0.0, le=100.0)


class ThreatMatrixPageSchema(BaseModel):
    items: List[ThreatMatrixItemSchema]
    total: int
    page: int
    page_size: int
