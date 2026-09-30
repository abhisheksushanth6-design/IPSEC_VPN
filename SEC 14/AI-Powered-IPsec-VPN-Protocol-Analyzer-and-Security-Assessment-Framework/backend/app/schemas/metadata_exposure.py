"""Pydantic schemas for Metadata Exposure Assessment."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MetadataExposureSchema(BaseModel):
    id: str
    capture_id: str
    session_id: Optional[str] = None
    overall_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    spi_leakage_score: float = Field(..., ge=0.0, le=100.0)
    sequence_leakage_score: float = Field(..., ge=0.0, le=100.0)
    packet_length_leakage_score: float = Field(..., ge=0.0, le=100.0)
    timing_leakage_score: float = Field(..., ge=0.0, le=100.0)
    topology_leakage_score: float = Field(..., ge=0.0, le=100.0)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    created_at: str

    class Config:
        from_attributes = True


class MetadataExposureSummarySchema(BaseModel):
    capture_id: str
    average_score: float
    highest_risk_level: str
    total_assessed: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    dominant_leakage_vector: str
