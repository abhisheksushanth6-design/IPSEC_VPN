"""Pydantic schemas for AI Traffic Classification inside ESP."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TrafficClassificationSchema(BaseModel):
    id: str
    capture_id: str
    session_id: Optional[str] = None
    flow_id: str
    traffic_type: str = Field(..., description="VOIP, WHATSAPP, EMAIL, VIDEO_STREAMING, GENERIC")
    confidence: float = Field(..., ge=0.0, le=1.0)
    probabilities: Dict[str, float] = Field(default_factory=dict)
    features: Dict[str, Any] = Field(default_factory=dict)
    explainability: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str

    class Config:
        from_attributes = True


class TrafficClassificationSummarySchema(BaseModel):
    capture_id: str
    total_classified: int
    distribution: Dict[str, int]
    voip_count: int
    whatsapp_count: int = 0
    email_count: int
    video_streaming_count: int
    web_browsing_count: int = 0
    icmp_count: int = 0
    other_count: int = 0
    generic_count: int = 0
    average_confidence: float


class TrafficClassificationPageSchema(BaseModel):
    items: List[TrafficClassificationSchema]
    total: int
    page: int
    page_size: int
