"""Pydantic schemas for the IPsec sessions API."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.packets import PacketSummarySchema

SessionState = Literal["DISCOVERED", "NEGOTIATING", "ESTABLISHED", "ACTIVE", "IDLE", "TERMINATED", "UNKNOWN"]
SessionDirection = Literal["OUTBOUND", "INBOUND", "BIDIRECTIONAL", "UNKNOWN"]
Correlation = Literal["DIRECT", "CORRELATED", "PARTIAL", "UNKNOWN"]
EngineState = Literal["NOT INITIALIZED", "READY", "ANALYZING", "AVAILABLE", "ERROR"]


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TimelineEventSchema(_Model):
    timestamp: Optional[str]
    packet_number: int
    label: str
    detail: str


class IKEInfoSchema(_Model):
    version: Optional[str]
    initiator_spis: list[str]
    responder_spis: list[str]
    exchange_types: list[str]
    message_ids: list[int]
    payload_types: list[str]
    packet_count: int
    nat_traversal: bool


class SPIInfoSchema(_Model):
    spi: str
    direction: str
    packet_count: int
    sequence_min: int
    sequence_max: int
    nat_traversal: bool


class DataPlaneInfoSchema(_Model):
    spis: list[SPIInfoSchema]
    packet_count: int


class ActivityPointSchema(_Model):
    timestamp: str
    packets: int


class SessionSummarySchema(_Model):
    id: str
    ordinal: int
    source: str
    destination: str
    direction: SessionDirection
    state: SessionState
    correlation: Correlation
    start_time: Optional[str]
    end_time: Optional[str]
    duration_seconds: Optional[float]
    packet_count: int
    byte_count: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    ike_version: Optional[str]
    nat_traversal: bool


class SessionDetailSchema(SessionSummarySchema):
    ike: Optional[IKEInfoSchema]
    esp: Optional[DataPlaneInfoSchema]
    ah: Optional[DataPlaneInfoSchema]
    timeline: list[TimelineEventSchema]
    activity: list[ActivityPointSchema]
    evidence: list[str]
    packets: list[PacketSummarySchema]
    packets_total: int
    packets_available: bool


class SessionStatisticsSchema(BaseModel):
    total: int
    active: int
    established: int
    negotiating: int
    terminated: int
    discovered: int
    unknown: int


class SessionStatusSchema(BaseModel):
    state: EngineState
    packets_available: bool
    capture_id: Optional[str]
    capture_filename: Optional[str]
    discovered_at: Optional[str]
    statistics: Optional[SessionStatisticsSchema]
    inactivity_gap_seconds: float
    last_error: Optional[str] = None


class SessionPageSchema(BaseModel):
    items: list[SessionSummarySchema]
    page: int
    page_size: int
    total: int
    total_pages: int


class PacketSessionSchema(BaseModel):
    packet_id: str
    session_id: Optional[str]
    role: Optional[str]
