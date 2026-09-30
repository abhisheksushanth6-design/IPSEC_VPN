"""Pydantic schemas for the SA lifecycle API."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.packets import PacketSummarySchema

SAType = Literal["IKE", "CHILD", "UNKNOWN"]
SAState = Literal["UNKNOWN", "DETECTED", "NEGOTIATING", "ESTABLISHED", "ACTIVE", "REKEYING", "EXPIRED", "TERMINATED", "FAILED"]
EngineState = Literal["NOT INITIALIZED", "READY", "ANALYZING", "ACTIVE", "ERROR"]


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SALifecycleEventSchema(_Model):
    timestamp: Optional[str]
    event_type: str
    previous_state: Optional[SAState]
    new_state: Optional[SAState]
    packet_number: Optional[int]
    message_id: Optional[int]
    spi: Optional[str]
    description: str


class SAStateHistorySchema(BaseModel):
    timestamp: Optional[str]
    state: SAState


class SAFailureSchema(BaseModel):
    exchange: str
    message_id: int
    notification: str
    timestamp: Optional[str]
    packet_number: int


class SASummarySchema(_Model):
    id: str
    type: SAType
    state: SAState
    protocol: str
    initiator: str
    responder: str
    ike_version: Optional[str]
    initiator_spi: Optional[str]
    responder_spi: Optional[str]
    spi: Optional[str]
    start_time: Optional[str]
    last_seen: Optional[str]
    duration_seconds: Optional[float]
    packet_count: int
    byte_count: int
    nat_traversal: bool
    parent_sa_id: Optional[str]
    association: str
    rekey_count: int
    session_id: Optional[str]
    ipsec_mode: str = "TUNNEL"
    ip_version: int = 4


class ChildSASummarySchema(BaseModel):
    id: str
    protocol: str
    spi: str
    state: SAState
    initiator: str
    responder: str
    packet_count: int
    start_time: Optional[str]
    last_seen: Optional[str]
    association: str


class SADetailSchema(SASummarySchema):
    exchange_types: list[str]
    message_ids: list[int]
    payload_types: list[str]
    flags_seen: list[str]
    child_sas: list[ChildSASummarySchema]
    parent: Optional[ChildSASummarySchema] = None
    timeline: list[SALifecycleEventSchema]
    state_history: list[SAStateHistorySchema]
    observations: list[str]
    failure: Optional[SAFailureSchema]
    capture_ended_in_state: bool
    security_parameters_available: bool
    traffic_selectors_available: bool
    packets: list[PacketSummarySchema]
    packets_total: int
    packets_available: bool


class SAStatisticsSchema(BaseModel):
    total: int
    ike: int
    child: int
    active: int
    established: int
    negotiating: int
    rekeying: int
    terminated: int
    failed: int
    detected: int
    unknown: int


class SAStatusSchema(BaseModel):
    state: EngineState
    packets_available: bool
    sessions_available: bool
    capture_id: Optional[str]
    capture_filename: Optional[str]
    discovered_at: Optional[str]
    statistics: Optional[SAStatisticsSchema]
    last_error: Optional[str] = None


class SAPageSchema(BaseModel):
    items: list[SASummarySchema]
    page: int
    page_size: int
    total: int
    total_pages: int


class SAReferenceSchema(BaseModel):
    id: str
    type: SAType
    state: SAState
    protocol: str
    spi: Optional[str]
    initiator_spi: Optional[str]


class SessionSAsSchema(BaseModel):
    session_id: str
    associations: list[SAReferenceSchema]
