"""SA lifecycle endpoints (Layer 04)."""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Query

from app.api.routes.packets import ERROR_RESPONSES
from app.schemas.packets import PacketSummarySchema
from app.schemas.security_associations import SADetailSchema, SALifecycleEventSchema, SAPageSchema, SAReferenceSchema, SAStatusSchema, SessionSAsSchema
from app.services.sa_lifecycle_service import sa_lifecycle_service

router = APIRouter(prefix="/sas", tags=["security-associations"])


@router.get("/status", response_model=SAStatusSchema, summary="SA engine state and statistics")
def read_status() -> SAStatusSchema:
    return sa_lifecycle_service.status()


@router.get("", response_model=SAPageSchema, summary="List Security Associations")
def list_sas(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
    type: Optional[str] = Query(None, pattern="^(?i)(IKE|CHILD|UNKNOWN)$"),
    state: Optional[str] = Query(None, pattern="^(?i)(UNKNOWN|DETECTED|NEGOTIATING|ESTABLISHED|ACTIVE|REKEYING|EXPIRED|TERMINATED|FAILED)$"),
    ike_version: Optional[str] = Query(None, max_length=8), source: Optional[str] = Query(None, max_length=64),
    destination: Optional[str] = Query(None, max_length=64), protocol: Optional[str] = Query(None, pattern="^(?i)(IKE|ESP|AH)$"),
    spi: Optional[str] = Query(None, max_length=32), search: Optional[str] = Query(None, max_length=128),
    sort: Literal["start_time", "last_seen", "state", "type", "initiator", "responder", "packet_count"] = "start_time",
    order: Literal["asc", "desc"] = "asc",
) -> SAPageSchema:
    return sa_lifecycle_service.query(page=page, page_size=page_size, sa_type=type, state=state, ike_version=ike_version, source=source,
                                      destination=destination, protocol=protocol, spi=spi, search=search, sort=sort, order=order)


@router.post("/discover", response_model=SAStatusSchema, responses=ERROR_RESPONSES, summary="Run SA lifecycle analysis on the loaded capture")
def discover() -> SAStatusSchema:
    return sa_lifecycle_service.discover()


@router.delete("", response_model=SAStatusSchema, summary="Clear SAs for the loaded capture")
def clear() -> SAStatusSchema:
    from app.services.packet_service import packet_service
    return sa_lifecycle_service.clear(packet_service.capture_id)


@router.get("/for-session/{session_id}", response_model=SessionSAsSchema, summary="SAs associated with a session")
def for_session(session_id: str) -> SessionSAsSchema:
    return sa_lifecycle_service.for_session(session_id)


@router.get("/for-packet/{packet_id}", response_model=list[SAReferenceSchema], responses=ERROR_RESPONSES, summary="SAs a packet belongs to")
def for_packet(packet_id: str) -> list[SAReferenceSchema]:
    return sa_lifecycle_service.for_packet(packet_id)


@router.get("/{sa_id}", response_model=SADetailSchema, responses=ERROR_RESPONSES, summary="SA detail")
def read_sa(sa_id: str) -> SADetailSchema:
    return sa_lifecycle_service.get(sa_id)


@router.get("/{sa_id}/timeline", response_model=list[SALifecycleEventSchema], responses=ERROR_RESPONSES, summary="SA lifecycle events")
def read_timeline(sa_id: str) -> list[SALifecycleEventSchema]:
    return sa_lifecycle_service.timeline(sa_id)


@router.get("/{sa_id}/packets", response_model=list[PacketSummarySchema], responses=ERROR_RESPONSES, summary="Packets associated with an SA")
def read_packets(sa_id: str) -> list[PacketSummarySchema]:
    return sa_lifecycle_service.packets(sa_id)
