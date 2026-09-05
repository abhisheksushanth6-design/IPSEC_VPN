"""IPsec sessions endpoints (supporting analysis module over Layer 03 output)."""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Query

from app.api.routes.packets import ERROR_RESPONSES
from app.schemas.sessions import PacketSessionSchema, SessionDetailSchema, SessionPageSchema, SessionStatusSchema
from app.services.session_service import session_service

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("/status", response_model=SessionStatusSchema, summary="Session engine state and statistics")
def read_status() -> SessionStatusSchema:
    return session_service.status()


@router.get("", response_model=SessionPageSchema, summary="List discovered sessions")
def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    state: Optional[str] = Query(None, pattern="^(?i)(DISCOVERED|NEGOTIATING|ESTABLISHED|ACTIVE|IDLE|TERMINATED|UNKNOWN)$"),
    protocol: Optional[str] = Query(None, pattern="^(?i)(IKE|ESP|AH)$"),
    source: Optional[str] = Query(None, max_length=64),
    destination: Optional[str] = Query(None, max_length=64),
    ike_version: Optional[str] = Query(None, max_length=8),
    search: Optional[str] = Query(None, max_length=128),
    start_after: Optional[str] = Query(None, max_length=40),
    end_before: Optional[str] = Query(None, max_length=40),
    sort: Literal["start_time", "end_time", "duration_seconds", "packet_count", "byte_count", "source", "destination", "state"] = "start_time",
    order: Literal["asc", "desc"] = "asc",
) -> SessionPageSchema:
    return session_service.query(page=page, page_size=page_size, state=state, protocol=protocol, source=source, destination=destination,
                                 ike_version=ike_version, search=search, start_after=start_after, end_before=end_before, sort=sort, order=order)


@router.post("/discover", response_model=SessionStatusSchema, responses=ERROR_RESPONSES, summary="Correlate loaded packets into sessions")
def discover() -> SessionStatusSchema:
    return session_service.discover()


@router.delete("", response_model=SessionStatusSchema, summary="Clear sessions for the loaded capture")
def clear() -> SessionStatusSchema:
    from app.services.packet_service import packet_service
    return session_service.clear(packet_service.capture_id)


@router.get("/for-packet/{packet_id}", response_model=PacketSessionSchema, responses=ERROR_RESPONSES, summary="Session associated with a packet")
def for_packet(packet_id: str) -> PacketSessionSchema:
    return session_service.for_packet(packet_id)


@router.get("/{session_id}", response_model=SessionDetailSchema, responses=ERROR_RESPONSES, summary="Session detail")
def read_session(session_id: str) -> SessionDetailSchema:
    return session_service.get(session_id)
