"""Session discovery, persistence and queries.

Sessions are derived by `session_correlation.correlate` from the packets the
packet service currently holds, then written to SQLite keyed by capture ID.
Packet association is by packet number, which is stable within a capture.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as DBSession

from app.db.base import SessionLocal
from app.models.ipsec_session import IPsecSession, SessionPacket
from app.schemas.packets import PacketSummarySchema
from app.schemas.sessions import (
    PacketSessionSchema,
    SessionDetailSchema,
    SessionPageSchema,
    SessionStatisticsSchema,
    SessionStatusSchema,
    SessionSummarySchema,
)
from app.services.packet_service import PacketServiceError, packet_service
from app.services.session_correlation import INACTIVITY_GAP_SECONDS, Session, correlate

MAX_PAGE_SIZE = 200
MAX_DETAIL_PACKETS = 500
SORTABLE = {"start_time", "end_time", "duration_seconds", "packet_count", "source", "destination", "state", "byte_count"}


class SessionService:
    def __init__(self) -> None:
        self._last_error: Optional[str] = None

    # ----- discovery -------------------------------------------------------

    def discover(self) -> SessionStatusSchema:
        capture_id = packet_service.capture_id
        if capture_id is None:
            raise PacketServiceError("PACKET_DATA_UNAVAILABLE", "No packet data is available. Load a capture in Packet Analysis first.", 409)
        packets = packet_service.all_packets()
        try:
            sessions = correlate(packets, capture_id)
        except Exception as exc:  # noqa: BLE001
            self._last_error = f"Correlation failed: {type(exc).__name__}"
            raise PacketServiceError("CORRELATION_ERROR", "Session correlation failed.", 500) from exc

        try:
            with SessionLocal() as db:
                db.execute(delete(SessionPacket).where(SessionPacket.capture_id == capture_id))
                db.execute(delete(IPsecSession).where(IPsecSession.capture_id == capture_id))
                now = datetime.now(timezone.utc)
                for s in sessions:
                    db.add(self._to_row(s, capture_id, now))
                    for number in s.packet_numbers:
                        db.add(SessionPacket(session_id=s.id, capture_id=capture_id, packet_number=number, role=s.packet_roles.get(number, "IKE")))
                db.commit()
        except SQLAlchemyError as exc:
            self._last_error = "Database error while storing sessions."
            raise PacketServiceError("DATABASE_ERROR", "Sessions could not be stored.", 503) from exc
        self._last_error = None
        return self.status()

    def clear(self, capture_id: Optional[str] = None) -> SessionStatusSchema:
        with SessionLocal() as db:
            if capture_id:
                db.execute(delete(SessionPacket).where(SessionPacket.capture_id == capture_id))
                db.execute(delete(IPsecSession).where(IPsecSession.capture_id == capture_id))
            else:
                db.execute(delete(SessionPacket))
                db.execute(delete(IPsecSession))
            db.commit()
        return self.status()

    # ----- queries ---------------------------------------------------------

    def status(self) -> SessionStatusSchema:
        capture_id = packet_service.capture_id
        packets_available = capture_id is not None
        statistics = None
        discovered_at = None
        with SessionLocal() as db:
            rows = self._rows_for_capture(db, capture_id) if capture_id else []
        if capture_id and rows:
            statistics = self._statistics(rows)
            discovered_at = max(r.discovered_at for r in rows).isoformat(timespec="seconds")
        state = "ERROR" if self._last_error else "AVAILABLE" if rows else "READY" if packets_available else "NOT INITIALIZED"
        capture_status = packet_service.status()
        return SessionStatusSchema(
            state=state,  # type: ignore[arg-type]
            packets_available=packets_available,
            capture_id=capture_id,
            capture_filename=capture_status.capture.filename if capture_status.capture else None,
            discovered_at=discovered_at,
            statistics=statistics,
            inactivity_gap_seconds=INACTIVITY_GAP_SECONDS,
            last_error=self._last_error,
        )

    def query(self, *, page: int, page_size: int, state, protocol, source, destination, ike_version, search, start_after, end_before, sort, order) -> SessionPageSchema:
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            rows = self._rows_for_capture(db, capture_id) if capture_id else []

        rows = [r for r in rows if self._matches(r, state, protocol, source, destination, ike_version, search, start_after, end_before)]
        key = sort if sort in SORTABLE else "start_time"
        rows.sort(key=lambda r: ((getattr(r, key) is None), getattr(r, key) or "", r.ordinal), reverse=(order == "desc"))

        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        total = len(rows)
        total_pages = max(1, math.ceil(total / page_size))
        page = max(1, min(page, total_pages))
        start = (page - 1) * page_size
        return SessionPageSchema(items=[self._summary(r) for r in rows[start : start + page_size]], page=page, page_size=page_size, total=total, total_pages=total_pages)

    def get(self, session_id: str) -> SessionDetailSchema:
        with SessionLocal() as db:
            row = db.get(IPsecSession, session_id)
            if row is None:
                raise PacketServiceError("SESSION_NOT_FOUND", "No session with that identifier exists.", 404)
            numbers = [sp.packet_number for sp in row.packets]
            detail = json.loads(row.detail_json)

        packets_available = packet_service.capture_id == row.capture_id
        summaries: list[PacketSummarySchema] = []
        if packets_available:
            for number in numbers[:MAX_DETAIL_PACKETS]:
                packet = packet_service.by_number(number)
                if packet is not None:
                    summaries.append(packet_service.summary(packet))

        return SessionDetailSchema(
            **self._summary(row).model_dump(),
            ike=detail.get("ike"),
            esp=detail.get("esp"),
            ah=detail.get("ah"),
            timeline=detail.get("timeline", []),
            activity=detail.get("activity", []),
            evidence=detail.get("evidence", []),
            packets=summaries,
            packets_total=len(numbers),
            packets_available=packets_available,
        )

    def for_packet(self, packet_id: str) -> PacketSessionSchema:
        packet = packet_service.get(packet_id)  # raises PACKET_NOT_FOUND
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            link = db.scalar(select(SessionPacket).where(SessionPacket.capture_id == capture_id, SessionPacket.packet_number == packet.number))
        return PacketSessionSchema(packet_id=packet_id, session_id=link.session_id if link else None, role=link.role if link else None)

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _rows_for_capture(db: DBSession, capture_id: str) -> list[IPsecSession]:
        return list(db.scalars(select(IPsecSession).where(IPsecSession.capture_id == capture_id).order_by(IPsecSession.ordinal)))

    @staticmethod
    def _to_row(s: Session, capture_id: str, now: datetime) -> IPsecSession:
        detail = {
            "ike": asdict(s.ike) if s.ike else None,
            "esp": asdict(s.esp) if s.esp else None,
            "ah": asdict(s.ah) if s.ah else None,
            "timeline": [asdict(e) for e in s.timeline],
            "activity": [asdict(a) for a in s.activity],
            "evidence": s.evidence,
        }
        return IPsecSession(
            id=s.id, capture_id=capture_id, ordinal=s.ordinal, source=s.source, destination=s.destination,
            direction=s.direction, state=s.state, correlation=s.correlation, start_time=s.start_time, end_time=s.end_time,
            duration_seconds=s.duration_seconds, packet_count=s.packet_count, byte_count=s.byte_count,
            ike_packets=s.ike_packets, esp_packets=s.esp_packets, ah_packets=s.ah_packets, ike_version=s.ike_version,
            nat_traversal=s.nat_traversal, ipsec_mode=s.ipsec_mode, ip_version=s.ip_version,
            detail_json=json.dumps(detail), discovered_at=now,
        )

    @staticmethod
    def _summary(r: IPsecSession) -> SessionSummarySchema:
        return SessionSummarySchema.model_validate(r)

    @staticmethod
    def _statistics(rows: list[IPsecSession]) -> SessionStatisticsSchema:
        count = lambda st: sum(1 for r in rows if r.state == st)  # noqa: E731
        return SessionStatisticsSchema(
            total=len(rows), active=count("ACTIVE"), established=count("ESTABLISHED"), negotiating=count("NEGOTIATING"),
            terminated=count("TERMINATED"), discovered=count("DISCOVERED"), unknown=count("UNKNOWN") + count("IDLE"),
        )

    @staticmethod
    def _matches(r: IPsecSession, state, protocol, source, destination, ike_version, search, start_after, end_before) -> bool:
        if state and r.state != state.upper():
            return False
        if protocol:
            p = protocol.upper()
            if (p == "IKE" and not r.ike_packets) or (p == "ESP" and not r.esp_packets) or (p == "AH" and not r.ah_packets):
                return False
        if source and source.lower() not in r.source.lower():
            return False
        if destination and destination.lower() not in r.destination.lower():
            return False
        if ike_version and (r.ike_version or "") != ike_version:
            return False
        if start_after and (r.start_time or "") < start_after:
            return False
        if end_before and (r.end_time or "") > end_before:
            return False
        if search:
            needle = search.lower()
            detail = json.loads(r.detail_json)
            spis = []
            for key in ("esp", "ah"):
                for entry in (detail.get(key) or {}).get("spis", []):
                    spis.append(entry["spi"])
            if detail.get("ike"):
                spis += detail["ike"].get("initiator_spis", []) + detail["ike"].get("responder_spis", [])
            haystack = [r.id, r.source, r.destination, r.state, r.direction] + spis + [k for k, n in (("IKE", r.ike_packets), ("ESP", r.esp_packets), ("AH", r.ah_packets)) if n]
            if not any(needle in h.lower() for h in haystack):
                return False
        return True


session_service = SessionService()
