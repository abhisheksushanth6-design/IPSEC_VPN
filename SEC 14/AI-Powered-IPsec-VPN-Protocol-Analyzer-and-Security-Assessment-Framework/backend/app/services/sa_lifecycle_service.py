"""SA lifecycle discovery, persistence and queries (Layer 04 service)."""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from app.db.base import SessionLocal
from app.layers.layer04_sa_lifecycle import SecurityAssociation, discover
from app.models.ipsec_session import SessionPacket
from app.models.security_association import SALifecycleEventRow, SAPacketLink, SecurityAssociationRow
from app.schemas.packets import PacketSummarySchema
from app.schemas.security_associations import (
    ChildSASummarySchema, SADetailSchema, SAPageSchema, SAReferenceSchema, SAStatisticsSchema, SAStatusSchema, SASummarySchema, SessionSAsSchema,
)
from app.services.packet_service import PacketServiceError, packet_service

MAX_PAGE_SIZE = 200
MAX_DETAIL_PACKETS = 500
SORTABLE = {"start_time", "last_seen", "state", "type", "initiator", "responder", "packet_count"}


class SALifecycleService:
    def __init__(self) -> None:
        self._last_error: Optional[str] = None

    # ----- discovery -------------------------------------------------------

    def discover(self) -> SAStatusSchema:
        capture_id = packet_service.capture_id
        if capture_id is None:
            raise PacketServiceError("PACKET_DATA_UNAVAILABLE", "No packet data is available. Load a capture in Packet Analysis first.", 409)
        try:
            result = discover(packet_service.all_packets(), capture_id)
        except Exception as exc:  # noqa: BLE001
            self._last_error = f"Lifecycle analysis failed: {type(exc).__name__}"
            raise PacketServiceError("LIFECYCLE_ANALYSIS_ERROR", "SA lifecycle analysis failed.", 500) from exc

        try:
            with SessionLocal() as db:
                # Session association from Section 6 rows, when discovery has run.
                links = db.scalars(select(SessionPacket).where(SessionPacket.capture_id == capture_id)).all()
                session_by_packet = {l.packet_number: l.session_id for l in links}

                db.execute(delete(SAPacketLink).where(SAPacketLink.capture_id == capture_id))
                db.execute(delete(SALifecycleEventRow).where(SALifecycleEventRow.sa_id.in_(
                    select(SecurityAssociationRow.id).where(SecurityAssociationRow.capture_id == capture_id))))
                db.execute(delete(SecurityAssociationRow).where(SecurityAssociationRow.capture_id == capture_id))
                now = datetime.now(timezone.utc)
                for sa in result.associations:
                    session_ids = {session_by_packet[n] for n in sa.packet_numbers if n in session_by_packet}
                    row = self._to_row(sa, capture_id, now, next(iter(session_ids)) if len(session_ids) == 1 else None)
                    db.add(row)
                    for seq, event in enumerate(sa.timeline):
                        db.add(SALifecycleEventRow(sa_id=sa.id, sequence=seq, **asdict(event)))
                    for number in sa.packet_numbers:
                        db.add(SAPacketLink(sa_id=sa.id, capture_id=capture_id, packet_number=number))
                db.commit()
        except SQLAlchemyError as exc:
            self._last_error = "Database error while storing Security Associations."
            raise PacketServiceError("DATABASE_ERROR", "Security Associations could not be stored.", 503) from exc
        self._last_error = None
        return self.status()

    def clear(self, capture_id: Optional[str] = None) -> SAStatusSchema:
        with SessionLocal() as db:
            ids = select(SecurityAssociationRow.id)
            if capture_id:
                ids = ids.where(SecurityAssociationRow.capture_id == capture_id)
                db.execute(delete(SAPacketLink).where(SAPacketLink.capture_id == capture_id))
            else:
                db.execute(delete(SAPacketLink))
            db.execute(delete(SALifecycleEventRow).where(SALifecycleEventRow.sa_id.in_(ids)))
            db.execute(delete(SecurityAssociationRow).where(SecurityAssociationRow.capture_id == capture_id) if capture_id else delete(SecurityAssociationRow))
            db.commit()
        return self.status()

    # ----- queries ---------------------------------------------------------

    def status(self) -> SAStatusSchema:
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            rows = self._rows(db, capture_id) if capture_id else []
            sessions_available = bool(capture_id) and db.scalar(select(SessionPacket.id).where(SessionPacket.capture_id == capture_id).limit(1)) is not None
        state = "ERROR" if self._last_error else "ACTIVE" if rows else "READY" if capture_id else "NOT INITIALIZED"
        capture_status = packet_service.status()
        return SAStatusSchema(
            state=state,  # type: ignore[arg-type]
            packets_available=capture_id is not None,
            sessions_available=sessions_available,
            capture_id=capture_id,
            capture_filename=capture_status.capture.filename if capture_status.capture else None,
            discovered_at=max(r.discovered_at for r in rows).isoformat(timespec="seconds") if rows else None,
            statistics=self._statistics(rows) if rows else None,
            last_error=self._last_error,
        )

    def query(self, *, page, page_size, sa_type, state, ike_version, source, destination, protocol, spi, search, sort, order) -> SAPageSchema:
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            rows = self._rows(db, capture_id) if capture_id else []
        rows = [r for r in rows if self._matches(r, sa_type, state, ike_version, source, destination, protocol, spi, search)]
        key = sort if sort in SORTABLE else "start_time"
        rows.sort(key=lambda r: ((getattr(r, key) is None), getattr(r, key) or "", r.id), reverse=(order == "desc"))
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        total = len(rows)
        total_pages = max(1, math.ceil(total / page_size))
        page = max(1, min(page, total_pages))
        start = (page - 1) * page_size
        return SAPageSchema(items=[SASummarySchema.model_validate(r) for r in rows[start:start + page_size]], page=page, page_size=page_size, total=total, total_pages=total_pages)

    def get(self, sa_id: str) -> SADetailSchema:
        with SessionLocal() as db:
            row = db.get(SecurityAssociationRow, sa_id)
            if row is None:
                raise PacketServiceError("SA_NOT_FOUND", "No Security Association with that identifier exists.", 404)
            detail = json.loads(row.detail_json)
            events = [self._event_schema(e) for e in row.events]
            numbers = [l.packet_number for l in row.packets]
            children = [self._child_ref(db.get(SecurityAssociationRow, cid)) for cid in detail.get("child_sa_ids", [])]
            parent = self._child_ref(db.get(SecurityAssociationRow, row.parent_sa_id)) if row.parent_sa_id else None

        packets_available = packet_service.capture_id == row.capture_id
        summaries: list[PacketSummarySchema] = []
        if packets_available:
            for n in numbers[:MAX_DETAIL_PACKETS]:
                p = packet_service.by_number(n)
                if p is not None:
                    summaries.append(packet_service.summary(p))

        return SADetailSchema(
            **SASummarySchema.model_validate(row).model_dump(),
            exchange_types=detail.get("exchange_types", []), message_ids=detail.get("message_ids", []),
            payload_types=detail.get("payload_types", []), flags_seen=detail.get("flags_seen", []),
            child_sas=[c for c in children if c], parent=parent, timeline=events,
            state_history=[{"timestamp": t, "state": s} for t, s in detail.get("state_history", [])],
            observations=detail.get("observations", []), failure=detail.get("failure"),
            capture_ended_in_state=detail.get("capture_ended_in_state", False),
            security_parameters_available=False, traffic_selectors_available=False,
            packets=summaries, packets_total=len(numbers), packets_available=packets_available,
        )

    def timeline(self, sa_id: str):
        return self.get(sa_id).timeline

    def packets(self, sa_id: str):
        return self.get(sa_id).packets

    def for_session(self, session_id: str) -> SessionSAsSchema:
        with SessionLocal() as db:
            rows = db.scalars(select(SecurityAssociationRow).where(SecurityAssociationRow.session_id == session_id).order_by(SecurityAssociationRow.start_time)).all()
        return SessionSAsSchema(session_id=session_id, associations=[SAReferenceSchema(id=r.id, type=r.type, state=r.state, protocol=r.protocol, spi=r.spi, initiator_spi=r.initiator_spi) for r in rows])

    def for_packet(self, packet_id: str) -> list[SAReferenceSchema]:
        packet = packet_service.get(packet_id)
        with SessionLocal() as db:
            links = db.scalars(select(SAPacketLink).where(SAPacketLink.capture_id == packet_service.capture_id, SAPacketLink.packet_number == packet.number)).all()
            rows = [db.get(SecurityAssociationRow, l.sa_id) for l in links]
        return [SAReferenceSchema(id=r.id, type=r.type, state=r.state, protocol=r.protocol, spi=r.spi, initiator_spi=r.initiator_spi) for r in rows if r]

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _rows(db, capture_id):
        return list(db.scalars(select(SecurityAssociationRow).where(SecurityAssociationRow.capture_id == capture_id).order_by(SecurityAssociationRow.start_time, SecurityAssociationRow.id)))

    @staticmethod
    def _to_row(sa: SecurityAssociation, capture_id: str, now: datetime, session_id: Optional[str]) -> SecurityAssociationRow:
        detail = {
            "exchange_types": sa.exchange_types, "message_ids": sa.message_ids, "payload_types": sa.payload_types, "flags_seen": sa.flags_seen,
            "child_sa_ids": sa.child_sa_ids, "state_history": sa.state_history, "observations": sa.observations, "failure": sa.failure,
            "capture_ended_in_state": sa.capture_ended_in_state,
        }
        return SecurityAssociationRow(
            id=sa.id, capture_id=capture_id, type=sa.type, state=sa.state, protocol=sa.protocol, initiator=sa.initiator, responder=sa.responder,
            ike_version=sa.ike_version, initiator_spi=sa.initiator_spi, responder_spi=sa.responder_spi, spi=sa.spi, start_time=sa.start_time,
            last_seen=sa.last_seen, duration_seconds=sa.duration_seconds, packet_count=sa.packet_count, byte_count=sa.byte_count,
            nat_traversal=sa.nat_traversal, parent_sa_id=sa.parent_sa_id, association=sa.association, rekey_count=sa.rekey_count,
            session_id=session_id, ipsec_mode=sa.ipsec_mode, ip_version=sa.ip_version,
            detail_json=json.dumps(detail), discovered_at=now,
        )

    @staticmethod
    def _event_schema(e: SALifecycleEventRow):
        return {"timestamp": e.timestamp, "event_type": e.event_type, "previous_state": e.previous_state, "new_state": e.new_state,
                "packet_number": e.packet_number, "message_id": e.message_id, "spi": e.spi, "description": e.description}

    @staticmethod
    def _child_ref(row: Optional[SecurityAssociationRow]) -> Optional[ChildSASummarySchema]:
        if row is None:
            return None
        return ChildSASummarySchema(id=row.id, protocol=row.protocol, spi=row.spi or row.initiator_spi or "", state=row.state, initiator=row.initiator,
                                    responder=row.responder, packet_count=row.packet_count, start_time=row.start_time, last_seen=row.last_seen, association=row.association)

    @staticmethod
    def _statistics(rows) -> SAStatisticsSchema:
        c = lambda pred: sum(1 for r in rows if pred(r))  # noqa: E731
        return SAStatisticsSchema(
            total=len(rows), ike=c(lambda r: r.type == "IKE"), child=c(lambda r: r.type == "CHILD"), active=c(lambda r: r.state == "ACTIVE"),
            established=c(lambda r: r.state == "ESTABLISHED"), negotiating=c(lambda r: r.state == "NEGOTIATING"), rekeying=c(lambda r: r.state == "REKEYING"),
            terminated=c(lambda r: r.state == "TERMINATED"), failed=c(lambda r: r.state == "FAILED"), detected=c(lambda r: r.state == "DETECTED"),
            unknown=c(lambda r: r.state in ("UNKNOWN", "EXPIRED")),
        )

    @staticmethod
    def _matches(r, sa_type, state, ike_version, source, destination, protocol, spi, search) -> bool:
        if sa_type and r.type != sa_type.upper():
            return False
        if state and r.state != state.upper():
            return False
        if ike_version and (r.ike_version or "") != ike_version:
            return False
        if source and source.lower() not in r.initiator.lower():
            return False
        if destination and destination.lower() not in r.responder.lower():
            return False
        if protocol and r.protocol != protocol.upper():
            return False
        if spi and spi.lower() not in " ".join(filter(None, [r.spi, r.initiator_spi, r.responder_spi])).lower():
            return False
        if search:
            needle = search.lower()
            hay = [r.id, r.initiator, r.responder, r.state, r.type, r.protocol, r.ike_version or "", r.spi or "", r.initiator_spi or "", r.responder_spi or ""]
            if not any(needle in h.lower() for h in hay):
                return False
        return True


sa_lifecycle_service = SALifecycleService()
