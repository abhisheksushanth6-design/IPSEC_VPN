"""Feature extraction, persistence and queries (Layer 05 service).

The service owns entity resolution and storage; all calculation lives in
``app.layers.layer05_feature_engineering``. Requests reference an entity by
type and id — the backend already holds the packets, sessions and SAs, so
nothing re-sends source data and nothing is re-parsed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import threading
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError

from app.db.base import SessionLocal
from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult
from app.layers.layer05_feature_engineering import (
    BURST_WINDOW_SECONDS,
    FEATURE_DEFINITIONS,
    FEATURE_VERSION,
    FeatureExtractionError,
    FeatureVector,
    SAEvent,
    SARecord,
    SessionRecord,
    definition,
    extract_packet,
    extract_sa,
    extract_session,
)
from app.models.feature_vector import FeatureValueRow, FeatureVectorRow
from app.models.ipsec_session import IPsecSession, SessionPacket
from app.models.security_association import SecurityAssociationRow
from app.schemas.features import (
    FeatureDefinitionSchema,
    FeatureEngineStatusSchema,
    FeatureEntityListSchema,
    FeatureEntitySchema,
    FeatureStatisticsSchema,
    FeatureValueSchema,
    FeatureVectorPageSchema,
    FeatureVectorSchema,
    FeatureVectorSummarySchema,
    SourceAvailabilitySchema,
)
from app.services.packet_service import PacketServiceError, packet_service

MAX_PAGE_SIZE = 200
MAX_ENTITY_OPTIONS = 200
ENTITY_TYPES = ("PACKET", "SESSION", "SA")


class FeatureExtractionService:
    def __init__(self) -> None:
        self._last_error: Optional[str] = None
        self._lock = threading.Lock()
        self._processing = False

    # ----- extraction ------------------------------------------------------

    def extract(self, entity_type: str, entity_id: str) -> FeatureVectorSchema:
        """Extract and store features for one entity."""
        capture_id = self._require_capture()
        with self._lock:
            self._processing = True
        try:
            vector = self._build(entity_type, entity_id, capture_id)
        except FeatureExtractionError as exc:
            self._last_error = exc.message
            raise PacketServiceError(exc.code, exc.message, 422) from exc
        except PacketServiceError:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced as a safe envelope
            self._last_error = f"Feature extraction failed: {type(exc).__name__}"
            raise PacketServiceError(
                "FEATURE_EXTRACTION_FAILED", "Feature extraction failed.", 500
            ) from exc
        finally:
            with self._lock:
                self._processing = False

        self._store(vector)
        self._last_error = None
        return self._to_schema(vector)

    def _build(self, entity_type: str, entity_id: str, capture_id: str) -> FeatureVector:
        if entity_type == "PACKET":
            return self._build_packet_vector(entity_id, capture_id)
        if entity_type == "SESSION":
            return self._build_session_vector(entity_id, capture_id)
        if entity_type == "SA":
            return self._build_sa_vector(entity_id, capture_id)
        raise PacketServiceError(
            "ENTITY_NOT_FOUND", f"Unsupported entity type '{entity_type}'.", 404
        )

    def _build_packet_vector(self, packet_id: str, capture_id: str) -> FeatureVector:
        packet = packet_service.get(packet_id)  # raises PACKET_NOT_FOUND
        session_source, session_id = self._session_reference(capture_id, packet.number)
        return extract_packet(
            packet, capture_id, session_source=session_source, session_id=session_id
        )

    def _build_session_vector(self, session_id: str, capture_id: str) -> FeatureVector:
        with SessionLocal() as db:
            row = db.get(IPsecSession, session_id)
            if row is None or row.capture_id != capture_id:
                raise PacketServiceError(
                    "ENTITY_NOT_FOUND", "No session with that identifier exists for the loaded capture.", 404
                )
            record = self._session_record(row)
            numbers = [sp.packet_number for sp in row.packets]

        packets = self._packets_for(capture_id, numbers)
        return extract_session(record, capture_id, packets)

    def _build_sa_vector(self, sa_id: str, capture_id: str) -> FeatureVector:
        with SessionLocal() as db:
            row = db.get(SecurityAssociationRow, sa_id)
            if row is None or row.capture_id != capture_id:
                raise PacketServiceError(
                    "ENTITY_NOT_FOUND", "No Security Association with that identifier exists for the loaded capture.", 404
                )
            record = self._sa_record(row)
        return extract_sa(record, capture_id)

    # ----- source resolution ------------------------------------------------

    @staticmethod
    def _session_reference(capture_id: str, packet_number: int) -> tuple[Optional[str], Optional[str]]:
        """The session a packet belongs to, which is what makes direction real."""
        with SessionLocal() as db:
            link = db.scalar(
                select(SessionPacket).where(
                    SessionPacket.capture_id == capture_id,
                    SessionPacket.packet_number == packet_number,
                )
            )
            if link is None:
                return None, None
            session = db.get(IPsecSession, link.session_id)
            return (session.source, session.id) if session else (None, None)

    @staticmethod
    def _packets_for(capture_id: str, numbers: list[int]) -> Optional[list[PacketAnalysisResult]]:
        """Decoded packets for a session, or None when the capture is gone."""
        if packet_service.capture_id != capture_id:
            return None
        packets = [packet_service.by_number(number) for number in numbers]
        return [p for p in packets if p is not None]

    @staticmethod
    def _session_record(row: IPsecSession) -> SessionRecord:
        detail = json.loads(row.detail_json) if row.detail_json else {}
        return SessionRecord(
            id=row.id,
            source=row.source,
            destination=row.destination,
            state=row.state,
            direction=row.direction,
            packet_count=row.packet_count,
            byte_count=row.byte_count,
            ike_packets=row.ike_packets,
            esp_packets=row.esp_packets,
            ah_packets=row.ah_packets,
            nat_traversal=bool(row.nat_traversal),
            start_time=row.start_time,
            end_time=row.end_time,
            duration_seconds=row.duration_seconds,
            ike_version=row.ike_version,
            ike_detail=detail.get("ike"),
        )

    @staticmethod
    def _sa_record(row: SecurityAssociationRow) -> SARecord:
        detail = json.loads(row.detail_json) if row.detail_json else {}
        events = [
            SAEvent(
                event_type=event.event_type,
                timestamp=event.timestamp,
                previous_state=event.previous_state,
                new_state=event.new_state,
                packet_number=event.packet_number,
            )
            for event in row.events
        ]
        return SARecord(
            id=row.id,
            type=row.type,
            state=row.state,
            protocol=row.protocol,
            initiator=row.initiator,
            responder=row.responder,
            packet_count=row.packet_count,
            byte_count=row.byte_count,
            nat_traversal=bool(row.nat_traversal),
            rekey_count=row.rekey_count,
            capture_ended_in_state=bool(detail.get("capture_ended_in_state", False)),
            ike_version=row.ike_version,
            spi_label=row.spi or row.initiator_spi,
            start_time=row.start_time,
            last_seen=row.last_seen,
            duration_seconds=row.duration_seconds,
            child_sa_ids=list(detail.get("child_sa_ids") or []),
            events=events,
        )

    # ----- persistence ------------------------------------------------------

    @staticmethod
    def _vector_id(vector: FeatureVector) -> str:
        digest = hashlib.sha256(
            f"{vector.capture_id}|{vector.entity_type}|{vector.entity_id}".encode()
        ).hexdigest()
        return f"FV-{digest[:32]}"

    def _store(self, vector: FeatureVector) -> None:
        vector_id = self._vector_id(vector)
        try:
            with SessionLocal() as db:
                db.execute(delete(FeatureValueRow).where(FeatureValueRow.vector_id == vector_id))
                db.execute(delete(FeatureVectorRow).where(FeatureVectorRow.id == vector_id))
                db.add(
                    FeatureVectorRow(
                        id=vector_id,
                        capture_id=vector.capture_id,
                        entity_type=vector.entity_type,
                        entity_id=vector.entity_id,
                        entity_label=vector.entity_label[:200],
                        feature_version=vector.feature_version,
                        generated_at=vector.generated_at,
                        feature_count=len(vector.features),
                        available_count=vector.available_count,
                        partial_count=vector.partial_count,
                        unavailable_count=vector.unavailable_count,
                        sources_json=json.dumps(
                            [
                                {"name": s.name, "available": s.available, "detail": s.detail}
                                for s in vector.sources
                            ]
                        ),
                        extracted_at=datetime.now(timezone.utc),
                    )
                )
                for ordinal, feature in enumerate(vector.features):
                    spec = definition(vector.entity_type, feature.name)
                    db.add(
                        FeatureValueRow(
                            vector_id=vector_id,
                            ordinal=ordinal,
                            name=feature.name,
                            level=spec.level,
                            data_type=spec.data_type,
                            value_integer=feature.value if spec.data_type == "INTEGER" and isinstance(feature.value, int) and not isinstance(feature.value, bool) else None,
                            value_float=float(feature.value) if spec.data_type == "FLOAT" and isinstance(feature.value, (int, float)) and not isinstance(feature.value, bool) else None,
                            value_boolean=feature.value if spec.data_type == "BOOLEAN" and isinstance(feature.value, bool) else None,
                            value_text=feature.value if spec.data_type in ("CATEGORICAL", "TIMESTAMP") and isinstance(feature.value, str) else None,
                            availability=feature.availability,
                            quality=feature.quality,
                            source=feature.source[:120],
                            detail=feature.detail,
                            normalization_method=feature.normalization_method,
                            normalized_value=feature.normalized_value,
                        )
                    )
                db.commit()
        except SQLAlchemyError as exc:
            self._last_error = "Database error while storing feature vectors."
            raise PacketServiceError(
                "DATABASE_ERROR", "The feature vector could not be stored.", 503
            ) from exc

    def clear(self, capture_id: Optional[str] = None) -> FeatureEngineStatusSchema:
        try:
            with SessionLocal() as db:
                if capture_id:
                    ids = select(FeatureVectorRow.id).where(FeatureVectorRow.capture_id == capture_id)
                    db.execute(delete(FeatureValueRow).where(FeatureValueRow.vector_id.in_(ids)))
                    db.execute(delete(FeatureVectorRow).where(FeatureVectorRow.capture_id == capture_id))
                else:
                    db.execute(delete(FeatureValueRow))
                    db.execute(delete(FeatureVectorRow))
                db.commit()
        except SQLAlchemyError as exc:
            self._last_error = "Database error while clearing feature vectors."
            raise PacketServiceError(
                "DATABASE_ERROR", "Feature vectors could not be cleared.", 503
            ) from exc
        self._last_error = None
        return self.status()

    # ----- queries ----------------------------------------------------------

    def status(self) -> FeatureEngineStatusSchema:
        capture_id = packet_service.capture_id
        packets_available = capture_id is not None
        sessions_available = False
        sas_available = False
        statistics = None
        extracted_at = None

        with SessionLocal() as db:
            if capture_id:
                sessions_available = bool(
                    db.scalar(select(func.count()).select_from(IPsecSession).where(IPsecSession.capture_id == capture_id))
                )
                sas_available = bool(
                    db.scalar(
                        select(func.count())
                        .select_from(SecurityAssociationRow)
                        .where(SecurityAssociationRow.capture_id == capture_id)
                    )
                )
                rows = list(
                    db.scalars(select(FeatureVectorRow).where(FeatureVectorRow.capture_id == capture_id))
                )
            else:
                rows = []
        if rows:
            statistics = self._statistics(rows)
            extracted_at = max(r.generated_at for r in rows)

        with self._lock:
            processing = self._processing

        if self._last_error:
            state = "ERROR"
        elif processing:
            state = "PROCESSING"
        elif rows:
            state = "AVAILABLE"
        elif packets_available:
            state = "READY"
        else:
            state = "NOT INITIALIZED"

        return FeatureEngineStatusSchema(
            state=state,  # type: ignore[arg-type]
            feature_version=FEATURE_VERSION,
            packets_available=packets_available,
            sessions_available=sessions_available,
            sas_available=sas_available,
            capture_id=capture_id,
            capture_filename=packet_service.status().capture.filename if packets_available else None,
            extracted_at=extracted_at,
            registered_features=len(FEATURE_DEFINITIONS),
            burst_window_seconds=BURST_WINDOW_SECONDS,
            statistics=statistics,
            last_error=self._last_error,
        )

    def definitions(self) -> list[FeatureDefinitionSchema]:
        return [FeatureDefinitionSchema.model_validate(d) for d in FEATURE_DEFINITIONS]

    def entities(self, entity_type: str) -> FeatureEntityListSchema:
        """Selectable entities of one type, for the source selector."""
        if entity_type not in ENTITY_TYPES:
            raise PacketServiceError("ENTITY_NOT_FOUND", f"Unsupported entity type '{entity_type}'.", 404)
        capture_id = packet_service.capture_id
        if capture_id is None:
            return FeatureEntityListSchema(
                entity_type=entity_type,  # type: ignore[arg-type]
                items=[],
                source_available=False,
                detail="No capture is loaded. Load one in Packet Analysis first.",
            )

        with SessionLocal() as db:
            extracted = {
                row.entity_id
                for row in db.scalars(
                    select(FeatureVectorRow).where(
                        FeatureVectorRow.capture_id == capture_id,
                        FeatureVectorRow.entity_type == entity_type,
                    )
                )
            }
            if entity_type == "SESSION":
                rows = list(
                    db.scalars(
                        select(IPsecSession)
                        .where(IPsecSession.capture_id == capture_id)
                        .order_by(IPsecSession.ordinal)
                        .limit(MAX_ENTITY_OPTIONS)
                    )
                )
                items = [
                    FeatureEntitySchema(
                        entity_type="SESSION",
                        entity_id=row.id,
                        label=f"{row.source} ↔ {row.destination}",
                        detail=f"{row.state} · {row.packet_count} packets",
                        extracted=row.id in extracted,
                    )
                    for row in rows
                ]
                detail = (
                    f"{len(items)} session(s) discovered."
                    if items
                    else "No sessions have been discovered for this capture. Run discovery in IPsec Sessions."
                )
            elif entity_type == "SA":
                rows = list(
                    db.scalars(
                        select(SecurityAssociationRow)
                        .where(SecurityAssociationRow.capture_id == capture_id)
                        .order_by(SecurityAssociationRow.start_time)
                        .limit(MAX_ENTITY_OPTIONS)
                    )
                )
                items = [
                    FeatureEntitySchema(
                        entity_type="SA",
                        entity_id=row.id,
                        label=f"{row.type} · {row.initiator} → {row.responder}",
                        detail=f"{row.state} · {row.packet_count} packets",
                        extracted=row.id in extracted,
                    )
                    for row in rows
                ]
                detail = (
                    f"{len(items)} Security Association(s) discovered."
                    if items
                    else "No Security Associations have been discovered. Run discovery in SA Lifecycle."
                )
            else:
                packets = packet_service.all_packets()[:MAX_ENTITY_OPTIONS]
                items = [
                    FeatureEntitySchema(
                        entity_type="PACKET",
                        entity_id=packet.id,
                        label=f"#{packet.number} · {packet.source} → {packet.destination}",
                        detail=f"{packet.protocol} · {packet.original_length} bytes",
                        extracted=packet.id in extracted,
                    )
                    for packet in packets
                ]
                detail = (
                    f"Showing the first {len(items)} packet(s) of the loaded capture."
                    if items
                    else "The loaded capture contains no packets."
                )

        return FeatureEntityListSchema(
            entity_type=entity_type,  # type: ignore[arg-type]
            items=items,
            source_available=bool(items),
            detail=detail,
        )

    def query(self, *, page: int, page_size: int, entity_type: Optional[str]) -> FeatureVectorPageSchema:
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            rows = (
                list(
                    db.scalars(
                        select(FeatureVectorRow)
                        .where(FeatureVectorRow.capture_id == capture_id)
                        .order_by(FeatureVectorRow.entity_type, FeatureVectorRow.generated_at)
                    )
                )
                if capture_id
                else []
            )
        if entity_type:
            rows = [r for r in rows if r.entity_type == entity_type.upper()]

        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        total = len(rows)
        total_pages = max(1, math.ceil(total / page_size))
        page = max(1, min(page, total_pages))
        start = (page - 1) * page_size
        return FeatureVectorPageSchema(
            items=[FeatureVectorSummarySchema.model_validate(r) for r in rows[start : start + page_size]],
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
        )

    def get(self, vector_id: str) -> FeatureVectorSchema:
        with SessionLocal() as db:
            row = db.get(FeatureVectorRow, vector_id)
            if row is None:
                raise PacketServiceError("FEATURE_VECTOR_NOT_FOUND", "No feature vector with that identifier exists.", 404)
            return self._row_to_schema(row)

    def for_entity(self, entity_type: str, entity_id: str) -> FeatureVectorSchema:
        with SessionLocal() as db:
            row = db.scalar(
                select(FeatureVectorRow).where(
                    FeatureVectorRow.entity_type == entity_type.upper(),
                    FeatureVectorRow.entity_id == entity_id,
                )
            )
            if row is None:
                raise PacketServiceError(
                    "FEATURE_VECTOR_NOT_FOUND",
                    "No features have been extracted for that entity yet.",
                    404,
                )
            return self._row_to_schema(row)

    def export(self, fmt: str) -> tuple[str, str]:
        """Export stored vectors as JSON or CSV. Returns (payload, media type)."""
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            rows = (
                list(db.scalars(select(FeatureVectorRow).where(FeatureVectorRow.capture_id == capture_id)))
                if capture_id
                else []
            )
            if not rows:
                raise PacketServiceError(
                    "NO_FEATURE_DATA_AVAILABLE", "No feature data is available to export.", 409
                )
            vectors = [self._row_to_schema(row) for row in rows]

        if fmt == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(
                [
                    "entity_type", "entity_id", "entity_label", "feature_version", "generated_at",
                    "feature", "value", "data_type", "unit", "availability", "quality", "source",
                ]
            )
            for vector in vectors:
                for feature in vector.features:
                    writer.writerow(
                        [
                            vector.entity_type, vector.entity_id, vector.entity_label,
                            vector.feature_version, vector.generated_at, feature.name,
                            "" if feature.value is None else feature.value,
                            feature.data_type, feature.unit or "", feature.availability,
                            feature.quality, feature.source,
                        ]
                    )
            return buffer.getvalue(), "text/csv"

        payload = {
            "feature_version": FEATURE_VERSION,
            "capture_id": capture_id,
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "feature_vectors": [vector.model_dump() for vector in vectors],
        }
        return json.dumps(payload, indent=2), "application/json"

    # ----- helpers ----------------------------------------------------------

    @staticmethod
    def _require_capture() -> str:
        capture_id = packet_service.capture_id
        if capture_id is None:
            raise PacketServiceError(
                "PACKET_DATA_UNAVAILABLE",
                "No packet data is available. Load a capture in Packet Analysis first.",
                409,
            )
        return capture_id

    @staticmethod
    def _statistics(rows: list[FeatureVectorRow]) -> FeatureStatisticsSchema:
        count = lambda kind: sum(1 for r in rows if r.entity_type == kind)  # noqa: E731
        return FeatureStatisticsSchema(
            vectors=len(rows),
            packet_vectors=count("PACKET"),
            session_vectors=count("SESSION"),
            sa_vectors=count("SA"),
            total_features=sum(r.feature_count for r in rows),
            available_features=sum(r.available_count for r in rows),
            partial_features=sum(r.partial_count for r in rows),
            unavailable_features=sum(r.unavailable_count for r in rows),
        )

    @staticmethod
    def _feature_schema(name: str, level: str, value, availability: str, quality: str, source: str, detail, normalized) -> FeatureValueSchema:
        spec = definition(level, name)
        return FeatureValueSchema(
            name=spec.name,
            display_name=spec.display_name,
            description=spec.description,
            value=value,
            data_type=spec.data_type,
            category=spec.category,
            level=spec.level,
            unit=spec.unit,
            source=source,
            detail=detail,
            availability=availability,  # type: ignore[arg-type]
            quality=quality,  # type: ignore[arg-type]
            formula=spec.formula,
            normalization_method=spec.normalization_method,
            normalized_value=normalized,
        )

    def _to_schema(self, vector: FeatureVector) -> FeatureVectorSchema:
        return FeatureVectorSchema(
            id=self._vector_id(vector),
            entity_type=vector.entity_type,
            entity_id=vector.entity_id,
            entity_label=vector.entity_label,
            capture_id=vector.capture_id,
            feature_version=vector.feature_version,
            generated_at=vector.generated_at,
            feature_count=len(vector.features),
            available_count=vector.available_count,
            partial_count=vector.partial_count,
            unavailable_count=vector.unavailable_count,
            sources=[
                SourceAvailabilitySchema(name=s.name, available=s.available, detail=s.detail)
                for s in vector.sources
            ],
            features=[
                self._feature_schema(
                    f.name, vector.entity_type, f.value, f.availability, f.quality,
                    f.source, f.detail, f.normalized_value,
                )
                for f in vector.features
            ],
        )

    def _row_to_schema(self, row: FeatureVectorRow) -> FeatureVectorSchema:
        features = []
        for value_row in row.values:
            stored = (
                value_row.value_integer
                if value_row.data_type == "INTEGER"
                else value_row.value_float
                if value_row.data_type == "FLOAT"
                else value_row.value_boolean
                if value_row.data_type == "BOOLEAN"
                else value_row.value_text
            )
            features.append(
                self._feature_schema(
                    value_row.name, value_row.level, stored, value_row.availability,
                    value_row.quality, value_row.source, value_row.detail, value_row.normalized_value,
                )
            )
        return FeatureVectorSchema(
            id=row.id,
            entity_type=row.entity_type,  # type: ignore[arg-type]
            entity_id=row.entity_id,
            entity_label=row.entity_label,
            capture_id=row.capture_id,
            feature_version=row.feature_version,
            generated_at=row.generated_at,
            feature_count=row.feature_count,
            available_count=row.available_count,
            partial_count=row.partial_count,
            unavailable_count=row.unavailable_count,
            sources=[SourceAvailabilitySchema(**s) for s in json.loads(row.sources_json or "[]")],
            features=features,
        )


feature_service = FeatureExtractionService()
