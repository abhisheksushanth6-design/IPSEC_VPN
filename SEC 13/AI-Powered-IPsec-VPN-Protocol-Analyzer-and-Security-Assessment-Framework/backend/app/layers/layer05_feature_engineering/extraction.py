"""Layer 05 — feature extraction.

    input entity -> validate source data -> calculate -> validate output -> vector

Extraction is deterministic: the same entity and the same feature version
produce the same values. The only clock reading is ``generated_at``, which is
metadata about the extraction run and never an input to a calculation.

Every vector carries the full registered feature set for its level. A feature
that no calculator reached is emitted UNAVAILABLE rather than omitted, so a
consumer can tell "not calculated" from "not in this schema" without holding
a copy of the registry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Sequence

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

from .calculators import (
    SARecord,
    SessionRecord,
    calculate_packet_features,
    calculate_sa_features,
    calculate_session_features,
)
from .models import (
    FEATURE_VERSION,
    EntityType,
    FeatureValue,
    FeatureVector,
    SourceAvailability,
)
from .registry import definitions_for
from .validation import FeatureSet


class FeatureExtractionError(Exception):
    """Raised when the source data cannot support extraction at all."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _generated_at() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _complete(level: str, values: list[FeatureValue]) -> list[FeatureValue]:
    """Order by the registry and fill anything a calculator did not emit."""
    by_name = {value.name: value for value in values}
    ordered: list[FeatureValue] = []
    for spec in definitions_for(level):
        existing = by_name.pop(spec.name, None)
        ordered.append(
            existing
            if existing is not None
            else FeatureValue(
                name=spec.name,
                value=None,
                availability="UNAVAILABLE",
                quality="MISSING_SOURCE_DATA",
                source=spec.source,
                detail="No calculator produced this feature for this entity.",
                normalized_value=None,
                normalization_method=spec.normalization_method,
            )
        )
    if by_name:  # pragma: no cover - guarded by FeatureSet, kept as a backstop
        raise FeatureExtractionError(
            "FEATURE_VALIDATION_FAILED",
            f"Unregistered feature(s) emitted at level {level}: {', '.join(sorted(by_name))}.",
        )
    return ordered


def build_vector(
    *,
    entity_type: EntityType,
    entity_id: str,
    entity_label: str,
    capture_id: str,
    feature_set: FeatureSet,
    sources: Sequence[SourceAvailability],
) -> FeatureVector:
    return FeatureVector(
        entity_id=entity_id,
        entity_type=entity_type,
        entity_label=entity_label,
        capture_id=capture_id,
        feature_version=FEATURE_VERSION,
        generated_at=_generated_at(),
        features=_complete(feature_set.level, feature_set.values),
        sources=list(sources),
    )


# ----- entry points ---------------------------------------------------------- #


def extract_packet(
    packet: PacketAnalysisResult,
    capture_id: str,
    *,
    session_source: Optional[str] = None,
    session_id: Optional[str] = None,
) -> FeatureVector:
    """Extract packet-level features from an already decoded packet."""
    sources = [
        SourceAvailability(
            name="Decoded packet",
            available=True,
            detail=f"Packet #{packet.number}, parse status {packet.parse_status}.",
        ),
        SourceAvailability(
            name="IPsec layer",
            available=packet.ipsec is not None,
            detail=f"IPsec type {packet.ipsec.type}." if packet.ipsec else "No IPsec layer was decoded.",
        ),
        SourceAvailability(
            name="Session association",
            available=session_source is not None,
            detail=f"Packet belongs to session {session_id}."
            if session_id
            else "The packet is not associated with a discovered session; direction is unavailable.",
        ),
    ]
    feature_set = calculate_packet_features(
        packet, session_source=session_source, session_id=session_id
    )
    return build_vector(
        entity_type="PACKET",
        entity_id=packet.id,
        entity_label=f"Packet #{packet.number} — {packet.source} → {packet.destination}",
        capture_id=capture_id,
        feature_set=feature_set,
        sources=sources,
    )


def extract_session(
    session: SessionRecord,
    capture_id: str,
    packets: Optional[Sequence[PacketAnalysisResult]] = None,
) -> FeatureVector:
    """Extract session-level features from a stored session record."""
    if session.packet_count < 0 or session.byte_count < 0:
        raise FeatureExtractionError(
            "SOURCE_DATA_INCOMPLETE", "The session record carries negative counts."
        )
    sources = [
        SourceAvailability(
            name="Session record",
            available=True,
            detail=f"{session.packet_count} packet(s), state {session.state}.",
        ),
        SourceAvailability(
            name="Session packets",
            available=packets is not None,
            detail=f"{len(packets)} decoded packet(s) available."
            if packets is not None
            else "The originating capture is not loaded; distribution, timing and directional "
            "features cannot be calculated.",
        ),
        SourceAvailability(
            name="IKE observations",
            available=session.ike_packets > 0,
            detail=f"{session.ike_packets} IKE message(s) observed."
            if session.ike_packets
            else "No IKE messages were observed in this session.",
        ),
    ]
    return build_vector(
        entity_type="SESSION",
        entity_id=session.id,
        entity_label=f"{session.source} ↔ {session.destination}",
        capture_id=capture_id,
        feature_set=calculate_session_features(session, packets),
        sources=sources,
    )


def extract_sa(sa: SARecord, capture_id: str) -> FeatureVector:
    """Extract SA-level features from a stored Security Association."""
    if sa.packet_count < 0 or sa.byte_count < 0:
        raise FeatureExtractionError(
            "SOURCE_DATA_INCOMPLETE", "The SA record carries negative counts."
        )
    sources = [
        SourceAvailability(
            name="SA record",
            available=True,
            detail=f"{sa.type} SA in state {sa.state}, {sa.packet_count} packet(s).",
        ),
        SourceAvailability(
            name="Lifecycle events",
            available=bool(sa.events),
            detail=f"{len(sa.events)} event(s) recorded."
            if sa.events
            else "No lifecycle events are recorded for this SA.",
        ),
    ]
    label = f"{sa.type} SA — {sa.initiator} → {sa.responder}"
    if sa.spi_label:
        label = f"{label} ({sa.spi_label})"
    return build_vector(
        entity_type="SA",
        entity_id=sa.id,
        entity_label=label,
        capture_id=capture_id,
        feature_set=calculate_sa_features(sa),
        sources=sources,
    )
