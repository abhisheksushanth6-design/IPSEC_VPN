"""Tests for Layer 06 Session Fingerprinting."""

from __future__ import annotations

import pytest

from app.layers.layer05_feature_engineering.models import (
    FEATURE_VERSION,
    FeatureValue,
    FeatureVector,
    SourceAvailability,
)
from app.layers.layer06_session_fingerprinting.fingerprint import (
    build_session_fingerprint,
    canonicalize_feature_value,
    generate_fingerprint_signature,
)


def _make_sample_session_vector(
    session_id: str = "sess-test-01",
    capture_id: str = "cap-test-01",
    packet_count: int = 100,
    byte_count: int = 50000,
    version: str = FEATURE_VERSION,
) -> FeatureVector:
    features = [
        FeatureValue(
            name="packet_count",
            value=packet_count,
            availability="AVAILABLE",
            quality="COMPLETE",
            source="Test source",
        ),
        FeatureValue(
            name="byte_count",
            value=byte_count,
            availability="AVAILABLE",
            quality="COMPLETE",
            source="Test source",
        ),
        FeatureValue(
            name="session_state",
            value="ESTABLISHED",
            availability="AVAILABLE",
            quality="COMPLETE",
            source="Test source",
        ),
        FeatureValue(
            name="average_packet_size",
            value=byte_count / packet_count if packet_count else 0.0,
            availability="AVAILABLE",
            quality="COMPLETE",
            source="Test source",
        ),
        FeatureValue(
            name="nat_traversal_observed",
            value=False,
            availability="AVAILABLE",
            quality="COMPLETE",
            source="Test source",
        ),
    ]
    sources = [SourceAvailability(name="Test Session", available=True, detail="OK")]
    return FeatureVector(
        entity_id=session_id,
        entity_type="SESSION",
        entity_label=f"Session {session_id}",
        capture_id=capture_id,
        feature_version=version,
        generated_at="2026-09-03T10:00:00Z",
        features=features,
        sources=sources,
    )


def test_fingerprint_deterministic_signature() -> None:
    vec1 = _make_sample_session_vector(packet_count=50, byte_count=25000)
    vec2 = _make_sample_session_vector(packet_count=50, byte_count=25000)

    fp1 = build_session_fingerprint(vec1, "cap-test-01")
    fp2 = build_session_fingerprint(vec2, "cap-test-01")

    assert fp1.fingerprint_signature == fp2.fingerprint_signature
    assert fp1.fingerprint_id == fp2.fingerprint_id
    assert fp1.feature_version == FEATURE_VERSION


def test_fingerprint_changes_on_feature_change() -> None:
    vec1 = _make_sample_session_vector(packet_count=50, byte_count=25000)
    vec2 = _make_sample_session_vector(packet_count=51, byte_count=25000)

    fp1 = build_session_fingerprint(vec1, "cap-test-01")
    fp2 = build_session_fingerprint(vec2, "cap-test-01")

    assert fp1.fingerprint_signature != fp2.fingerprint_signature
    assert fp1.fingerprint_id != fp2.fingerprint_id


def test_fingerprint_rejects_non_session_entity() -> None:
    vec = _make_sample_session_vector()
    vec.entity_type = "PACKET"

    with pytest.raises(ValueError, match="Expected 'SESSION'"):
        build_session_fingerprint(vec, "cap-test-01")


def test_fingerprint_rejects_incompatible_version() -> None:
    vec = _make_sample_session_vector(version="9.9")

    with pytest.raises(ValueError, match="Feature version mismatch"):
        build_session_fingerprint(vec, "cap-test-01")


def test_canonicalize_feature_value() -> None:
    assert canonicalize_feature_value(None) is None
    assert canonicalize_feature_value(True) is True
    assert canonicalize_feature_value(False) is False
    assert canonicalize_feature_value(42) == 42
    assert canonicalize_feature_value(3.1415926535) == 3.141593
    assert canonicalize_feature_value("IKEv2") == "IKEv2"
