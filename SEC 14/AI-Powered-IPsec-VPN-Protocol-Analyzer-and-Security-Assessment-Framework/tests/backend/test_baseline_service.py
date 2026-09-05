"""Tests for Layer 06 Baseline Profile Builder and Validation."""

from __future__ import annotations

import pytest

from app.layers.layer06_session_fingerprinting.fingerprint import build_session_fingerprint
from app.layers.layer06_session_fingerprinting.models import SessionFingerprint
from app.layers.layer06_session_fingerprinting.service import build_baseline_profile
from app.layers.layer06_session_fingerprinting.validators import BaselineValidationError
from test_fingerprint import _make_sample_session_vector


def test_build_baseline_profile_with_sufficient_data() -> None:
    fps = [
        build_session_fingerprint(
            _make_sample_session_vector(
                session_id=f"sess-0{i}",
                packet_count=10 * i,
                byte_count=5000 * i,
            ),
            "cap-1",
        )
        for i in range(1, 6)
    ]

    profile = build_baseline_profile(
        baseline_id="BL-TEST-01",
        name="Production Reference Baseline",
        fingerprints=fps,
        minimum_sessions=3,
    )

    assert profile.status == "READY"
    assert profile.session_count == 5
    assert profile.version == 1
    assert profile.feature_version == "1.0"
    assert profile.coverage is not None
    assert profile.coverage.total_sessions == 5
    assert profile.data_quality is not None
    assert profile.data_quality.quality_rating in ("HIGH", "SUFFICIENT")

    pkt_feat = profile.get_feature("packet_count")
    assert pkt_feat is not None
    assert pkt_feat.numeric_stats is not None
    assert pkt_feat.numeric_stats.min == 10.0
    assert pkt_feat.numeric_stats.max == 50.0
    assert pkt_feat.numeric_stats.mean == 30.0


def test_build_baseline_profile_insufficient_data() -> None:
    fps = [
        build_session_fingerprint(
            _make_sample_session_vector(session_id="sess-solo", packet_count=10),
            "cap-1",
        )
    ]

    profile = build_baseline_profile(
        baseline_id="BL-TEST-SOLO",
        name="Single Session Profile",
        fingerprints=fps,
        minimum_sessions=3,
    )

    assert profile.status == "INSUFFICIENT_DATA"
    assert profile.session_count == 1


def test_feature_version_mismatch_rejected() -> None:
    fp1 = build_session_fingerprint(_make_sample_session_vector(session_id="s1"), "cap-1")
    fp2 = SessionFingerprint(
        fingerprint_id="fp-bad",
        session_id="s2",
        capture_id="cap-1",
        feature_version="9.9",
        fingerprint_signature="sig",
        created_at="2026-09-03T10:00:00Z",
    )

    with pytest.raises(BaselineValidationError, match="does not match current version"):
        build_baseline_profile(
            baseline_id="BL-FAIL",
            name="Incompatible Baseline",
            fingerprints=[fp1, fp2],
        )
