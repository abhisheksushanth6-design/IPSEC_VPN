"""Tests for Layer 06 Baseline Statistics Engine."""

from __future__ import annotations

import math

from app.layers.layer06_session_fingerprinting.models import (
    FingerprintFeature,
    SessionFingerprint,
)
from app.layers.layer06_session_fingerprinting.statistics import (
    build_feature_profile,
    calculate_percentile,
    compute_boolean_statistics,
    compute_categorical_statistics,
    compute_numeric_statistics,
)


def test_numeric_statistics_multi_sample() -> None:
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    stats = compute_numeric_statistics(values)
    assert stats is not None
    assert stats.count == 5
    assert stats.mean == 30.0
    assert stats.median == 30.0
    assert stats.min == 10.0
    assert stats.max == 50.0
    # Sample std dev of [10, 20, 30, 40, 50] is sqrt(250) ≈ 15.8114
    assert math.isclose(stats.std_dev, 15.8114, rel_tol=1e-3)
    assert stats.p25 == 20.0
    assert stats.p50 == 30.0
    assert stats.p75 == 40.0
    assert stats.p95 == 48.0


def test_numeric_statistics_single_sample() -> None:
    stats = compute_numeric_statistics([42.0])
    assert stats is not None
    assert stats.count == 1
    assert stats.mean == 42.0
    assert stats.median == 42.0
    assert stats.min == 42.0
    assert stats.max == 42.0
    assert stats.std_dev == 0.0


def test_numeric_statistics_zero_variance() -> None:
    stats = compute_numeric_statistics([100.0, 100.0, 100.0, 100.0])
    assert stats is not None
    assert stats.count == 4
    assert stats.mean == 100.0
    assert stats.std_dev == 0.0
    assert stats.min == 100.0
    assert stats.max == 100.0


def test_numeric_statistics_empty_or_invalid() -> None:
    assert compute_numeric_statistics([]) is None
    assert compute_numeric_statistics([None, None]) is None


def test_categorical_statistics() -> None:
    values = ["IKEv2", "IKEv2", "IKEv2", "IKEv1"]
    stats = compute_categorical_statistics(values)
    assert stats is not None
    assert stats.count == 4
    assert stats.unique_count == 2
    assert stats.mode == "IKEv2"
    assert stats.frequencies["IKEv2"] == 3
    assert stats.frequencies["IKEv1"] == 1
    assert stats.relative_frequencies["IKEv2"] == 0.75
    assert stats.relative_frequencies["IKEv1"] == 0.25


def test_boolean_statistics() -> None:
    values = [True, True, True, False]
    stats = compute_boolean_statistics(values)
    assert stats is not None
    assert stats.count == 4
    assert stats.true_count == 3
    assert stats.false_count == 1
    assert stats.true_ratio == 0.75
    assert stats.false_ratio == 0.25


def test_calculate_percentile() -> None:
    sorted_vals = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert calculate_percentile(sorted_vals, 0) == 10.0
    assert calculate_percentile(sorted_vals, 50) == 30.0
    assert calculate_percentile(sorted_vals, 100) == 50.0


def test_build_feature_profile_with_missing_data() -> None:
    fps = [
        SessionFingerprint(
            fingerprint_id=f"fp-0{i}",
            session_id=f"s-0{i}",
            capture_id="cap-1",
            feature_version="1.0",
            fingerprint_signature=f"sig-0{i}",
            created_at="2026-09-03T10:00:00Z",
            features=[
                FingerprintFeature(
                    name="packet_count",
                    display_name="Packet Count",
                    category="TRAFFIC",
                    data_type="INTEGER",
                    unit="packets",
                    value=val,
                    availability="AVAILABLE" if val is not None else "UNAVAILABLE",
                    quality="COMPLETE" if val is not None else "MISSING_SOURCE_DATA",
                    source="Test",
                )
            ],
            feature_count=1,
        )
        for i, val in enumerate([10, 20, None, 40], start=1)
    ]

    profile = build_feature_profile("packet_count", fps)
    assert profile is not None
    assert profile.name == "packet_count"
    assert profile.total_samples == 4
    assert profile.available_samples == 3
    assert profile.missing_samples == 1
    assert profile.completeness_ratio == 0.75
    assert profile.numeric_stats is not None
    assert profile.numeric_stats.count == 3
    assert profile.numeric_stats.min == 10.0
    assert profile.numeric_stats.max == 40.0
