"""Tests for Layer 07 precondition and schema compatibility validation."""

import pytest
from app.layers.layer07_drift_detection.validators import (
    DriftPreconditionError,
    FeatureVersionMismatchError,
    validate_baseline_for_drift,
    validate_feature_version_compatibility,
    validate_session_vector_for_drift,
)


class MockBaseline:
    def __init__(self, status="READY", session_count=5, minimum_sessions=3, feature_version="1.0"):
        self.status = status
        self.session_count = session_count
        self.minimum_sessions = minimum_sessions
        self.feature_version = feature_version


class MockVector:
    def __init__(self, feature_version="1.0", features=None):
        self.feature_version = feature_version
        self.features = features if features is not None else ["feat1", "feat2"]


def test_feature_version_compatibility_pass():
    """Matching versions pass without exception."""
    validate_feature_version_compatibility("1.0", "1.0")


def test_feature_version_compatibility_mismatch():
    """Mismatched versions raise FeatureVersionMismatchError."""
    with pytest.raises(FeatureVersionMismatchError) as exc_info:
        validate_feature_version_compatibility("1.1", "1.0")
    assert "FEATURE_VERSION_MISMATCH" in str(exc_info.value)


def test_missing_baseline_raises_error():
    """None baseline raises DriftPreconditionError."""
    with pytest.raises(DriftPreconditionError) as exc_info:
        validate_baseline_for_drift(None)
    assert "A valid reference baseline profile is required" in str(exc_info.value)


def test_unready_baseline_status_raises_error():
    """Baseline with status BUILDING raises DriftPreconditionError."""
    b = MockBaseline(status="BUILDING")
    with pytest.raises(DriftPreconditionError) as exc_info:
        validate_baseline_for_drift(b)
    assert "expected READY or AVAILABLE" in str(exc_info.value)


def test_active_baseline_status_passes():
    """Baseline with canonical status ACTIVE and is_active=1 passes validation."""
    b = MockBaseline(status="ACTIVE", session_count=5, minimum_sessions=3)
    # Must pass without raising DriftPreconditionError
    validate_baseline_for_drift(b)


def test_insufficient_baseline_samples_raises_error():
    """Baseline with fewer than minimum sessions raises DriftPreconditionError."""
    b = MockBaseline(session_count=2, minimum_sessions=3)
    with pytest.raises(DriftPreconditionError) as exc_info:
        validate_baseline_for_drift(b)
    assert "INSUFFICIENT DATA" in str(exc_info.value)


def test_empty_session_vector_raises_error():
    """Empty or None session vector raises DriftPreconditionError."""
    with pytest.raises(DriftPreconditionError):
        validate_session_vector_for_drift(None)

    v = MockVector(features=[])
    with pytest.raises(DriftPreconditionError):
        validate_session_vector_for_drift(v)
