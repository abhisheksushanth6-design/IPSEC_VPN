"""Validation rules and precondition checks for Layer 07 Drift Detection.

Enforces feature schema compatibility, baseline availability, and observation thresholds.
"""

from __future__ import annotations

from typing import Any, Optional


class DriftPreconditionError(ValueError):
    """Raised when an analysis precondition is unmet."""


class FeatureVersionMismatchError(DriftPreconditionError):
    """Raised when session and baseline feature schema versions differ."""


def validate_feature_version_compatibility(session_version: str, baseline_version: str) -> None:
    """Verify that current session feature schema version matches baseline profile version."""
    if session_version != baseline_version:
        raise FeatureVersionMismatchError(
            f"FEATURE_VERSION_MISMATCH: Current session feature version '{session_version}' "
            f"is incompatible with baseline feature version '{baseline_version}'."
        )


def validate_baseline_for_drift(baseline: Optional[Any], minimum_sessions: int = 3) -> None:
    """Verify baseline exists, is operational, and has sufficient observations."""
    if baseline is None:
        raise DriftPreconditionError(
            "DRIFT ANALYSIS UNAVAILABLE: A valid reference baseline profile is required."
        )

    # Status check
    status = getattr(baseline, "status", "")
    if status not in ("READY", "AVAILABLE", "OPERATIONAL"):
        raise DriftPreconditionError(
            f"DRIFT ANALYSIS UNAVAILABLE: Baseline profile status is '{status}', expected READY or AVAILABLE."
        )

    # Observation sufficiency check
    session_count = getattr(baseline, "session_count", 0)
    min_required = max(getattr(baseline, "minimum_sessions", minimum_sessions), minimum_sessions)
    if session_count < min_required:
        raise DriftPreconditionError(
            f"INSUFFICIENT DATA: Baseline profile contains only {session_count} session observations "
            f"(minimum {min_required} required for valid statistical comparison)."
        )


def validate_session_vector_for_drift(feature_vector: Optional[Any]) -> None:
    """Verify session feature vector exists and contains extracted feature values."""
    if feature_vector is None:
        raise DriftPreconditionError(
            "DRIFT ANALYSIS UNAVAILABLE: Session feature vector is unavailable for the target session."
        )

    features = getattr(feature_vector, "features", [])
    if not features:
        raise DriftPreconditionError(
            "DRIFT ANALYSIS UNAVAILABLE: Session feature vector contains zero extracted feature observations."
        )
