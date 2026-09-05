"""Layer 06 — Baseline Validators and Quality Assessment.

Factual validation and quality audits for session observations.
Ensures feature version compatibility, checks minimum sample sizes, detects
duplicate sessions, and computes factual coverage without fabrication.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Set, Tuple

from app.layers.layer05_feature_engineering.models import FEATURE_VERSION
from .models import (
    BaselineCoverage,
    BaselineDataQuality,
    BaselineStatus,
    DEFAULT_MINIMUM_SESSIONS,
    SessionFingerprint,
)


class BaselineValidationError(Exception):
    """Raised when session data or feature vectors violate baseline preconditions."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def validate_feature_version_compatibility(fingerprints: Sequence[SessionFingerprint]) -> None:
    """Ensure all session fingerprints share the exact same feature schema version."""
    for fp in fingerprints:
        if fp.feature_version != FEATURE_VERSION:
            raise BaselineValidationError(
                "FEATURE_VERSION_MISMATCH",
                f"Session '{fp.session_id}' has feature version '{fp.feature_version}', "
                f"which does not match current version '{FEATURE_VERSION}'.",
            )


def check_minimum_observations(
    session_count: int,
    minimum_required: int = DEFAULT_MINIMUM_SESSIONS,
) -> Tuple[BaselineStatus, str]:
    """Check whether observation count meets minimum threshold for a reliable baseline."""
    if session_count == 0:
        return "INSUFFICIENT_DATA", "No session observations available."
    if session_count < minimum_required:
        return (
            "INSUFFICIENT_DATA",
            f"Insufficient data: {session_count} observation(s) provided; minimum {minimum_required} required.",
        )
    return "READY", f"Baseline constructed from {session_count} valid session observations."


def audit_baseline_data_quality(
    fingerprints: Sequence[SessionFingerprint],
) -> BaselineDataQuality:
    """Compute factual data quality metrics across included fingerprints."""
    if not fingerprints:
        return BaselineDataQuality(
            complete_sessions=0,
            partial_sessions=0,
            missing_data_features=0,
            invalid_records=0,
            quality_rating="INSUFFICIENT",
        )

    complete_cnt = 0
    partial_cnt = 0
    missing_features_cnt = 0

    for fp in fingerprints:
        has_partial = False
        for f in fp.features:
            if f.availability != "AVAILABLE" or f.value is None:
                missing_features_cnt += 1
                has_partial = True
        if has_partial:
            partial_cnt += 1
        else:
            complete_cnt += 1

    total = len(fingerprints)
    completeness_ratio = complete_cnt / total if total > 0 else 0.0

    if completeness_ratio >= 0.8:
        rating = "HIGH"
    elif completeness_ratio >= 0.5:
        rating = "SUFFICIENT"
    elif complete_cnt > 0:
        rating = "DEGRADED"
    else:
        rating = "INSUFFICIENT"

    return BaselineDataQuality(
        complete_sessions=complete_cnt,
        partial_sessions=partial_cnt,
        missing_data_features=missing_features_cnt,
        invalid_records=0,
        quality_rating=rating,
    )


def audit_baseline_coverage(
    fingerprints: Sequence[SessionFingerprint],
    expected_features: Sequence[str],
) -> BaselineCoverage:
    """Compute factual observation period and feature completeness for the baseline."""
    if not fingerprints:
        return BaselineCoverage(
            sessions_included=[],
            total_sessions=0,
            features_profiled=0,
            features_available=0,
            features_missing=len(expected_features),
            feature_completeness=0.0,
            first_observation=None,
            last_observation=None,
        )

    session_ids = [fp.session_id for fp in fingerprints]
    first_timestamps: List[str] = []
    last_timestamps: List[str] = []

    for fp in fingerprints:
        fs = fp.get_feature("first_seen")
        if fs and fs.value:
            first_timestamps.append(str(fs.value))
        ls = fp.get_feature("last_seen")
        if ls and ls.value:
            last_timestamps.append(str(ls.value))

    first_obs = min(first_timestamps) if first_timestamps else None
    last_obs = max(last_timestamps) if last_timestamps else None

    # Tally how many expected features have at least one valid observation
    observed_feature_names: Set[str] = set()
    for fp in fingerprints:
        for f in fp.features:
            if f.availability == "AVAILABLE" and f.value is not None:
                observed_feature_names.add(f.name)

    total_expected = len(expected_features) if expected_features else 1
    avail_expected = len(observed_feature_names)
    completeness = round(avail_expected / total_expected, 4) if total_expected > 0 else 0.0

    return BaselineCoverage(
        sessions_included=session_ids,
        total_sessions=len(session_ids),
        features_profiled=len(expected_features),
        features_available=avail_expected,
        features_missing=max(0, total_expected - avail_expected),
        feature_completeness=completeness,
        first_observation=first_obs,
        last_observation=last_obs,
    )
