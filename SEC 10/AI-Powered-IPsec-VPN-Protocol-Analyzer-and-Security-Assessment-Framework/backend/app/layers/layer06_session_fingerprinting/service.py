"""Layer 06 — Core Baseline Profile Builder Service.

Coordinates session fingerprint compilation, feature validation, statistical
aggregation, and baseline profile assembly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Sequence

from app.layers.layer05_feature_engineering.models import FEATURE_VERSION
from app.layers.layer05_feature_engineering.registry import definitions_for
from .fingerprint import build_session_fingerprint
from .models import (
    BaselineCoverage,
    BaselineDataQuality,
    BaselineFeatureProfile,
    BaselineProfile,
    BaselineStatus,
    DEFAULT_MINIMUM_SESSIONS,
    SessionFingerprint,
)
from .statistics import build_feature_profile
from .validators import (
    audit_baseline_coverage,
    audit_baseline_data_quality,
    check_minimum_observations,
    validate_feature_version_compatibility,
)


def build_baseline_profile(
    baseline_id: str,
    name: str,
    fingerprints: Sequence[SessionFingerprint],
    description: Optional[str] = None,
    version: int = 1,
    minimum_sessions: int = DEFAULT_MINIMUM_SESSIONS,
    is_active: bool = False,
) -> BaselineProfile:
    """Compile a complete BaselineProfile from a collection of SessionFingerprints.
    
    Adheres strictly to the architectural constraints:
    - Descriptive factual statistics only.
    - Status reflects actual sample size (READY vs INSUFFICIENT_DATA).
    - Preserves feature lineage and metadata.
    """
    validate_feature_version_compatibility(fingerprints)
    status, status_reason = check_minimum_observations(len(fingerprints), minimum_sessions)

    now_iso = datetime.now(timezone.utc).isoformat()
    session_definitions = definitions_for("SESSION")
    feature_names = [d.name for d in session_definitions]

    feature_profiles: List[BaselineFeatureProfile] = []
    for f_name in feature_names:
        prof = build_feature_profile(f_name, fingerprints)
        if prof is not None:
            feature_profiles.append(prof)

    coverage = audit_baseline_coverage(fingerprints, feature_names)
    data_quality = audit_baseline_data_quality(fingerprints)

    return BaselineProfile(
        baseline_id=baseline_id,
        name=name,
        description=description,
        version=version,
        feature_version=FEATURE_VERSION,
        status=status,
        is_active=is_active,
        session_count=len(fingerprints),
        feature_count=len(feature_profiles),
        created_at=now_iso,
        updated_at=now_iso,
        first_observation=coverage.first_observation,
        last_observation=coverage.last_observation,
        minimum_sessions=minimum_sessions,
        features=feature_profiles,
        coverage=coverage,
        data_quality=data_quality,
    )
