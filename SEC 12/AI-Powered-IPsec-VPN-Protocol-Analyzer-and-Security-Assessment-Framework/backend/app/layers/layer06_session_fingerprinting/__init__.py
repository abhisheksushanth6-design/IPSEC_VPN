"""Layer 06 — Session Fingerprinting & Baseline Profiling.

Builds behavioral fingerprints and reference baselines from observed IPsec VPN
session features.

The layer models and summarizes reference distributions; it does NOT judge.
There is no drift detection, no anomaly detection, no vulnerability analysis,
and no risk scoring here. Those belong strictly to later layers.
"""

from .fingerprint import (
    FINGERPRINT_FEATURE_CATEGORIES,
    build_session_fingerprint,
    canonicalize_feature_value,
    generate_fingerprint_signature,
)
from .models import (
    DEFAULT_MINIMUM_SESSIONS,
    LAYER_NAME,
    LAYER_NUMBER,
    BaselineCoverage,
    BaselineDataQuality,
    BaselineFeatureProfile,
    BaselineProfile,
    BaselineStatus,
    BooleanStatistics,
    CategoricalStatistics,
    FingerprintFeature,
    NumericStatistics,
    SessionFingerprint,
)
from .service import build_baseline_profile
from .statistics import (
    build_feature_profile,
    compute_boolean_statistics,
    compute_categorical_statistics,
    compute_numeric_statistics,
)
from .validators import (
    BaselineValidationError,
    audit_baseline_coverage,
    audit_baseline_data_quality,
    check_minimum_observations,
    validate_feature_version_compatibility,
)

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "DEFAULT_MINIMUM_SESSIONS",
    "BaselineStatus",
    "FingerprintFeature",
    "SessionFingerprint",
    "NumericStatistics",
    "CategoricalStatistics",
    "BooleanStatistics",
    "BaselineFeatureProfile",
    "BaselineCoverage",
    "BaselineDataQuality",
    "BaselineProfile",
    "FINGERPRINT_FEATURE_CATEGORIES",
    "canonicalize_feature_value",
    "generate_fingerprint_signature",
    "build_session_fingerprint",
    "compute_numeric_statistics",
    "compute_categorical_statistics",
    "compute_boolean_statistics",
    "build_feature_profile",
    "BaselineValidationError",
    "validate_feature_version_compatibility",
    "check_minimum_observations",
    "audit_baseline_data_quality",
    "audit_baseline_coverage",
    "build_baseline_profile",
]
