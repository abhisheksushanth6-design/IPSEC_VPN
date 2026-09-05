"""Layer 07 — Security Drift Detection.

Status: IN DEVELOPMENT.

Delivers deterministic, statistical behavioral drift detection comparing
observed IPsec session feature vectors against established reference baselines.
"""

from app.layers.layer07_drift_detection.config import (
    DEFAULT_DRIFT_CONFIG,
    DriftThresholdConfig,
)
from app.layers.layer07_drift_detection.evaluator import DriftEvaluator
from app.layers.layer07_drift_detection.models import (
    ComparisonMethod,
    DriftEvidence,
    DriftLineage,
    DriftSeverity,
    DriftStatus,
    FeatureDriftResult,
    SessionDriftResult,
)
from app.layers.layer07_drift_detection.service import DriftDetectionDomainService
from app.layers.layer07_drift_detection.validators import (
    DriftPreconditionError,
    FeatureVersionMismatchError,
    validate_baseline_for_drift,
    validate_feature_version_compatibility,
    validate_session_vector_for_drift,
)

LAYER_NUMBER = 7
LAYER_NAME = "Security Drift Detection"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "DriftSeverity",
    "DriftStatus",
    "ComparisonMethod",
    "FeatureDriftResult",
    "SessionDriftResult",
    "DriftEvidence",
    "DriftLineage",
    "DriftThresholdConfig",
    "DEFAULT_DRIFT_CONFIG",
    "DriftEvaluator",
    "DriftDetectionDomainService",
    "DriftPreconditionError",
    "FeatureVersionMismatchError",
    "validate_feature_version_compatibility",
    "validate_baseline_for_drift",
    "validate_session_vector_for_drift",
]
