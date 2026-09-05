"""Layer 07 — Security Drift Detection domain models and dataclasses.

Defines deterministic, explainable data structures for comparing observed
session feature vectors against established reference baseline distributions.
No AI/ML anomaly scores, vulnerability labels, or threat classifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DriftSeverity(str, Enum):
    """Magnitude of behavioral deviation relative to baseline.

    NOTE: Indicates behavioral change only; does NOT represent security risk.
    """

    NONE = "NONE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class DriftStatus(str, Enum):
    """Overall session drift classification status."""

    WITHIN_BASELINE = "WITHIN BASELINE"
    DRIFT_DETECTED = "DRIFT DETECTED"
    ANALYSIS_UNAVAILABLE = "ANALYSIS UNAVAILABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT DATA"
    ERROR = "ERROR"


class ComparisonMethod(str, Enum):
    """Documented statistical comparison method used for feature evaluation."""

    Z_SCORE = "Z-Score (Gaussian Standard Deviation)"
    ZERO_VARIANCE = "Zero-Variance Exact Match"
    PERCENTILE_RANGE = "Interquartile Percentile Range (IQR)"
    CATEGORICAL_FREQUENCY = "Categorical Distribution Frequency"
    BOOLEAN_RATIO = "Boolean State Probability"
    BASELINE_UNAVAILABLE = "Baseline Reference Unavailable"
    FEATURE_UNAVAILABLE = "Feature Observation Unavailable"


@dataclass
class FeatureDriftResult:
    """Detailed drift evaluation for a single protocol feature."""

    feature_name: str
    display_name: str
    category: str
    data_type: str
    unit: Optional[str]
    current_value: Any
    baseline_mean: Optional[float]
    baseline_std: Optional[float]
    baseline_median: Optional[float]
    baseline_distribution: Optional[Dict[str, Any]]
    deviation: Optional[float]
    z_score: Optional[float]
    comparison_method: ComparisonMethod
    drift_detected: bool
    severity: DriftSeverity
    reason: str


@dataclass
class SessionDriftResult:
    """Full session-level drift evaluation aggregating feature results."""

    analysis_id: str
    session_id: str
    baseline_id: str
    baseline_version: int
    feature_version: str
    configuration_version: str
    analyzed_at: str
    status: DriftStatus
    severity: DriftSeverity
    features_analyzed: int
    features_drifting: int
    feature_results: List[FeatureDriftResult] = field(default_factory=list)
    thresholds_used: Dict[str, Any] = field(default_factory=dict)

    def get_feature(self, name: str) -> Optional[FeatureDriftResult]:
        """Lookup feature drift result by exact machine name."""
        for feat in self.feature_results:
            if feat.feature_name == name:
                return feat
        return None


@dataclass
class DriftEvidence:
    """Audit evidence linking feature observation to baseline thresholds."""

    feature_name: str
    observed_value: Any
    baseline_reference: str
    comparison_method: str
    threshold_applied: str
    result: str


@dataclass
class DriftLineage:
    """Traceability mapping linking drift evaluation to contributing sessions and baselines."""

    analysis_id: str
    session_id: str
    baseline_id: str
    baseline_version: int
    contributing_baseline_sessions: List[str]
    feature_version: str
    configuration_version: str
