"""Layer 06 — Session Fingerprinting & Baseline Profiling domain models.

Plain dataclasses with no web-framework dependencies.
Calculates and models factual descriptive session fingerprints and baseline
reference distributions.

STRICT DESIGN RULE:
The fingerprint and baseline profile are factual descriptive representations
of observed behavior. They are NOT anomaly detectors, drift detectors,
vulnerability scanners, or risk scorers. No security judgments or verdict
labels are generated here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Union

LAYER_NUMBER = 6
LAYER_NAME = "Session Fingerprinting & Baseline Profiling"
DEFAULT_MINIMUM_SESSIONS = 3

BaselineStatus = Literal[
    "NOT INITIALIZED",
    "READY",
    "COLLECTING",
    "BUILDING",
    "AVAILABLE",
    "ERROR",
    "STALE",
    "INVALID",
    "INSUFFICIENT_DATA",
]


@dataclass(frozen=True)
class FingerprintFeature:
    """One factual feature preserved in a session fingerprint."""

    name: str
    display_name: str
    category: str
    data_type: str
    unit: Optional[str]
    value: Union[int, float, bool, str, None]
    availability: str  # AVAILABLE / PARTIAL / UNAVAILABLE
    quality: str  # COMPLETE / PARTIAL / MISSING_SOURCE_DATA
    source: str


@dataclass
class SessionFingerprint:
    """Stable behavioral representation of an observed IPsec session.
    
    Derived from Section 8 session feature vector facts. Identity is
    deterministic and cryptographically hashed from the canonical feature facts.
    """

    fingerprint_id: str
    session_id: str
    capture_id: str
    feature_version: str
    fingerprint_signature: str
    created_at: str
    features: List[FingerprintFeature] = field(default_factory=list)
    feature_count: int = 0

    def get_feature(self, name: str) -> Optional[FingerprintFeature]:
        for f in self.features:
            if f.name == name:
                return f
        return None

    @property
    def available_features(self) -> List[FingerprintFeature]:
        return [f for f in self.features if f.availability == "AVAILABLE"]


@dataclass
class NumericStatistics:
    """Factual descriptive statistics for a numerical feature."""

    count: int
    mean: float
    median: float
    min: float
    max: float
    std_dev: float
    p25: float
    p50: float
    p75: float
    p95: float


@dataclass
class CategoricalStatistics:
    """Factual descriptive statistics for a categorical feature."""

    count: int
    unique_count: int
    frequencies: Dict[str, int]
    relative_frequencies: Dict[str, float]
    mode: Optional[str]


@dataclass
class BooleanStatistics:
    """Factual descriptive statistics for a boolean feature."""

    count: int
    true_count: int
    false_count: int
    true_ratio: float
    false_ratio: float


@dataclass
class BaselineFeatureProfile:
    """Statistical reference profile for a single feature across baseline sessions."""

    name: str
    display_name: str
    category: str
    data_type: str
    unit: Optional[str]
    numeric_stats: Optional[NumericStatistics] = None
    categorical_stats: Optional[CategoricalStatistics] = None
    boolean_stats: Optional[BooleanStatistics] = None
    total_samples: int = 0
    available_samples: int = 0
    missing_samples: int = 0
    completeness_ratio: float = 1.0


@dataclass
class BaselineCoverage:
    """Factual coverage audit of the baseline dataset."""

    sessions_included: List[str]
    total_sessions: int
    features_profiled: int
    features_available: int
    features_missing: int
    feature_completeness: float
    first_observation: Optional[str]
    last_observation: Optional[str]


@dataclass
class BaselineDataQuality:
    """Factual data quality assessment of baseline sessions."""

    complete_sessions: int
    partial_sessions: int
    missing_data_features: int
    invalid_records: int
    quality_rating: str  # HIGH / SUFFICIENT / DEGRADED / INSUFFICIENT


@dataclass
class BaselineProfile:
    """Statistical baseline representing observed normal IPsec session behavior."""

    baseline_id: str
    name: str
    description: Optional[str]
    version: int
    feature_version: str
    status: BaselineStatus
    is_active: bool
    session_count: int
    feature_count: int
    created_at: str
    updated_at: str
    first_observation: Optional[str]
    last_observation: Optional[str]
    minimum_sessions: int
    features: List[BaselineFeatureProfile] = field(default_factory=list)
    coverage: Optional[BaselineCoverage] = None
    data_quality: Optional[BaselineDataQuality] = None

    def get_feature(self, name: str) -> Optional[BaselineFeatureProfile]:
        for f in self.features:
            if f.name == name:
                return f
        return None
