"""Pydantic schemas for Layer 07 Drift Detection.

API request and response models for deterministic drift evaluation, feature deviations,
history inspection, and threshold configuration.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DriftThresholdConfigSchema(BaseModel):
    """Configuration schema for drift detection thresholds."""

    config_version: str = "1.0"
    z_score_low: float = 2.0
    z_score_moderate: float = 3.0
    z_score_high: float = 4.0
    enable_percentile_check: bool = True
    iqr_multiplier: float = 1.5
    unseen_category_severity: str = "MODERATE"
    boolean_flip_severity: str = "LOW"
    category_rare_threshold: float = 0.05
    minimum_baseline_samples: int = 3


class DriftAnalyzeRequestSchema(BaseModel):
    """Request payload to trigger drift analysis on a session."""

    session_id: str = Field(..., description="Target session ID to evaluate for drift")
    baseline_id: Optional[str] = Field(None, description="Optional baseline ID; defaults to active reference")
    config_override: Optional[DriftThresholdConfigSchema] = Field(None, description="Optional threshold configuration override")


class FeatureDriftSchema(BaseModel):
    """Detailed drift evaluation for an individual protocol feature."""

    feature_name: str
    display_name: str
    category: str
    data_type: str
    unit: Optional[str] = None
    current_value: Any = None
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    baseline_median: Optional[float] = None
    baseline_distribution: Optional[Dict[str, Any]] = None
    deviation: Optional[float] = None
    z_score: Optional[float] = None
    comparison_method: str
    drift_detected: bool
    severity: str
    reason: str


class DriftAnalysisSummarySchema(BaseModel):
    """Summary record for historical drift analysis listings."""

    id: str
    session_id: str
    baseline_id: str
    baseline_version: int
    feature_version: str
    configuration_version: str
    status: str
    severity: str
    features_analyzed: int
    features_drifting: int
    analyzed_at: str


class DriftAnalysisSchema(DriftAnalysisSummarySchema):
    """Full drift analysis record including all feature comparison details."""

    feature_results: List[FeatureDriftSchema] = Field(default_factory=list)
    thresholds_used: Dict[str, Any] = Field(default_factory=dict)


class DriftEngineStatusSchema(BaseModel):
    """Live operational status of the drift detection engine."""

    state: str = Field(..., description="Engine state: NOT INITIALIZED, READY, ANALYZING, AVAILABLE, ERROR, INSUFFICIENT DATA")
    active_baseline_id: Optional[str] = None
    active_baseline_name: Optional[str] = None
    total_analyses: int = 0
    sessions_evaluated: int = 0
    drifting_sessions_count: int = 0
    feature_schema_version: str = "1.0"
    configuration_version: str = "1.0"
