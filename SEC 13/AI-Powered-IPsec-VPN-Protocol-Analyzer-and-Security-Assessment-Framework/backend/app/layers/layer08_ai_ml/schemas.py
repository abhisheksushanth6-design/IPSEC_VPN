"""Pydantic schemas for Layer 08 AI / ML Anomaly Detection Engine.

Strictly records factual machine-learning parameters, diagnostics, and
explainable deviations. No security risk scores, CVEs, or attack probabilities.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MLModelConfiguration(BaseModel):
    """Hyperparameters for Isolation Forest training."""

    contamination: float = Field(
        default=0.05,
        ge=0.001,
        le=0.5,
        description="Expected proportion of outliers in the data set (model parameter, not attack probability).",
    )
    n_estimators: int = Field(
        default=100,
        ge=10,
        le=500,
        description="Number of base estimators in the ensemble.",
    )
    max_samples: str = Field(
        default="auto",
        description="Number of samples to draw from X to train each base estimator.",
    )
    random_state: int = Field(
        default=42,
        description="Controlled seed for reproducible model training.",
    )


class MLModelDiagnostics(BaseModel):
    """Genuine, mathematically calculated unsupervised model diagnostics (no fake accuracy)."""

    sample_count: int
    feature_count: int
    contamination: float
    score_min: float
    score_max: float
    score_mean: float
    score_std: float
    score_p25: float
    score_p50: float
    score_p75: float
    score_threshold: float = Field(
        default=0.0,
        description="Decision threshold where raw score < threshold indicates anomaly.",
    )


class MLModelTrainRequest(BaseModel):
    """Request payload to train an anomaly detection model on an established baseline."""

    baseline_id: str = Field(..., description="ID of the baseline profile supplying reference sessions.")
    name: Optional[str] = Field(None, description="Descriptive name for the model version.")
    model_type: str = Field(default="IsolationForest", description="ML model architecture.")
    minimum_training_samples: int = Field(
        default=3,
        ge=2,
        description="Configurable threshold of minimum real sessions required for training.",
    )
    configuration: Optional[MLModelConfiguration] = None


class MLModelSummary(BaseModel):
    """High-level summary of a registered ML model."""

    id: str
    name: str
    model_type: str
    model_version: str
    feature_version: str
    preprocessing_version: str
    training_samples: int
    feature_count: int
    status: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class MLModelDetail(MLModelSummary):
    """Comprehensive details of an ML model including genuine diagnostics and configuration."""

    configuration: Dict[str, Any]
    metrics: Optional[MLModelDiagnostics] = None
    feature_names: List[str]
    model_checksum: Optional[str] = None
    training_dataset_id: Optional[str] = None
    baseline_id: Optional[str] = None


class TrainingDatasetSummary(BaseModel):
    """Summary of a frozen training dataset snapshot."""

    id: str
    baseline_id: str
    dataset_version: str
    feature_version: str
    sample_count: int
    feature_count: int
    session_ids: List[str]
    created_at: datetime


class TrainingDatasetDetail(TrainingDatasetSummary):
    """Detailed inspection of an ML training dataset."""

    feature_names: List[str]
    missing_data_summary: Dict[str, Any]


class AnomalyInferenceRequest(BaseModel):
    """Request payload to execute anomaly inference on an observed VPN session."""

    session_id: str = Field(..., description="ID of the session to evaluate.")
    model_id: Optional[str] = Field(
        None,
        description="Optional model ID to use. If omitted, the currently active model is used.",
    )


class AnomalyFeatureContribution(BaseModel):
    """Factual, model-derived evidence for an individual feature's contribution to anomaly score."""

    feature_name: str
    display_name: str
    category: str
    data_type: str
    observed_value: Any
    reference_mean: Optional[float] = None
    reference_std: Optional[float] = None
    reference_median: Optional[float] = None
    contribution_score: float = Field(
        ...,
        description="Relative contribution percentage (0-100%) to overall anomaly deviation.",
    )
    deviation: Optional[float] = Field(
        None,
        description="Normalized z-score or distance from reference distribution.",
    )
    direction: str = Field(
        ...,
        description="Direction of deviation: ABOVE_REFERENCE, BELOW_REFERENCE, or WITHIN_RANGE.",
    )
    evidence_description: str = Field(
        ...,
        description="Plain-text factual statement of observed vs reference behavior.",
    )


class SignalComparisonSummary(BaseModel):
    """Separated 3-signal behavioral comparison panel (no risk fusion)."""

    baseline_id: Optional[str] = None
    baseline_status: str = Field(
        default="NO_BASELINE",
        description="Baseline profiling status: WITHIN_BASELINE, DRIFT_DETECTED, or NO_BASELINE.",
    )
    drift_analysis_id: Optional[str] = None
    drift_status: str = Field(
        default="NOT_ANALYZED",
        description="Statistical drift status: NO_DRIFT, DRIFT_DETECTED, or NOT_ANALYZED.",
    )
    ml_model_id: str
    ml_status: str = Field(
        ...,
        description="ML anomaly status: NORMAL or ANOMALOUS.",
    )


class AnomalyAnalysisResponse(BaseModel):
    """Result of an anomaly detection evaluation run."""

    id: str
    session_id: str
    model_id: str
    model_version: str
    feature_version: str
    preprocessing_version: str
    classification: str = Field(
        ...,
        description="Classification: NORMAL (inlier) or ANOMALOUS (outlier). Does NOT mean attack or malware.",
    )
    raw_score: float = Field(
        ...,
        description="Raw decision score from Isolation Forest (negative = outlier, positive = inlier).",
    )
    display_score: float = Field(
        ...,
        description="Normalized score [0-100] via logistic transformation: higher = more anomalous.",
    )
    features_analyzed: int
    features_anomalous: int
    explanation_summary: str
    feature_contributions: List[AnomalyFeatureContribution]
    signal_comparison: SignalComparisonSummary
    analyzed_at: datetime


class AIAnomalyEngineStatus(BaseModel):
    """Operational status and health of the Layer 08 engine."""

    status: str = Field(
        ...,
        description="Engine status: NOT_INITIALIZED, READY, TRAINING, TRAINED, INFERENCE_READY, ERROR, INSUFFICIENT_DATA.",
    )
    active_model: Optional[MLModelSummary] = None
    total_models: int = 0
    feature_version: str = "1.0"
    preprocessing_version: str = "1.0"
    models_dir_writable: bool = True
    available_baselines_count: int = 0
    available_sessions_count: int = 0
