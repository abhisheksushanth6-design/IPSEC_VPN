"""Pydantic schemas for baseline profiles, feature distributions, and comparisons.

All schemas strictly model descriptive baseline statistics without drift or
anomaly judgment labels.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class NumericStatisticsSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    count: int = Field(..., description="Sample count")
    mean: float = Field(..., description="Arithmetic mean")
    median: float = Field(..., description="Median value (50th percentile)")
    min: float = Field(..., description="Minimum observed value")
    max: float = Field(..., description="Maximum observed value")
    std_dev: float = Field(..., description="Sample standard deviation (0 for zero variance)")
    p25: float = Field(..., description="25th percentile")
    p50: float = Field(..., description="50th percentile")
    p75: float = Field(..., description="75th percentile")
    p95: float = Field(..., description="95th percentile")


class CategoricalStatisticsSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    count: int = Field(..., description="Valid observations count")
    unique_count: int = Field(..., description="Distinct categories observed")
    frequencies: Dict[str, int] = Field(default_factory=dict, description="Value to count mapping")
    relative_frequencies: Dict[str, float] = Field(default_factory=dict, description="Value to relative ratio mapping")
    mode: Optional[str] = Field(None, description="Most frequently observed category")


class BooleanStatisticsSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    count: int = Field(..., description="Total observations")
    true_count: int = Field(..., description="True observations count")
    false_count: int = Field(..., description="False observations count")
    true_ratio: float = Field(..., description="Ratio of true observations")
    false_ratio: float = Field(..., description="Ratio of false observations")


class BaselineFeatureProfileSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str = Field(..., description="Feature identifier")
    display_name: str = Field(..., description="Human-readable feature name")
    category: str = Field(..., description="Feature category")
    data_type: str = Field(..., description="Data type")
    unit: Optional[str] = Field(None, description="Physical unit")
    numeric_stats: Optional[NumericStatisticsSchema] = Field(None, description="Descriptive numeric statistics")
    categorical_stats: Optional[CategoricalStatisticsSchema] = Field(None, description="Categorical distributions")
    boolean_stats: Optional[BooleanStatisticsSchema] = Field(None, description="Boolean statistics")
    total_samples: int = Field(..., description="Total sessions evaluated")
    available_samples: int = Field(..., description="Sessions with feature present")
    missing_samples: int = Field(..., description="Sessions where feature was missing")
    completeness_ratio: float = Field(..., description="Available over total samples ratio")


class BaselineCoverageSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sessions_included: List[str] = Field(default_factory=list, description="IDs of sessions included")
    total_sessions: int = Field(..., description="Count of included sessions")
    features_profiled: int = Field(..., description="Total feature definitions profiled")
    features_available: int = Field(..., description="Features observed with valid data")
    features_missing: int = Field(..., description="Features missing in all observations")
    feature_completeness: float = Field(..., description="Completeness percentage")
    first_observation: Optional[str] = Field(None, description="Earliest packet timestamp")
    last_observation: Optional[str] = Field(None, description="Latest packet timestamp")


class BaselineDataQualitySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    complete_sessions: int = Field(..., description="Sessions with 100% available features")
    partial_sessions: int = Field(..., description="Sessions with some unavailable features")
    missing_data_features: int = Field(..., description="Total missing feature values across sessions")
    invalid_records: int = Field(0, description="Invalid or rejected session records")
    quality_rating: str = Field(..., description="Data quality rating (HIGH / SUFFICIENT / DEGRADED / INSUFFICIENT)")


class BaselineSummarySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    version: int
    feature_version: str
    status: str
    is_active: bool
    session_count: int
    feature_count: int
    minimum_sessions: int
    first_observation: Optional[str] = None
    last_observation: Optional[str] = None
    created_at: str
    updated_at: str


class BaselineProfileSchema(BaselineSummarySchema):
    coverage: BaselineCoverageSchema
    data_quality: BaselineDataQualitySchema
    features: List[BaselineFeatureProfileSchema] = Field(default_factory=list)


class BaselineBuildRequestSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=120, description="Human readable baseline name")
    description: Optional[str] = Field(None, max_length=500, description="Optional baseline description")
    session_ids: Optional[List[str]] = Field(None, description="Explicit list of session IDs to profile")
    minimum_sessions: int = Field(3, ge=1, le=1000, description="Minimum observations required for READY status")
    activate: bool = Field(False, description="Whether to activate this baseline upon creation")


class BaselineEngineStatusSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    state: str = Field(..., description="NOT INITIALIZED / READY / COLLECTING / BUILDING / AVAILABLE / ERROR")
    feature_version: str
    active_baseline_id: Optional[str] = None
    active_baseline_name: Optional[str] = None
    total_baselines: int = 0
    total_fingerprints: int = 0
    total_sessions_profiled: int = 0
    total_features_profiled: int = 0
    last_error: Optional[str] = None


class BaselineComparisonItemSchema(BaseModel):
    feature_name: str
    display_name: str
    category: str
    data_type: str
    unit: Optional[str] = None
    observed_value: Union[int, float, bool, str, None] = None
    baseline_mean: Optional[float] = None
    baseline_median: Optional[float] = None
    baseline_min: Optional[float] = None
    baseline_max: Optional[float] = None
    baseline_std_dev: Optional[float] = None
    baseline_mode: Optional[str] = None
    availability: str


class BaselineComparisonSchema(BaseModel):
    fingerprint_id: str
    session_id: str
    baseline_id: str
    baseline_name: str
    baseline_version: int
    features: List[BaselineComparisonItemSchema]


class BaselineSessionItemSchema(BaseModel):
    session_id: str
    fingerprint_id: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: Optional[float] = None
    packets: int
    bytes: int
    source: str
    destination: str
    state: str
    ike_version: Optional[str] = None
