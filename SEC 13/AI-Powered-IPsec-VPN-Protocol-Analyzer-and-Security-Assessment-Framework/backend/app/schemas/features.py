"""Pydantic schemas for the Feature Extraction & Engineering API (Layer 05)."""

from __future__ import annotations

from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict

EntityType = Literal["PACKET", "SESSION", "SA"]
FeatureLevel = Literal["PACKET", "SESSION", "SA"]
FeatureType = Literal["INTEGER", "FLOAT", "BOOLEAN", "CATEGORICAL", "TIMESTAMP"]
FeatureCategory = Literal[
    "TRAFFIC", "TIMING", "PROTOCOL", "IPSEC", "IKE", "SA_LIFECYCLE", "DIRECTIONAL", "STATISTICAL"
]
FeatureAvailability = Literal["AVAILABLE", "PARTIAL", "UNAVAILABLE"]
FeatureQuality = Literal["COMPLETE", "PARTIAL", "MISSING_SOURCE_DATA"]
NormalizationMethod = Literal["NONE", "MIN_MAX", "STANDARD", "ROBUST", "CATEGORICAL_ENCODING"]
EngineState = Literal["NOT INITIALIZED", "READY", "PROCESSING", "AVAILABLE", "ERROR"]

FeatureScalar = Union[bool, int, float, str, None]


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class FeatureDefinitionSchema(_Model):
    name: str
    display_name: str
    description: str
    level: FeatureLevel
    category: FeatureCategory
    data_type: FeatureType
    unit: Optional[str]
    source: str
    nullable: bool
    formula: Optional[str] = None
    normalization_method: NormalizationMethod = "NONE"
    minimum_expected_value: Optional[float] = None
    maximum_expected_value: Optional[float] = None


class FeatureValueSchema(_Model):
    """A calculated feature, joined with its definition for display."""

    name: str
    display_name: str
    description: str
    value: FeatureScalar
    data_type: FeatureType
    category: FeatureCategory
    level: FeatureLevel
    unit: Optional[str]
    source: str
    detail: Optional[str] = None
    availability: FeatureAvailability
    quality: FeatureQuality
    formula: Optional[str] = None
    normalization_method: NormalizationMethod = "NONE"
    #: Reserved for a later section; always null while no parameters are fitted.
    normalized_value: Optional[float] = None


class SourceAvailabilitySchema(_Model):
    name: str
    available: bool
    detail: str


class FeatureVectorSchema(_Model):
    id: str
    entity_type: EntityType
    entity_id: str
    entity_label: str
    capture_id: str
    feature_version: str
    generated_at: str
    feature_count: int
    available_count: int
    partial_count: int
    unavailable_count: int
    sources: list[SourceAvailabilitySchema] = []
    features: list[FeatureValueSchema] = []


class FeatureVectorSummarySchema(_Model):
    """List view of a stored vector, without its values."""

    id: str
    entity_type: EntityType
    entity_id: str
    entity_label: str
    feature_version: str
    generated_at: str
    feature_count: int
    available_count: int
    partial_count: int
    unavailable_count: int


class FeatureVectorPageSchema(_Model):
    items: list[FeatureVectorSummarySchema]
    page: int
    page_size: int
    total: int
    total_pages: int


class FeatureEntitySchema(_Model):
    """A selectable entity for the source selector."""

    entity_type: EntityType
    entity_id: str
    label: str
    detail: str
    extracted: bool


class FeatureEntityListSchema(_Model):
    entity_type: EntityType
    items: list[FeatureEntitySchema]
    source_available: bool
    detail: str


class FeatureStatisticsSchema(_Model):
    vectors: int
    packet_vectors: int
    session_vectors: int
    sa_vectors: int
    total_features: int
    available_features: int
    partial_features: int
    unavailable_features: int


class FeatureEngineStatusSchema(_Model):
    state: EngineState
    feature_version: str
    packets_available: bool
    sessions_available: bool
    sas_available: bool
    capture_id: Optional[str] = None
    capture_filename: Optional[str] = None
    extracted_at: Optional[str] = None
    registered_features: int
    burst_window_seconds: float
    statistics: Optional[FeatureStatisticsSchema] = None
    last_error: Optional[str] = None


class FeatureExtractionRequestSchema(BaseModel):
    """Entity reference only; the backend already owns the source data."""

    entity_type: EntityType
    entity_id: str


class FeatureExtractionResponseSchema(_Model):
    status: Literal["EXTRACTED"]
    feature_version: str
    generated_at: str
    feature_vector: FeatureVectorSchema
