"""Pydantic schemas for session fingerprints and comparisons.

Descriptive schemas only. No drift or anomaly scores.
"""

from __future__ import annotations

from typing import Any, List, Optional, Union

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class FingerprintFeatureSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str = Field(..., description="Machine-readable feature identifier")
    display_name: str = Field(..., description="Human-readable feature name")
    category: str = Field(..., description="Feature category (TRAFFIC, TIMING, PROTOCOL, etc.)")
    data_type: str = Field(..., description="Data type (INTEGER, FLOAT, BOOLEAN, CATEGORICAL, etc.)")
    unit: Optional[str] = Field(None, description="Physical unit of measurement")
    value: Union[int, float, bool, str, None] = Field(None, description="Observed feature value")
    availability: str = Field(..., description="AVAILABLE / PARTIAL / UNAVAILABLE")
    quality: str = Field(..., description="COMPLETE / PARTIAL / MISSING_SOURCE_DATA")
    source: str = Field(..., description="Origin of observation for lineage")


class SessionFingerprintSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str = Field(
        ...,
        validation_alias=AliasChoices("id", "fingerprint_id"),
        serialization_alias="id",
        description="Deterministic fingerprint identifier",
    )
    session_id: str = Field(..., description="Source IPsec session identifier")
    capture_id: str = Field(..., description="Source capture identifier")
    feature_version: str = Field(..., description="Feature schema version")
    signature: str = Field(
        ...,
        validation_alias=AliasChoices("signature", "fingerprint_signature"),
        serialization_alias="signature",
        description="Deterministic SHA-256 behavioral signature",
    )
    created_at: str = Field(..., description="Fingerprint creation timestamp")
    feature_count: int = Field(..., description="Total features preserved in fingerprint")
    features: List[FingerprintFeatureSchema] = Field(default_factory=list, description="Preserved feature values")


class FingerprintSummarySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str = Field(..., validation_alias=AliasChoices("id", "fingerprint_id"), serialization_alias="id")
    session_id: str
    capture_id: str
    feature_version: str
    signature: str = Field(..., validation_alias=AliasChoices("signature", "fingerprint_signature"), serialization_alias="signature")
    created_at: str
    feature_count: int


class FingerprintComparisonItemSchema(BaseModel):
    feature_name: str
    display_name: str
    category: str
    data_type: str
    unit: Optional[str] = None
    value_a: Union[int, float, bool, str, None] = None
    value_b: Union[int, float, bool, str, None] = None
    availability_a: str
    availability_b: str


class FingerprintComparisonSchema(BaseModel):
    fingerprint_a: FingerprintSummarySchema
    fingerprint_b: FingerprintSummarySchema
    features: List[FingerprintComparisonItemSchema]
