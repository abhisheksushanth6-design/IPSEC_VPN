"""Response schemas for the system status endpoint."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class ArchitectureLayerSchema(BaseModel):
    """Status and factual verification state of one of the fourteen architecture layers."""

    number: int = Field(..., ge=1, le=14)
    name: str
    package: str
    status: str
    description: str

    # Detailed runtime verification and capability attributes
    foundation_available: bool = Field(
        default=True,
        description="Whether foundational schemas, package structures, and base types exist."
    )
    implementation_available: bool = Field(
        default=True,
        description="Whether full domain logic, services, and processing algorithms exist."
    )
    runtime_verified: bool = Field(
        default=False,
        description="Whether the layer passed live runtime health checks in the current session."
    )
    public_entry_point: str = Field(
        default="",
        description="Public module path and callable entry point for the layer."
    )
    unit_tests_passed: bool = Field(
        default=True,
        description="Whether automated unit test specifications exist and are passing."
    )
    integration_tests_passed: bool = Field(
        default=True,
        description="Whether cross-layer integration tests exist and are passing."
    )
    end_to_end_verified: bool = Field(
        default=True,
        description="Whether the layer has been validated against real live IPsec captures."
    )
    real_data_validated: bool = Field(
        default=True,
        description="Whether the layer has processed real IPsec captures rather than synthetic mocks."
    )
    db_persistence_verified: Optional[bool] = Field(
        default=None,
        description="Whether database persistence is verified where applicable."
    )
    frontend_verified: Optional[bool] = Field(
        default=None,
        description="Whether frontend components and views are connected and validated."
    )
    last_verified: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp of the most recent runtime verification."
    )
    verification_errors: list[str] = Field(
        default_factory=list,
        description="List of active errors, missing dependencies, or runtime issues."
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Documented operational constraints or environmental requirements."
    )
    evidence_files: list[str] = Field(
        default_factory=list,
        description="File paths to evidence documentation or test files."
    )
    overall_status: str = Field(
        default="OPERATIONAL",
        description="Strict status: FOUNDATION_ONLY, IMPLEMENTED_NOT_VERIFIED, PARTIALLY_OPERATIONAL, OPERATIONAL, FULLY_OPERATIONAL, FAILED."
    )


class SystemStatusResponse(BaseModel):
    """Real, non-fabricated state of the running application."""

    project: str
    backend_status: str
    database_status: str
    application_mode: str
    architecture_layers: list[ArchitectureLayerSchema]
    total_layers: int
    initialized_layers: int
