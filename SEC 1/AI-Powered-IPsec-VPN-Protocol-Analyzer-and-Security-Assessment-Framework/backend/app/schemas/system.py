"""Response schemas for the system status endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ArchitectureLayerSchema(BaseModel):
    """Status of one of the fourteen architecture layers."""

    number: int = Field(..., ge=1, le=14)
    name: str
    package: str
    status: str
    description: str


class SystemStatusResponse(BaseModel):
    """Real, non-fabricated state of the running application."""

    project: str
    backend_status: str
    database_status: str
    application_mode: str
    architecture_layers: list[ArchitectureLayerSchema]
    total_layers: int
    initialized_layers: int
