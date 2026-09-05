"""Response schema for the health endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Minimal liveness payload."""

    project: str = Field(..., description="Full project name.")
    status: str = Field(..., description="Service status.")
