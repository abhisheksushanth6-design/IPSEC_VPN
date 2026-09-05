"""Health endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Liveness check")
def read_health() -> HealthResponse:
    """Report that the API process is up."""
    return HealthResponse(project=get_settings().project_name, status="operational")
