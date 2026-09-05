"""System status endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.schemas.system import SystemStatusResponse
from app.services.system_service import build_system_status

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/status", response_model=SystemStatusResponse, summary="System status")
def read_system_status(session: Session = Depends(get_db)) -> SystemStatusResponse:
    """Report backend, database and architecture-layer state."""
    return build_system_status(session)
