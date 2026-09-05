"""Service layer for reporting real application state."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.architecture import ARCHITECTURE_LAYERS, LayerStatus, TOTAL_LAYERS
from app.core.config import get_settings
from app.db.init_db import APPLICATION_MODE_KEY, database_is_ready
from app.models.system_settings import SystemSetting
from app.schemas.system import ArchitectureLayerSchema, SystemStatusResponse


def read_application_mode(session: Session) -> tuple[str, str]:
    """Return (application_mode, database_status) from the live database.

    Falls back to the environment configuration when the database has not been
    initialised, so the endpoint never reports invented state.
    """
    settings = get_settings()
    if not database_is_ready():
        return settings.application_mode, "NOT INITIALIZED"
    try:
        setting = session.scalar(
            select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)
        )
    except SQLAlchemyError:
        return settings.application_mode, "UNAVAILABLE"
    if setting is None:
        return settings.application_mode, "CONNECTED (UNSEEDED)"
    return setting.value, "CONNECTED"


def build_system_status(session: Session) -> SystemStatusResponse:
    """Assemble the system status response from real configuration state."""
    settings = get_settings()
    application_mode, database_status = read_application_mode(session)

    layers = [
        ArchitectureLayerSchema(
            number=layer.number,
            name=layer.name,
            package=layer.package,
            status=layer.status.value,
            description=layer.description,
        )
        for layer in ARCHITECTURE_LAYERS
    ]
    initialized = sum(
        1 for layer in ARCHITECTURE_LAYERS if layer.status is not LayerStatus.NOT_INITIALIZED
    )

    return SystemStatusResponse(
        project=settings.project_name,
        backend_status="operational",
        database_status=database_status,
        application_mode=application_mode,
        architecture_layers=layers,
        total_layers=TOTAL_LAYERS,
        initialized_layers=initialized,
    )
