"""Database initialisation.

Creates the schema and seeds only the configuration row required to boot the
application. No security, packet or session data is written here.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import DatabaseInitializationError
from app.db.base import Base, SessionLocal, engine
from app.models.system_settings import SystemSetting

logger = logging.getLogger(__name__)

APPLICATION_MODE_KEY = "application_mode"


def create_schema() -> None:
    """Create any tables that do not yet exist."""
    Base.metadata.create_all(bind=engine)


def seed_system_settings(session: Session) -> SystemSetting:
    """Ensure the application_mode setting exists, and return it."""
    settings = get_settings()
    existing = session.scalar(
        select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)
    )
    if existing is None:
        existing = SystemSetting(
            key=APPLICATION_MODE_KEY,
            value=settings.application_mode,
            description="Operating mode of the application.",
        )
        session.add(existing)
        session.commit()
        session.refresh(existing)
        logger.info("Seeded system_settings.%s = %s", APPLICATION_MODE_KEY, existing.value)
    return existing


def initialize_database() -> None:
    """Create the schema and seed configuration. Safe to call repeatedly."""
    try:
        create_schema()
        with SessionLocal() as session:
            seed_system_settings(session)
    except SQLAlchemyError as exc:  # pragma: no cover - exercised on real failures
        logger.error("Database initialisation failed: %s", exc)
        raise DatabaseInitializationError(str(exc)) from exc


def database_is_ready() -> bool:
    """Return True when the database answers and the schema is present."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return SystemSetting.__tablename__ in inspect(engine).get_table_names()
    except SQLAlchemyError:
        return False
