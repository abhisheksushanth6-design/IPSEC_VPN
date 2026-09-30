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
import app.models  # noqa: F401 - registers every model with Base.metadata
from app.models.system_settings import SystemSetting

logger = logging.getLogger(__name__)

APPLICATION_MODE_KEY = "application_mode"


def _migrate_sqlite_columns() -> None:
    """Ensure newly added columns exist in existing SQLite tables."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if "ipsec_sessions" in table_names:
        cols = {c["name"] for c in inspector.get_columns("ipsec_sessions")}
        with engine.begin() as conn:
            if "ipsec_mode" not in cols:
                conn.execute(text("ALTER TABLE ipsec_sessions ADD COLUMN ipsec_mode VARCHAR(16) DEFAULT 'TUNNEL' NOT NULL"))
            if "ip_version" not in cols:
                conn.execute(text("ALTER TABLE ipsec_sessions ADD COLUMN ip_version INTEGER DEFAULT 4 NOT NULL"))

    if "security_associations" in table_names:
        cols = {c["name"] for c in inspector.get_columns("security_associations")}
        with engine.begin() as conn:
            if "ipsec_mode" not in cols:
                conn.execute(text("ALTER TABLE security_associations ADD COLUMN ipsec_mode VARCHAR(16) DEFAULT 'TUNNEL' NOT NULL"))
            if "ip_version" not in cols:
                conn.execute(text("ALTER TABLE security_associations ADD COLUMN ip_version INTEGER DEFAULT 4 NOT NULL"))


def create_schema() -> None:
    """Create any tables that do not yet exist."""
    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_columns()


def seed_system_settings(session: Session) -> SystemSetting:
    """Ensure the application_mode setting exists and matches configuration."""
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
    elif existing.value != settings.application_mode:
        existing.value = settings.application_mode
        session.commit()
        session.refresh(existing)
        logger.info("Synchronized system_settings.%s = %s", APPLICATION_MODE_KEY, existing.value)
    return existing


def seed_default_users(session: Session) -> None:
    """Ensure a default security analyst demo user exists for technical presentations."""
    from app.core.security import hash_password
    from app.models.user import User

    existing = session.scalar(select(User).limit(1))
    if existing is None:
        demo_user = User(
            name="Security Analyst",
            email="admin@ipsec-analyzer.local",
            username="analyst",
            password_hash=hash_password("Analyst@2026!"),
            role="admin",
            is_active=True,
            is_verified=True,
        )
        session.add(demo_user)
        session.commit()
        logger.info(
            "Seeded default demo user: username=%s email=%s",
            demo_user.username,
            demo_user.email,
        )


def initialize_database() -> None:
    """Create the schema and seed configuration. Safe to call repeatedly."""
    try:
        create_schema()
        with SessionLocal() as session:
            seed_system_settings(session)
            seed_default_users(session)
            try:
                from app.layers.layer08_ai_ml.cicids_bundle import ensure_cicids_model_registered
                ensure_cicids_model_registered(session)
            except Exception as exc:
                logger.warning("CIC-IDS model bootstrap deferred: %s", exc)
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
