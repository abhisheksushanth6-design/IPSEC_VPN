"""Database initialisation and the system_settings table."""

from __future__ import annotations

from sqlalchemy import inspect, select

from app.db.base import SessionLocal, engine
from app.db.init_db import APPLICATION_MODE_KEY, database_is_ready, initialize_database
from app.models.system_settings import SystemSetting


def test_initialize_database_creates_system_settings() -> None:
    initialize_database()
    assert "system_settings" in inspect(engine).get_table_names()
    assert database_is_ready() is True


def test_application_mode_seeded_as_demo() -> None:
    initialize_database()
    with SessionLocal() as session:
        setting = session.scalar(
            select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)
        )
    assert setting is not None
    assert setting.value == "DEMO"


def test_initialization_is_idempotent() -> None:
    initialize_database()
    initialize_database()
    with SessionLocal() as session:
        rows = session.scalars(
            select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)
        ).all()
    assert len(rows) == 1


def test_no_security_tables_exist_yet() -> None:
    initialize_database()
    tables = set(inspect(engine).get_table_names())
    assert tables == {"system_settings"}
