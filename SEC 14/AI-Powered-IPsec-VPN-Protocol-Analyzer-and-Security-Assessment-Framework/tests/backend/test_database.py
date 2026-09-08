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


def test_application_mode_seeded_as_standalone() -> None:
    initialize_database()
    with SessionLocal() as session:
        setting = session.scalar(
            select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)
        )
    assert setting is not None
    assert setting.value == "STANDALONE"


def test_initialization_is_idempotent() -> None:
    initialize_database()
    initialize_database()
    with SessionLocal() as session:
        rows = session.scalars(
            select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)
        ).all()
    assert len(rows) == 1


def test_only_expected_tables_exist() -> None:
    initialize_database()
    tables = set(inspect(engine).get_table_names())
    assert tables == {
        "system_settings",
        "ipsec_sessions",
        "session_packets",
        "security_associations",
        "sa_lifecycle_events",
        "sa_packet_links",
        "feature_vectors",
        "feature_values",
        "session_fingerprints",
        "baseline_profiles",
        "baseline_features",
        "baseline_sessions",
        "drift_analyses",
        "feature_drifts",
        "ml_models",
        "training_datasets",
        "anomaly_analyses",
        "anomaly_feature_contributions",
        "security_rules",
        "vulnerability_findings",
        "finding_evidence",
        "risk_assessments",
        "reports",
    }
