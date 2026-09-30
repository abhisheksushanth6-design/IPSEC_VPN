"""Layer 11 — Security Databases (SQLite) Service.

Provides runtime verification of SQLite database connectivity, schema integrity,
table existence validation, and live database telemetry for the 14-layer architecture.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from sqlalchemy import inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import Base, SessionLocal, engine
from app.db.init_db import database_is_ready

logger = logging.getLogger(__name__)

EXPECTED_CORE_TABLES = [
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
    "traffic_classifications",
    "metadata_exposure_assessments",
    "threat_matrix_entries",
    "users",
    "password_reset_tokens",
    "user_sessions",
]


@contextmanager
def atomic_transaction(session: Session) -> Iterator[Session]:
    """Context manager providing atomic transaction execution with clean rollback on error."""
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise


class DatabaseLayerService:
    """Service facade for Layer 11 — Security Databases (SQLite)."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_connected(self, db: Optional[Session] = None) -> bool:
        """Verify that SQLite engine is reachable and executable."""
        try:
            if db is not None:
                db.execute(text("SELECT 1"))
                return True
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                return True
        except Exception as exc:
            logger.warning("Layer 11 Database ping failed: %s", exc)
            return False

    def get_existing_tables(self) -> List[str]:
        """Return all tables present in the SQLite database."""
        try:
            inspector = inspect(engine)
            return inspector.get_table_names()
        except Exception as exc:
            logger.error("Failed to inspect database tables: %s", exc)
            return []

    def get_table_statistics(self, db: Optional[Session] = None) -> Dict[str, int]:
        """Query row counts across core security tables."""
        stats: Dict[str, int] = {}
        existing = set(self.get_existing_tables())

        def _count(session: Session, table_name: str) -> int:
            if table_name not in existing:
                return 0
            try:
                res = session.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
                return int(res or 0)
            except Exception:
                return 0

        if db is not None:
            for t in EXPECTED_CORE_TABLES:
                stats[t] = _count(db, t)
        else:
            with SessionLocal() as session:
                for t in EXPECTED_CORE_TABLES:
                    stats[t] = _count(session, t)

        return stats

    def get_database_info(self) -> Dict[str, Any]:
        """Return filesystem, connection, and PRAGMA details for SQLite database."""
        db_url = self.settings.resolved_database_url
        is_sqlite = db_url.startswith("sqlite")
        file_path = None
        size_bytes = None

        if is_sqlite and not db_url.endswith(":memory:"):
            raw_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
            if os.path.isfile(raw_path):
                file_path = os.path.abspath(raw_path)
                try:
                    size_bytes = os.path.getsize(file_path)
                except OSError:
                    size_bytes = None

        foreign_keys = None
        journal_mode = None
        busy_timeout = None
        synchronous = None

        try:
            with engine.connect() as conn:
                foreign_keys = conn.execute(text("PRAGMA foreign_keys")).scalar()
                journal_mode = conn.execute(text("PRAGMA journal_mode")).scalar()
                busy_timeout = conn.execute(text("PRAGMA busy_timeout")).scalar()
                synchronous = conn.execute(text("PRAGMA synchronous")).scalar()
        except Exception as exc:
            logger.warning("Failed to query SQLite PRAGMAs: %s", exc)

        return {
            "database_url": "sqlite:///***" if "sqlite" in db_url else db_url,
            "resolved_url_type": "sqlite" if is_sqlite else "other",
            "is_sqlite": is_sqlite,
            "is_memory": ":memory:" in db_url,
            "file_path": file_path,
            "file_size_bytes": size_bytes,
            "foreign_keys_enabled": foreign_keys == 1,
            "foreign_keys_pragma": foreign_keys,
            "journal_mode": str(journal_mode) if journal_mode is not None else None,
            "busy_timeout_ms": busy_timeout,
            "synchronous": synchronous,
        }

    def get_detailed_health(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Execute deep database diagnostics verifying connectivity, pragmas, schema, and transaction integrity."""
        start_time = time.perf_counter()
        reachable = False
        ping_latency_ms = None
        integrity_ok = False
        integrity_result = None
        fk_enforced = False
        journal_mode = None
        rollback_verified = False
        errors: List[str] = []
        diagnostics: List[str] = []

        # 1. Ping & Connectivity Test
        try:
            if db is not None:
                db.execute(text("SELECT 1"))
            else:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
            reachable = True
            ping_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            diagnostics.append(f"Connectivity verified in {ping_latency_ms} ms.")
        except Exception as exc:
            errors.append(f"Engine connectivity check failed: {exc}")

        # 2. SQLite PRAGMAs & Integrity Check
        if reachable:
            try:
                with engine.connect() as conn:
                    # Integrity check
                    raw_integrity = conn.execute(text("PRAGMA integrity_check")).scalar()
                    integrity_result = str(raw_integrity)
                    integrity_ok = integrity_result.lower() == "ok"
                    if integrity_ok:
                        diagnostics.append("PRAGMA integrity_check passed ('ok').")
                    else:
                        errors.append(f"PRAGMA integrity_check returned: {integrity_result}")

                    # Foreign keys check
                    fk_val = conn.execute(text("PRAGMA foreign_keys")).scalar()
                    fk_enforced = (fk_val == 1)
                    if fk_enforced:
                        diagnostics.append("PRAGMA foreign_keys=ON (referential integrity enforced).")
                    else:
                        errors.append("PRAGMA foreign_keys is disabled (0).")

                    # Journal mode
                    jm_val = conn.execute(text("PRAGMA journal_mode")).scalar()
                    journal_mode = str(jm_val) if jm_val is not None else None
                    diagnostics.append(f"PRAGMA journal_mode={journal_mode}.")
            except Exception as exc:
                errors.append(f"PRAGMA query failed: {exc}")

        # 3. Table Schema Presence
        existing_tables = set(self.get_existing_tables())
        missing_tables = [t for t in EXPECTED_CORE_TABLES if t not in existing_tables]
        if not missing_tables:
            diagnostics.append(f"All {len(EXPECTED_CORE_TABLES)} core architecture tables verified.")
        else:
            errors.append(f"{len(missing_tables)} expected tables missing: {missing_tables}")

        # 4. Transaction Commit & Rollback Integrity Test
        if reachable:
            try:
                session_to_use = db if db is not None else SessionLocal()
                owns_session = db is None
                try:
                    # Create savepoint / subtransaction to test rollback
                    sp = session_to_use.begin_nested()
                    # Execute benign query inside savepoint
                    session_to_use.execute(text("SELECT COUNT(*) FROM system_settings"))
                    sp.rollback()
                    rollback_verified = True
                    diagnostics.append("Transaction rollback and savepoint mechanism verified.")
                finally:
                    if owns_session:
                        session_to_use.close()
            except Exception as exc:
                errors.append(f"Transaction rollback verification failed: {exc}")

        # Determine overall status
        if not reachable or not integrity_ok or not fk_enforced:
            health_status = "NOT_OPERATIONAL"
        elif missing_tables:
            health_status = "DEGRADED"
        else:
            health_status = "OPERATIONAL"

        return {
            "status": health_status,
            "reachable": reachable,
            "ping_latency_ms": ping_latency_ms,
            "integrity_check": integrity_result,
            "integrity_ok": integrity_ok,
            "foreign_keys_enforced": fk_enforced,
            "journal_mode": journal_mode,
            "tables_present": len(existing_tables),
            "expected_tables": len(EXPECTED_CORE_TABLES),
            "missing_tables": missing_tables,
            "rollback_verified": rollback_verified,
            "diagnostics": diagnostics,
            "errors": errors,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def verify_layer(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Perform comprehensive runtime verification for Layer 11."""
        detailed_health = self.get_detailed_health(db)
        connected = detailed_health["reachable"]
        tables = set(self.get_existing_tables())
        missing_tables = detailed_health["missing_tables"]
        stats = self.get_table_statistics(db)
        info = self.get_database_info()

        status = detailed_health["status"]
        errors = list(detailed_health["errors"])
        limitations: List[str] = []

        if missing_tables:
            limitations.append(f"{len(missing_tables)} expected tables not yet migrated: {missing_tables[:3]}")

        return {
            "status": status,
            "connected": connected,
            "table_count": len(tables),
            "expected_table_count": len(EXPECTED_CORE_TABLES),
            "missing_tables": missing_tables,
            "table_statistics": stats,
            "database_info": info,
            "health_diagnostics": detailed_health,
            "errors": errors,
            "limitations": limitations,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_layer_status(self, db: Optional[Session] = None) -> str:
        """Derive dynamic Layer 11 status based on genuine database connectivity."""
        if not database_is_ready():
            return "NOT INITIALIZED"
        if not self.is_connected(db):
            return "ERROR"
        tables = set(self.get_existing_tables())
        primary_tables = {"system_settings", "ipsec_sessions", "security_associations"}
        if not primary_tables.issubset(tables):
            return "READY"

        health = self.get_detailed_health(db)
        if health["status"] == "OPERATIONAL":
            return "OPERATIONAL"
        if health["status"] == "DEGRADED":
            return "WARNING"
        return "ERROR"


_service_instance: Optional[DatabaseLayerService] = None


def get_database_layer_service() -> DatabaseLayerService:
    """Singleton provider for DatabaseLayerService."""
    global _service_instance
    if _service_instance is None:
        _service_instance = DatabaseLayerService()
    return _service_instance
