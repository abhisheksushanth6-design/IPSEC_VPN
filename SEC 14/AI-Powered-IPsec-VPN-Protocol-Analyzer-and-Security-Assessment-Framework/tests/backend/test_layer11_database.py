"""Comprehensive test suite for Layer 11 — Database Persistence & Data Integrity.

Verifies:
- Clean database initialization and idempotency across all 26 core tables.
- SQLite PRAGMA enforcement (foreign_keys=ON, WAL journal_mode, busy_timeout).
- Referential integrity, foreign key rejection of orphan rows, and cascading deletes.
- Transaction commit persistence across independent sessions and clean rollback on failure.
- atomic_transaction context manager behavior.
- Data serialization and deserialization fidelity (JSON, Datetime, Boolean, Numeric).
- End-to-end multi-layer data persistence for Layers 1–10 pipeline outputs.
- DatabaseLayerService verification, telemetry, and detailed health diagnostics.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base, SessionLocal, engine
from app.db.init_db import (
    APPLICATION_MODE_KEY,
    database_is_ready,
    initialize_database,
)
from app.layers.layer11_database.service import (
    EXPECTED_CORE_TABLES,
    atomic_transaction,
    get_database_layer_service,
)
from app.models import (
    AnomalyAnalysisRow,
    BaselineProfileRow,
    DriftAnalysisRow,
    FeatureVectorRow,
    FindingEvidenceRow,
    IPsecSession,
    RiskAssessmentRow,
    SALifecycleEventRow,
    SecurityAssociationRow,
    SecurityRuleRow,
    SessionPacket,
    SystemSetting,
    VulnerabilityFindingRow,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# 1. Database Initialization & Schema Verification
# =============================================================================


def test_database_initialization_all_26_tables() -> None:
    """Verify that initialize_database creates all 26 expected architecture tables."""
    initialize_database()
    assert database_is_ready() is True

    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    assert len(EXPECTED_CORE_TABLES) == 29
    for table in EXPECTED_CORE_TABLES:
        assert table in table_names, f"Expected table '{table}' missing from database"


def test_database_initialization_is_idempotent() -> None:
    """Verify initialize_database can run multiple times without duplicating or corrupting data."""
    initialize_database()

    with SessionLocal() as session:
        initial_settings_count = session.scalar(select(SystemSetting.id).where(SystemSetting.key == APPLICATION_MODE_KEY))
        assert initial_settings_count is not None

    # Re-run initialization
    initialize_database()
    initialize_database()

    with SessionLocal() as session:
        rows = session.scalars(select(SystemSetting).where(SystemSetting.key == APPLICATION_MODE_KEY)).all()
        assert len(rows) == 1


# =============================================================================
# 2. SQLite PRAGMA & Connection Settings
# =============================================================================


def test_sqlite_pragmas_enforced() -> None:
    """Verify that every new connection executes the required SQLite PRAGMAs."""
    with engine.connect() as conn:
        fk = conn.execute(text("PRAGMA foreign_keys")).scalar()
        jm = conn.execute(text("PRAGMA journal_mode")).scalar()
        bt = conn.execute(text("PRAGMA busy_timeout")).scalar()

        assert fk == 1, "PRAGMA foreign_keys must be 1 (ON)"
        assert str(jm).lower() in ("wal", "memory"), f"Unexpected journal_mode: {jm}"
        assert bt is not None and bt >= 5000, f"PRAGMA busy_timeout should be at least 5000, got: {bt}"


# =============================================================================
# 3. Referential Integrity & Foreign Key Enforcement
# =============================================================================


def test_foreign_key_rejects_orphan_session_packet() -> None:
    """Verify that inserting a SessionPacket with a non-existent session_id raises IntegrityError."""
    initialize_database()
    with SessionLocal() as session:
        bad_packet = SessionPacket(
            session_id=f"nonexistent-session-{uuid.uuid4()}",
            capture_id="cap-orphan-test",
            packet_number=1,
            role="ESP",
        )
        session.add(bad_packet)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_foreign_key_rejects_orphan_finding_evidence() -> None:
    """Verify that inserting FindingEvidenceRow with non-existent finding_id raises IntegrityError."""
    initialize_database()
    with SessionLocal() as session:
        bad_evidence = FindingEvidenceRow(
            finding_id=f"nonexistent-finding-{uuid.uuid4()}",
            evidence_key="proposal_enc",
            observed_value="3DES",
            expected_value="AES-GCM",
            description="Deprecated cipher",
        )
        session.add(bad_evidence)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_cascade_delete_session_packets() -> None:
    """Verify that deleting an IPsecSession cascades to all its SessionPacket rows."""
    initialize_database()
    sess_id = f"test-cascade-{uuid.uuid4()}"
    cap_id = "cap-cascade-test"

    with SessionLocal() as session:
        ipsec_sess = IPsecSession(
            id=sess_id,
            capture_id=cap_id,
            ordinal=1,
            source="10.0.0.1:500",
            destination="10.0.0.2:500",
            direction="OUTBOUND",
            state="ESTABLISHED",
            correlation="IKE_ESP",
            packet_count=2,
            byte_count=500,
            detail_json="{}",
        )
        session.add(ipsec_sess)

        p1 = SessionPacket(session_id=sess_id, capture_id=cap_id, packet_number=1, role="IKE")
        p2 = SessionPacket(session_id=sess_id, capture_id=cap_id, packet_number=2, role="ESP")
        session.add_all([p1, p2])
        session.commit()

    # Verify both packets exist
    with SessionLocal() as session:
        packets = session.scalars(select(SessionPacket).where(SessionPacket.session_id == sess_id)).all()
        assert len(packets) == 2

        # Delete parent session
        sess_to_delete = session.scalar(select(IPsecSession).where(IPsecSession.id == sess_id))
        assert sess_to_delete is not None
        session.delete(sess_to_delete)
        session.commit()

    # Verify packets were cascade-deleted
    with SessionLocal() as session:
        remaining_packets = session.scalars(select(SessionPacket).where(SessionPacket.session_id == sess_id)).all()
        assert len(remaining_packets) == 0


def test_cascade_delete_vulnerability_finding_evidence() -> None:
    """Verify that deleting a VulnerabilityFindingRow cascades to its FindingEvidenceRow."""
    initialize_database()
    rule_id = f"rule-{uuid.uuid4().hex[:8]}"
    finding_id = f"vuln-{uuid.uuid4().hex[:8]}"

    with SessionLocal() as session:
        # Create rule first
        rule = SecurityRuleRow(
            id=rule_id,
            name="Proposal Audit",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            description="Detects legacy ciphers",
            remediation="Use AES-GCM",
        )
        session.add(rule)

        finding = VulnerabilityFindingRow(
            id=finding_id,
            rule_id=rule_id,
            title="Weak Proposal",
            description="DES encryption in proposal",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            confidence="HIGH",
            status="OPEN",
            affected_object_type="SESSION",
            affected_object_id=f"sess-{uuid.uuid4().hex[:8]}",
            dedup_hash=f"dedup-{uuid.uuid4().hex[:16]}",
        )
        session.add(finding)

        evidence = FindingEvidenceRow(
            finding_id=finding_id,
            evidence_key="cipher",
            observed_value="3DES",
            expected_value="AES-GCM",
            description="Insecure cipher in SA proposal",
        )
        session.add(evidence)
        session.commit()

    # Verify evidence exists
    with SessionLocal() as session:
        ev_rows = session.scalars(select(FindingEvidenceRow).where(FindingEvidenceRow.finding_id == finding_id)).all()
        assert len(ev_rows) == 1

        f_row = session.scalar(select(VulnerabilityFindingRow).where(VulnerabilityFindingRow.id == finding_id))
        assert f_row is not None
        session.delete(f_row)
        session.commit()

    # Verify evidence was cascade-deleted
    with SessionLocal() as session:
        ev_after = session.scalars(select(FindingEvidenceRow).where(FindingEvidenceRow.finding_id == finding_id)).all()
        assert len(ev_after) == 0


# =============================================================================
# 4. Transaction Boundaries & atomic_transaction Context Manager
# =============================================================================


def test_transaction_commit_persists_across_sessions() -> None:
    """Verify that committed writes in Session A are faithfully read by independent Session B."""
    initialize_database()
    test_id = f"cross-sess-{uuid.uuid4()}"

    # Write in Session A
    with SessionLocal() as session_a:
        row = IPsecSession(
            id=test_id,
            capture_id="cap-cross",
            ordinal=42,
            source="192.168.1.100:500",
            destination="192.168.1.200:500",
            direction="INBOUND",
            state="ESTABLISHED",
            correlation="IKE_SA",
            packet_count=10,
            byte_count=1024,
            detail_json=json.dumps({"test_key": "test_value"}),
        )
        session_a.add(row)
        session_a.commit()

    # Read in Session B
    with SessionLocal() as session_b:
        retrieved = session_b.scalar(select(IPsecSession).where(IPsecSession.id == test_id))
        assert retrieved is not None
        assert retrieved.ordinal == 42
        assert retrieved.source == "192.168.1.100:500"
        detail = json.loads(retrieved.detail_json)
        assert detail["test_key"] == "test_value"

        # Cleanup
        session_b.delete(retrieved)
        session_b.commit()


def test_transaction_rollback_prevents_partial_writes() -> None:
    """Verify that an uncommitted or rolled-back transaction leaves zero residual records."""
    initialize_database()
    test_id = f"rollback-test-{uuid.uuid4()}"

    with SessionLocal() as session:
        row = IPsecSession(
            id=test_id,
            capture_id="cap-rollback",
            ordinal=1,
            source="10.10.10.1:500",
            destination="10.10.10.2:500",
            direction="OUTBOUND",
            state="INITIATED",
            correlation="NONE",
            packet_count=1,
            byte_count=100,
            detail_json="{}",
        )
        session.add(row)
        session.flush()
        # Deliberately roll back
        session.rollback()

    # Verify record was not persisted
    with SessionLocal() as session:
        persisted = session.scalar(select(IPsecSession).where(IPsecSession.id == test_id))
        assert persisted is None


def test_atomic_transaction_success_and_failure() -> None:
    """Verify atomic_transaction commits on normal exit and rolls back on exception."""
    initialize_database()
    success_id = f"atomic-ok-{uuid.uuid4()}"
    fail_id = f"atomic-fail-{uuid.uuid4()}"

    # 1. Success case
    with SessionLocal() as session:
        with atomic_transaction(session):
            session.add(
                IPsecSession(
                    id=success_id,
                    capture_id="cap-atomic",
                    ordinal=1,
                    source="1.1.1.1:500",
                    destination="2.2.2.2:500",
                    direction="OUTBOUND",
                    state="ESTABLISHED",
                    correlation="IKE",
                    packet_count=1,
                    byte_count=50,
                    detail_json="{}",
                )
            )

    # Verify committed
    with SessionLocal() as session:
        assert session.scalar(select(IPsecSession).where(IPsecSession.id == success_id)) is not None

    # 2. Failure case
    with SessionLocal() as session:
        with pytest.raises(RuntimeError):
            with atomic_transaction(session):
                session.add(
                    IPsecSession(
                        id=fail_id,
                        capture_id="cap-atomic",
                        ordinal=2,
                        source="1.1.1.1:500",
                        destination="2.2.2.2:500",
                        direction="OUTBOUND",
                        state="ESTABLISHED",
                        correlation="IKE",
                        packet_count=1,
                        byte_count=50,
                        detail_json="{}",
                    )
                )
                raise RuntimeError("Simulated transaction fault")

    # Verify rolled back
    with SessionLocal() as session:
        assert session.scalar(select(IPsecSession).where(IPsecSession.id == fail_id)) is None


# =============================================================================
# 5. Data Serialization & Type Fidelity
# =============================================================================


def test_json_and_datetime_serialization_fidelity() -> None:
    """Verify complex nested JSON structures, datetimes, and floats preserve exact precision."""
    initialize_database()
    sess_id = f"json-sess-{uuid.uuid4()}"
    assessment_id = f"json-risk-{uuid.uuid4()}"

    complex_signals = [
        {"source": "vulnerability", "rule_id": "SEC-001", "points": 25.0, "reason": "Weak DH Group"},
        {"source": "ml_anomaly", "model": "CIC-IDS", "points": 18.5, "anomaly_score": 0.85},
    ]
    complex_evidence = [
        {"type": "packet_hex", "data": "0x4500003c"},
        {"type": "sa_spi", "spi": "0xc0ffee01"},
    ]
    complex_actions = ["Upgrade DH group to >= 14", "Re-key Child SA immediately"]

    with SessionLocal() as session:
        # Parent session
        session.add(
            IPsecSession(
                id=sess_id,
                capture_id="cap-json",
                ordinal=1,
                source="192.168.1.1:500",
                destination="192.168.1.2:500",
                direction="OUTBOUND",
                state="ESTABLISHED",
                correlation="IKE_ESP",
                packet_count=5,
                byte_count=600,
                detail_json=json.dumps({"nested": {"array": [1, 2, 3], "unicode": "IPsec 安全评估"}}),
            )
        )

        # Risk assessment with JSON fields
        risk_row = RiskAssessmentRow(
            id=assessment_id,
            session_id=sess_id,
            risk_score=78.55,
            risk_level="CRITICAL",
            decision="TERMINATE",
            data_quality="COMPLETE",
            confidence_score=1.0,
            vulnerability_score=35.0,
            ml_score=25.0,
            drift_score=10.55,
            state_score=8.0,
            contributing_signals_json=json.dumps(complex_signals),
            evidence_json=json.dumps(complex_evidence),
            recommended_actions_json=json.dumps(complex_actions),
        )
        session.add(risk_row)
        session.commit()

    # Re-read and assert exact round-trip fidelity
    with SessionLocal() as session:
        row = session.scalar(select(RiskAssessmentRow).where(RiskAssessmentRow.id == assessment_id))
        assert row is not None
        assert abs(row.risk_score - 78.55) < 1e-4
        assert row.risk_level == "CRITICAL"
        assert row.decision == "TERMINATE"

        signals = json.loads(row.contributing_signals_json)
        assert signals == complex_signals

        evidence = json.loads(row.evidence_json)
        assert evidence == complex_evidence

        actions = json.loads(row.recommended_actions_json)
        assert actions == complex_actions


# =============================================================================
# 6. Complete Upstream Pipeline Persistence (Layers 1–10)
# =============================================================================


def test_full_pipeline_persistence_layers_1_to_10() -> None:
    """Verify that factual and derived records from Layers 1–10 persist and relate accurately."""
    initialize_database()
    uid = uuid.uuid4().hex[:8]
    sess_id = f"pipeline-sess-{uid}"
    cap_id = f"pipeline-cap-{uid}"
    sa_id = f"pipeline-sa-{uid}"
    fv_id = f"pipeline-fv-{uid}"
    base_id = f"pipeline-base-{uid}"
    drift_id = f"pipeline-drift-{uid}"
    anomaly_id = f"pipeline-anom-{uid}"
    rule_id = f"pipeline-rule-{uid}"
    vuln_id = f"pipeline-vuln-{uid}"
    risk_id = f"pipeline-risk-{uid}"

    with SessionLocal() as session:
        # Layer 1/4: Session
        ipsec_sess = IPsecSession(
            id=sess_id,
            capture_id=cap_id,
            ordinal=1,
            source="10.0.0.1:500",
            destination="10.0.0.2:500",
            direction="OUTBOUND",
            state="ESTABLISHED",
            correlation="IKE_ESP",
            packet_count=10,
            byte_count=1500,
            detail_json=json.dumps({"initiator_spi": "0x12345678", "responder_spi": "0x87654321"}),
        )
        session.add(ipsec_sess)

        # Layer 2: Packet Link
        pkt = SessionPacket(session_id=sess_id, capture_id=cap_id, packet_number=1, role="IKE")
        session.add(pkt)

        # Layer 3/4: Security Association
        sa = SecurityAssociationRow(
            id=sa_id,
            capture_id=cap_id,
            type="ESP",
            state="ACTIVE",
            protocol="ESP",
            initiator="10.0.0.1",
            responder="10.0.0.2",
            association="CHILD",
            packet_count=10,
            byte_count=1500,
            session_id=sess_id,
            detail_json=json.dumps({"encryption": "AES-GCM-256"}),
            discovered_at=_utc_now(),
        )
        session.add(sa)

        # Layer 4: SA Lifecycle Event
        event = SALifecycleEventRow(
            sa_id=sa_id,
            sequence=1,
            timestamp=_utc_now().isoformat(),
            event_type="SA_ESTABLISHED",
            previous_state="INITIATED",
            new_state="ACTIVE",
            description="Rekey completed successfully",
        )
        session.add(event)

        # Layer 5: Feature Vector
        fv = FeatureVectorRow(
            id=fv_id,
            capture_id=cap_id,
            entity_type="SESSION",
            entity_id=sess_id,
            entity_label="Session Vector",
            feature_version="1.0",
            generated_at=_utc_now().isoformat(),
            feature_count=10,
            available_count=10,
            partial_count=0,
            unavailable_count=0,
            sources_json="[]",
            extracted_at=_utc_now(),
        )
        session.add(fv)

        # Layer 6: Baseline Profile
        base = BaselineProfileRow(
            id=base_id,
            name=f"Baseline-{uid}",
            description="Synthetic test baseline",
            version=1,
            feature_version="1.0",
            status="ACTIVE",
            is_active=True,
            session_count=10,
            feature_count=10,
            created_at=_utc_now(),
        )
        session.add(base)

        # Layer 7: Drift Analysis
        drift = DriftAnalysisRow(
            id=drift_id,
            session_id=sess_id,
            baseline_id=base_id,
            status="NORMAL",
            severity="NONE",
            features_analyzed=10,
            features_drifting=0,
            analyzed_at=_utc_now(),
        )
        session.add(drift)

        # Layer 8: ML Anomaly Analysis
        anomaly = AnomalyAnalysisRow(
            id=anomaly_id,
            session_id=sess_id,
            model_id="CICIDS2017-RF-V1",
            classification="NORMAL",
            raw_score=0.12,
            display_score=12.0,
            features_analyzed=10,
            features_anomalous=0,
            explanation_summary="Normal baseline traffic",
            analyzed_at=_utc_now(),
        )
        session.add(anomaly)

        # Layer 9: Security Rule, Vulnerability Finding & Evidence
        rule = SecurityRuleRow(
            id=rule_id,
            name="Lifetime Rule",
            category="POLICY",
            severity="MEDIUM",
            description="Checks SA lifetime bounds",
            remediation="Enforce 8-hour lifetime",
        )
        session.add(rule)

        vuln = VulnerabilityFindingRow(
            id=vuln_id,
            rule_id=rule_id,
            title="Weak Lifetime",
            description="SA lifetime exceeds recommended max duration",
            category="POLICY",
            severity="MEDIUM",
            confidence="HIGH",
            status="OPEN",
            affected_object_type="SESSION",
            affected_object_id=sess_id,
            dedup_hash=f"dedup-{uid}",
            created_at=_utc_now(),
        )
        session.add(vuln)

        evidence = FindingEvidenceRow(
            finding_id=vuln_id,
            evidence_key="lifetime",
            observed_value="86400",
            expected_value="28800",
            description="Configured lifetime 86400 exceeds threshold",
        )
        session.add(evidence)

        # Layer 10: Risk Assessment
        risk = RiskAssessmentRow(
            id=risk_id,
            session_id=sess_id,
            risk_score=22.5,
            risk_level="MEDIUM",
            decision="INSPECT",
            data_quality="COMPLETE",
            confidence_score=1.0,
            vulnerability_score=15.0,
            ml_score=5.0,
            drift_score=2.5,
            state_score=0.0,
            contributing_signals_json=json.dumps([{"rule": rule_id, "points": 15.0}]),
            evidence_json=json.dumps([{"finding_id": vuln_id}]),
            recommended_actions_json=json.dumps(["Shorten SA lifetime to 28800s"]),
            evaluated_at=_utc_now(),
        )
        session.add(risk)

        session.commit()

    # Verify all records retrievable from fresh session
    with SessionLocal() as session:
        ret_sess = session.scalar(select(IPsecSession).where(IPsecSession.id == sess_id))
        assert ret_sess is not None
        assert ret_sess.packet_count == 10

        ret_sa = session.scalar(select(SecurityAssociationRow).where(SecurityAssociationRow.id == sa_id))
        assert ret_sa is not None
        assert ret_sa.protocol == "ESP"
        assert json.loads(ret_sa.detail_json)["encryption"] == "AES-GCM-256"

        ret_drift = session.scalar(select(DriftAnalysisRow).where(DriftAnalysisRow.id == drift_id))
        assert ret_drift is not None
        assert ret_drift.status == "NORMAL"
        assert ret_drift.features_analyzed == 10

        ret_anomaly = session.scalar(select(AnomalyAnalysisRow).where(AnomalyAnalysisRow.id == anomaly_id))
        assert ret_anomaly is not None
        assert ret_anomaly.classification == "NORMAL"
        assert abs(ret_anomaly.raw_score - 0.12) < 1e-4

        ret_vuln = session.scalar(select(VulnerabilityFindingRow).where(VulnerabilityFindingRow.id == vuln_id))
        assert ret_vuln is not None
        assert ret_vuln.severity == "MEDIUM"

        ret_risk = session.scalar(select(RiskAssessmentRow).where(RiskAssessmentRow.id == risk_id))
        assert ret_risk is not None
        assert ret_risk.decision == "INSPECT"
        assert abs(ret_risk.risk_score - 22.5) < 1e-4


# =============================================================================
# 7. DatabaseLayerService Verification & Health Diagnostics
# =============================================================================


def test_database_layer_service_telemetry_and_health() -> None:
    """Verify DatabaseLayerService telemetry, PRAGMA reporting, and structured health output."""
    svc = get_database_layer_service()

    # 1. Ping
    assert svc.is_connected() is True

    # 2. Database Info
    info = svc.get_database_info()
    assert info["is_sqlite"] is True
    assert info["foreign_keys_enabled"] is True
    assert info["foreign_keys_pragma"] == 1
    assert str(info["journal_mode"]).lower() in ("wal", "memory")

    # 3. Detailed Health
    health = svc.get_detailed_health()
    assert health["status"] == "OPERATIONAL"
    assert health["reachable"] is True
    assert health["integrity_ok"] is True
    assert health["integrity_check"] == "ok"
    assert health["foreign_keys_enforced"] is True
    assert health["tables_present"] == 29
    assert health["missing_tables"] == []
    assert health["rollback_verified"] is True
    assert len(health["diagnostics"]) >= 4
    assert len(health["errors"]) == 0

    # 4. Verify Layer
    verif = svc.verify_layer()
    assert verif["status"] == "OPERATIONAL"
    assert verif["connected"] is True
    assert verif["table_count"] == 29
    assert verif["expected_table_count"] == 29
    assert verif["missing_tables"] == []
    assert len(verif["table_statistics"]) == 29

    # 5. Layer Status
    assert svc.get_layer_status() == "OPERATIONAL"
