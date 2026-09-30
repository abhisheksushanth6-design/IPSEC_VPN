"""Backend tests for Layer 13 — Web Dashboard API endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from app.db.base import SessionLocal
from app.db.init_db import initialize_database
from app.models.drift import DriftAnalysisRow, FeatureDriftRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import AnomalyAnalysisRow, AnomalyFeatureContributionRow
from app.models.security_association import SALifecycleEventRow, SecurityAssociationRow
from app.models.risk import RiskAssessmentRow
from app.models.vulnerability import FindingEvidenceRow, SecurityRuleRow, VulnerabilityFindingRow


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def clean_db():
    """Ensure a clean database state for dashboard tests."""
    initialize_database()
    db = SessionLocal()
    try:
        db.query(RiskAssessmentRow).delete()
        db.query(FeatureDriftRow).delete()
        db.query(DriftAnalysisRow).delete()
        db.query(FindingEvidenceRow).delete()
        db.query(VulnerabilityFindingRow).delete()
        db.query(SecurityRuleRow).delete()
        db.query(AnomalyFeatureContributionRow).delete()
        db.query(AnomalyAnalysisRow).delete()
        db.query(SALifecycleEventRow).delete()
        db.query(SecurityAssociationRow).delete()
        db.query(IPsecSession).delete()
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(RiskAssessmentRow).delete()
        db.query(FeatureDriftRow).delete()
        db.query(DriftAnalysisRow).delete()
        db.query(FindingEvidenceRow).delete()
        db.query(VulnerabilityFindingRow).delete()
        db.query(SecurityRuleRow).delete()
        db.query(AnomalyFeatureContributionRow).delete()
        db.query(AnomalyAnalysisRow).delete()
        db.query(SALifecycleEventRow).delete()
        db.query(SecurityAssociationRow).delete()
        db.query(IPsecSession).delete()
        db.commit()
    finally:
        db.close()


def test_dashboard_endpoints_empty_db(client) -> None:
    """Dashboard endpoints succeed on clean/empty database with zero fabrication."""
    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    data = res.json()

    # Posture
    assert data["posture"]["backend_status"] == "OPERATIONAL"
    assert data["posture"]["layers_total"] == 10
    assert data["posture"]["layers_initialized"] == 10

    # Metrics
    assert data["metrics"]["overall_risk_score"] is None
    assert data["metrics"]["overall_risk_status"] in ("NOT INITIALIZED", "READY", "OPERATIONAL")
    assert data["metrics"]["active_vpn_sessions"] == 0
    assert data["metrics"]["active_sas"] == 0
    assert data["metrics"]["ai_anomalies"] == 0
    assert data["metrics"]["drift_events"] == 0
    assert data["metrics"]["vulnerabilities_total"] == 0
    assert data["metrics"]["capture_status"] in ("READY", "IDLE")

    # Collections are clean empty lists, not fabricated
    assert data["recent_sessions"] == []
    assert data["recent_events"] == []
    assert isinstance(data["protocol_posture"], dict)
    assert data["protocol_posture"]["ike_versions"] == []


def test_dashboard_metrics_endpoint(client) -> None:
    """GET /api/dashboard/metrics returns exact schema with null risk score."""
    res = client.get("/api/dashboard/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert metrics["overall_risk_score"] is None
    assert metrics["overall_risk_status"] in ("NOT INITIALIZED", "READY", "OPERATIONAL")
    assert "packets_analyzed" in metrics
    assert "vulnerabilities_critical" in metrics


def test_dashboard_timeline_endpoint(client) -> None:
    """GET /api/dashboard/timeline returns an array of real events."""
    res = client.get("/api/dashboard/timeline?limit=10")
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)


def test_dashboard_protocols_endpoint(client) -> None:
    """GET /api/dashboard/protocols returns protocol posture schema."""
    res = client.get("/api/dashboard/protocols")
    assert res.status_code == 200
    posture = res.json()
    assert "ike_versions" in posture
    assert "observed_encryption_algorithms" in posture
    assert "observed_dh_groups" in posture


def test_dashboard_with_populated_security_entities(client) -> None:
    """Populate real rows across layers 04, 08, 09 and verify aggregation."""
    now = _utc_now()

    with SessionLocal() as db_session:
        # 1. Create a session
        session = IPsecSession(
            id="sess-dash-01",
            capture_id="cap-01",
            ordinal=1,
            source="192.168.1.10",
            destination="192.168.1.20",
            direction="OUTBOUND",
            state="ACTIVE",
            correlation="DIRECT",
            start_time="2026-09-04T10:00:00Z",
            duration_seconds=120.5,
            packet_count=45,
            byte_count=4500,
            ike_packets=10,
            esp_packets=35,
            ah_packets=0,
            ike_version="IKEv2",
            nat_traversal=False,
            detail_json=json.dumps({
                "ike_info": {"version": "2", "cipher": "AES-CBC-256", "dh_group": 14},
                "esp_info": {"cipher": "AES-GCM-256"},
            }),
            discovered_at=now,
        )
        db_session.add(session)

        # 2. Create an SA with lifecycle event
        sa = SecurityAssociationRow(
            id="sa-dash-01",
            capture_id="cap-01",
            type="IKE",
            state="ESTABLISHED",
            protocol="IKE",
            initiator="192.168.1.10",
            responder="192.168.1.20",
            ike_version="IKEv2",
            packet_count=10,
            byte_count=1200,
            association="DIRECT",
            session_id="sess-dash-01",
            detail_json=json.dumps({"encryption_algorithm": "AES-CBC-256", "dh_group": "MODP_2048", "pfs_enabled": True}),
            discovered_at=now,
        )
        db_session.add(sa)

        sa_evt = SALifecycleEventRow(
            sa_id="sa-dash-01",
            sequence=1,
            timestamp="2026-09-04T10:00:02Z",
            event_type="SA_ESTABLISHED",
            previous_state="NEGOTIATING",
            new_state="ESTABLISHED",
            description="IKE SA negotiation established successfully.",
        )
        db_session.add(sa_evt)

        # 3. Create an AI/ML Anomaly
        anomaly = AnomalyAnalysisRow(
            id="anom-dash-01",
            session_id="sess-dash-01",
            model_id="model-isoforest-01",
            classification="ANOMALOUS",
            raw_score=0.78,
            display_score=82.5,
            features_analyzed=100,
            features_anomalous=3,
            explanation_summary="Abnormal packet inter-arrival bursts detected.",
            analyzed_at=now,
        )
        db_session.add(anomaly)

        # 4. Create a Vulnerability Rule and Finding
        rule = SecurityRuleRow(
            id="RULE-TEST-001",
            name="Test Cryptographic Rule",
            category="CRYPTO",
            severity="HIGH",
            default_confidence="HIGH",
            enabled=True,
            version="1.0",
            description="Test rule description",
            remediation="Upgrade cryptography",
            references_json="[]",
            created_at=now,
            updated_at=now,
        )
        db_session.add(rule)

        finding = VulnerabilityFindingRow(
            id="vuln-dash-01",
            rule_id="RULE-TEST-001",
            rule_version="1.0",
            title="Insecure Cipher Detected",
            description="Legacy cryptographic transform observed in session.",
            category="CRYPTO",
            severity="HIGH",
            confidence="HIGH",
            status="OPEN",
            affected_object_type="SESSION",
            affected_object_id="sess-dash-01",
            affected_session_id="sess-dash-01",
            dedup_hash="hash-dash-001",
            occurrence_count=1,
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db_session.add(finding)
        db_session.commit()

    # Query dashboard summary
    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    data = res.json()

    # Verify metrics aggregation
    assert data["metrics"]["active_vpn_sessions"] == 1
    assert data["metrics"]["active_sas"] == 1
    assert data["metrics"]["ai_anomalies"] == 1
    assert data["metrics"]["vulnerabilities_total"] == 1
    assert data["metrics"]["vulnerabilities_high"] == 1
    assert data["metrics"]["overall_risk_score"] is None or isinstance(data["metrics"]["overall_risk_score"], (int, float))

    # Verify recent sessions
    assert len(data["recent_sessions"]) == 1
    sess_item = data["recent_sessions"][0]
    assert sess_item["session_id"] == "sess-dash-01"
    assert sess_item["has_anomaly"] is True
    assert sess_item["anomaly_score"] == 82.5
    assert sess_item["vulnerabilities_count"] == 1
    assert sess_item["sa_count"] == 1

    # Verify timeline events contain synthesized items from layers
    events = data["recent_events"]
    assert len(events) >= 3
    event_types = {e["event_type"] for e in events}
    assert "Vulnerability Detected" in event_types
    assert "AI Anomaly Detected" in event_types

    # Verify protocol posture
    proto = data["protocol_posture"]
    assert "IKEv2" in proto["ike_versions"] or "2" in proto["ike_versions"]
    assert any("AES" in a for a in proto["observed_encryption_algorithms"])
