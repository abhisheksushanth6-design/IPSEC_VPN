"""Comprehensive test suite for Layer 10 — Risk Assessment & Decision Engine."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.layers.layer10_risk_engine.evaluator import (
    EvaluationInput,
    RiskEvaluator,
    MAX_VULNERABILITY_SCORE,
    MAX_ML_SCORE,
    MAX_DRIFT_SCORE,
    MAX_STATE_SCORE,
    MAX_TOTAL_SCORE,
)
from app.layers.layer10_risk_engine.service import get_risk_engine_service
from app.models.ipsec_session import IPsecSession
from app.models.risk import RiskAssessmentRow


def test_risk_evaluator_sub_score_bounds() -> None:
    """Verify each risk component adheres strictly to mathematical bounds."""
    # 1. Vulnerability capping at 50
    huge_vulns = [
        {"id": f"v{i}", "severity": "CRITICAL", "rule_id": f"R-{i}", "title": "Critical"}
        for i in range(10)
    ]
    score, signals, evidence, has_crit, has_high = RiskEvaluator.calculate_vulnerability_score(huge_vulns)
    assert score == MAX_VULNERABILITY_SCORE
    assert has_crit is True

    # 2. ML capping at 30
    ml_data = {"raw_score": 1.5, "classification": "ANOMALOUS", "model_id": "M1"}
    ml_score, ml_signals, ml_evidence = RiskEvaluator.calculate_ml_score(ml_data)
    assert ml_score == MAX_ML_SCORE

    # Normal ML with low attack probability
    ml_normal = {"raw_score": 0.05, "classification": "NORMAL", "model_id": "M2"}
    norm_score, _, _ = RiskEvaluator.calculate_ml_score(ml_normal)
    assert norm_score == 0.5  # 10 * 0.05

    # 3. Drift capping at 12
    drift_crit = {"drift_detected": True, "severity": "CRITICAL", "overall_drift_score": 0.9}
    drift_score, _, _ = RiskEvaluator.calculate_drift_score(drift_crit)
    assert drift_score == MAX_DRIFT_SCORE

    # 4. State capping at 8
    events = [
        {"event_type": "REKEY FAILED", "description": "Rekey failure"},
        {"event_type": "ANTI-REPLAY VIOLATION", "description": "Replay drop"},
    ]
    state_score, _, _, has_crit_proto = RiskEvaluator.calculate_state_score([], events)
    assert state_score == MAX_STATE_SCORE
    assert has_crit_proto is True


def test_risk_evaluator_decisions_and_bands() -> None:
    """Verify deterministic mapping to risk bands and policy decisions."""
    # Clean baseline input
    clean_inp = EvaluationInput(
        session_id="S-CLEAN",
        session_info={"source": "10.0.0.1", "destination": "10.0.0.2", "state": "ESTABLISHED", "ike_version": "2.0"},
        sas=[{"id": "SA-1", "state": "ESTABLISHED", "protocol": "ESP"}],
        has_features=True,
        feature_count=10,
        has_baseline=True,
        baseline_id="BASE-1",
        drift_data={"drift_detected": False, "severity": "NONE", "overall_drift_score": 0.0},
        ml_data={"raw_score": 0.0, "classification": "NORMAL"},
        vulnerabilities=[],
    )
    (
        score,
        level,
        decision,
        quality,
        conf,
        breakdown,
        signals,
        evidence,
        recs,
        avail,
        unavail,
    ) = RiskEvaluator.evaluate(clean_inp)

    assert score == 0.0
    assert level == "LOW"
    assert decision == "ALLOW"
    assert quality == "COMPLETE"
    assert conf == 1.0
    assert len(unavail) == 0

    # Critical finding triggers TERMINATE decision
    crit_inp = EvaluationInput(
        session_id="S-CRIT",
        sas=[{"id": "SA-1", "state": "ESTABLISHED", "protocol": "ESP"}],
        vulnerabilities=[{"id": "v1", "severity": "CRITICAL", "rule_id": "R-1", "title": "Zero-Key"}],
    )
    score_c, level_c, decision_c, quality_c, conf_c, _, _, _, _, _, _ = RiskEvaluator.evaluate(crit_inp)
    assert score_c == 35.0
    assert level_c == "MEDIUM"  # 35.0 is in [20.0, 44.9]
    assert decision_c == "TERMINATE"  # Critical finding forces TERMINATE
    assert quality_c == "PARTIAL"


def test_risk_service_on_real_or_seeded_session(client) -> None:
    """Test full service evaluation and database persistence."""
    from app.db.base import SessionLocal

    svc = get_risk_engine_service()

    with SessionLocal() as session:
        # Find any existing session or create a lightweight test session
        sess = session.query(IPsecSession).first()
        if sess is None:
            sess = IPsecSession(
                id="IPSEC-TEST-UNIT",
                capture_id="CAP-UNIT",
                ordinal=1,
                source="192.168.1.10",
                destination="192.168.1.20",
                direction="INBOUND",
                state="ESTABLISHED",
                correlation="DIRECT",
                packet_count=10,
                byte_count=1500,
                detail_json="{}",
            )
            session.add(sess)
            session.commit()

        target_id = sess.id

        # 1. Evaluate session
        res = svc.evaluate_session(session, target_id, force_refresh=True)
        assert res.session_id == target_id
        assert 0.0 <= res.risk_score <= 100.0
        assert res.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert res.decision in ("ALLOW", "INSPECT", "RESTRICT", "TERMINATE")
        assert res.data_quality in ("COMPLETE", "PARTIAL")
        assert 0.0 <= res.confidence_score <= 1.0

        # 2. Verify persisted row in SQLite
        row = session.query(RiskAssessmentRow).filter(RiskAssessmentRow.session_id == target_id).first()
        assert row is not None
        assert row.risk_score == res.risk_score

        # 3. Cached retrieval
        cached = svc.get_session_assessment(session, target_id)
        assert cached is not None
        assert cached.id == res.id

        # 4. Summary metrics
        summary = svc.get_summary(session)
        assert summary.state == "OPERATIONAL"
        assert summary.assessed_sessions_count >= 1
        assert summary.overall_risk_score is not None


def test_risk_api_endpoints(client) -> None:
    """Verify HTTP API contracts for Layer 10 endpoints."""
    # 1. Status
    res = client.get("/api/risk/status")
    assert res.status_code == 200
    data = res.json()
    assert data["layer_number"] == 10
    assert data["status"] in ("READY", "OPERATIONAL")

    # 2. Summary
    res = client.get("/api/risk/summary")
    assert res.status_code == 200
    summary = res.json()
    assert summary["state"] in ("READY", "OPERATIONAL")

    # 3. Assessments list
    res = client.get("/api/risk/assessments")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    # 4. Non-existent session returns 404
    res = client.get("/api/risk/sessions/IPSEC-NON-EXISTENT-XYZ")
    assert res.status_code == 404

    # 5. Verify singular route does NOT exist (contract consistency)
    res_singular = client.get("/api/risk/session/IPSEC-NON-EXISTENT-XYZ")
    assert res_singular.status_code == 404

    # 6. Fetch existing session risk via plural contract
    from app.db.base import SessionLocal
    with SessionLocal() as db_session:
        sess = db_session.query(IPsecSession).first()
        if sess is not None:
            res_valid = client.get(f"/api/risk/sessions/{sess.id}")
            assert res_valid.status_code == 200
            data_valid = res_valid.json()
            assert data_valid["session_id"] == sess.id
            assert "risk_score" in data_valid
            assert "decision" in data_valid

