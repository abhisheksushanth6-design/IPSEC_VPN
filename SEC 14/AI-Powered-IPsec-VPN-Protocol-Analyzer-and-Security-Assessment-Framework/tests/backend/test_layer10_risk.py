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


def test_risk_evaluator_exact_threshold_boundaries() -> None:
    """Verify exact score boundaries for risk bands and policy decisions."""
    test_cases = [
        (0.0, "LOW", "ALLOW", "ALLOW"),
        (19.9, "LOW", "ALLOW", "ALLOW"),
        (20.0, "MEDIUM", "INSPECT", "WARN"),
        (44.9, "MEDIUM", "INSPECT", "WARN"),
        (45.0, "HIGH", "RESTRICT", "ISOLATE"),
        (69.9, "HIGH", "RESTRICT", "ISOLATE"),
        (70.0, "CRITICAL", "TERMINATE", "BLOCK"),
        (100.0, "CRITICAL", "TERMINATE", "BLOCK"),
        (-5.0, "LOW", "ALLOW", "ALLOW"),
        (150.0, "CRITICAL", "TERMINATE", "BLOCK"),
    ]
    for raw_score, expected_level, expected_decision, expected_alias in test_cases:
        level = RiskEvaluator.classify_risk_level(raw_score)
        dec, alias = RiskEvaluator.determine_decision(raw_score)
        assert level == expected_level, f"Score {raw_score} expected level {expected_level}, got {level}"
        assert dec == expected_decision, f"Score {raw_score} expected decision {expected_decision}, got {dec}"
        assert alias == expected_alias, f"Score {raw_score} expected alias {expected_alias}, got {alias}"


def test_risk_evaluator_finding_status_filtering() -> None:
    """Verify resolved, false positive, and suppressed findings do not inflate risk score."""
    findings = [
        {"id": "v-open", "severity": "HIGH", "rule_id": "R-1", "title": "Active High", "status": "OPEN"},
        {"id": "v-resolved", "severity": "CRITICAL", "rule_id": "R-2", "title": "Resolved Crit", "status": "RESOLVED"},
        {"id": "v-fp", "severity": "HIGH", "rule_id": "R-3", "title": "False Positive", "status": "FALSE_POSITIVE"},
        {"id": "v-suppressed", "severity": "MEDIUM", "rule_id": "R-4", "title": "Suppressed Med", "status": "SUPPRESSED"},
    ]
    score, signals, evidence, has_crit, has_high = RiskEvaluator.calculate_vulnerability_score(findings)
    # Only v-open (HIGH = 20.0) counts
    assert score == 20.0
    assert has_crit is False  # Resolved critical does NOT trigger critical override
    assert has_high is True   # Active high triggers high override
    assert len(signals) == 1
    assert signals[0].evidence_reference == "v-open"
    # All 4 findings retained in evidence trail for audit integrity
    assert len(evidence) == 4
    resolved_item = next(e for e in evidence if e.identifier == "v-resolved")
    assert "STATUS: RESOLVED" in resolved_item.summary


def test_risk_evaluator_confidence_weighting() -> None:
    """Verify finding confidence scales risk contribution appropriately."""
    # Confidence 0.5 on HIGH (base 20.0) -> 10.0 points
    findings_half = [
        {"id": "v1", "severity": "HIGH", "rule_id": "R-1", "title": "Half Conf", "confidence": 0.5, "status": "OPEN"}
    ]
    score_half, signals_half, _, _, has_high_half = RiskEvaluator.calculate_vulnerability_score(findings_half)
    assert score_half == 10.0
    assert has_high_half is True

    # Low confidence (< 0.5) does not trigger severe policy override
    findings_low_conf = [
        {"id": "v2", "severity": "CRITICAL", "rule_id": "R-2", "title": "Low Conf Crit", "confidence": 0.2, "status": "OPEN"}
    ]
    score_low, _, _, has_crit_low, _ = RiskEvaluator.calculate_vulnerability_score(findings_low_conf)
    assert score_low == 7.0  # 35 * 0.2
    assert has_crit_low is False  # confidence < 0.5 does NOT trigger critical override


def test_risk_evaluator_recurrence_and_deduplication() -> None:
    """Verify deduplication ignores identical IDs and applies recurrence damping."""
    # Duplicate IDs are ignored
    findings_dup = [
        {"id": "v-dup", "severity": "MEDIUM", "rule_id": "R-1", "title": "Dup 1", "status": "OPEN"},
        {"id": "v-dup", "severity": "MEDIUM", "rule_id": "R-1", "title": "Dup 2", "status": "OPEN"},
    ]
    score_dup, signals_dup, _, _, _ = RiskEvaluator.calculate_vulnerability_score(findings_dup)
    assert score_dup == 10.0
    assert len(signals_dup) == 1

    # Recurrence damping on repeated observations
    finding_rec = [
        {"id": "v-rec", "severity": "MEDIUM", "rule_id": "R-1", "recurrence_count": 8, "status": "OPEN"}
    ]
    score_rec, _, _, _, _ = RiskEvaluator.calculate_vulnerability_score(finding_rec)
    # Base 10.0 + min(10.0 * 0.2 * log2(8)=6.0, 10.0 * 0.5=5.0) = 15.0
    assert score_rec == 15.0


def test_risk_evaluator_decision_overrides() -> None:
    """Verify critical findings and protocol failures override total score thresholds."""
    # Critical finding with low total score forces TERMINATE / BLOCK
    inp_crit = EvaluationInput(
        session_id="S-OVR-1",
        vulnerabilities=[{"id": "v1", "severity": "CRITICAL", "confidence": 1.0, "status": "OPEN"}],
    )
    score, level, decision, _, _, _, _, _, _, _, _ = RiskEvaluator.evaluate(inp_crit)
    assert score == 35.0  # Medium score band
    assert level == "MEDIUM"
    assert decision == "TERMINATE"  # Overridden by critical finding

    # Rekey failure forces TERMINATE / BLOCK
    inp_rekey = EvaluationInput(
        session_id="S-OVR-2",
        lifecycle_events=[{"event_type": "REKEY_FAILURE", "description": "IKE SA rekey error"}],
    )
    score_rk, level_rk, decision_rk, _, _, _, _, _, _, _, _ = RiskEvaluator.evaluate(inp_rekey)
    assert score_rk == 5.0
    assert level_rk == "LOW"
    assert decision_rk == "TERMINATE"  # Rekey failure is an active protocol breach


def test_risk_evaluator_empty_and_missing_inputs() -> None:
    """Verify evaluation handles completely empty and missing signals safely."""
    empty_inp = EvaluationInput(session_id="S-EMPTY")
    score, level, decision, quality, conf, breakdown, signals, evidence, recs, avail, unavail = (
        RiskEvaluator.evaluate(empty_inp)
    )
    assert score == 0.0
    assert level == "LOW"
    assert decision == "ALLOW"
    assert quality == "PARTIAL"
    assert conf < 1.0
    assert len(signals) == 0
    assert breakdown.total_risk_score == 0.0
    assert len(recs) > 0


def test_risk_evaluator_severity_summary() -> None:
    """Verify active finding counts by severity."""
    findings = [
        {"id": "1", "severity": "CRITICAL", "status": "OPEN"},
        {"id": "2", "severity": "HIGH", "status": "CONFIRMED"},
        {"id": "3", "severity": "HIGH", "status": "RESOLVED"},  # Excluded
        {"id": "4", "severity": "LOW", "status": "OPEN"},
    ]
    summary = RiskEvaluator.count_severity_summary(findings)
    assert summary["CRITICAL"] == 1
    assert summary["HIGH"] == 1
    assert summary["MEDIUM"] == 0
    assert summary["LOW"] == 1


def test_risk_service_assessment_by_id_and_export(client) -> None:
    """Test get_assessment_by_id, export_assessments, and detailed status service methods."""
    from app.db.base import SessionLocal

    svc = get_risk_engine_service()
    with SessionLocal() as db:
        # Create test session
        sess = db.query(IPsecSession).first()
        if sess is None:
            sess = IPsecSession(
                id="IPSEC-SESS-SRV-TEST",
                capture_id="CAP-TEST",
                ordinal=1,
                source="10.0.0.1",
                destination="10.0.0.2",
                direction="INBOUND",
                state="ESTABLISHED",
                correlation="DIRECT",
                packet_count=5,
                byte_count=500,
                detail_json="{}",
            )
            db.add(sess)
            db.commit()

        assessment = svc.evaluate_session(db, sess.id, force_refresh=True)

        # 1. get_assessment_by_id
        found = svc.get_assessment_by_id(db, assessment.id)
        assert found is not None
        assert found.id == assessment.id
        assert found.decision_alias in ("ALLOW", "WARN", "ISOLATE", "BLOCK")
        assert found.is_advisory is True

        # Non-existent ID returns None
        assert svc.get_assessment_by_id(db, "NON-EXISTENT-RISK-ID") is None

        # 2. export_assessments
        exp = svc.export_assessments(db, session_id=sess.id)
        assert exp.total_assessments >= 1
        assert exp.export_version == "1.0.0"
        assert len(exp.assessments) >= 1

        # 3. get_detailed_status
        detailed = svc.get_detailed_status(db)
        assert detailed["status"] in ("OPERATIONAL", "READY")
        assert detailed["checks"]["evaluator_loaded"] is True
        assert detailed["checks"]["dry_run_passed"] is True
        assert detailed["checks"]["database_connected"] is True


def test_risk_api_export_and_id_endpoints(client) -> None:
    """Test GET /api/risk/export and GET /api/risk/assessments/{assessment_id}."""
    from app.db.base import SessionLocal
    from app.models.risk import RiskAssessmentRow

    with SessionLocal() as db:
        row = db.query(RiskAssessmentRow).first()
        if row is None:
            svc = get_risk_engine_service()
            sess = db.query(IPsecSession).first()
            if sess:
                svc.evaluate_session(db, sess.id, force_refresh=True)
                row = db.query(RiskAssessmentRow).first()

    # 1. Export endpoint
    res_export = client.get("/api/risk/export")
    assert res_export.status_code == 200
    export_data = res_export.json()
    assert "export_version" in export_data
    assert "assessments" in export_data
    assert isinstance(export_data["assessments"], list)

    # 2. Assessment by ID endpoint
    if row is not None:
        res_id = client.get(f"/api/risk/assessments/{row.id}")
        assert res_id.status_code == 200
        data_id = res_id.json()
        assert data_id["id"] == row.id
        assert "decision_alias" in data_id
        assert data_id["is_advisory"] is True

    # 3. Invalid assessment ID returns 404
    res_404 = client.get("/api/risk/assessments/RISK-DOES-NOT-EXIST-404")
    assert res_404.status_code == 404

