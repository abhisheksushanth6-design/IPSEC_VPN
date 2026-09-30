"""Standalone Reproducible Verification Script for Layer 10 — Risk Assessment & Decision Engine.

Validates:
1. Database connectivity and table schema integrity (RiskAssessmentRow, IPsecSession)
2. Empty input safety: deterministic 0.0 risk score, LOW level, ALLOW policy
3. Confidence score weighting (Weff = Wbase * confidence)
4. Recurrence damping logic (diminishing returns for repeated findings)
5. Finding status triage filter (RESOLVED / FALSE_POSITIVE / SUPPRESSED contribute 0 points & no overrides)
6. Sub-score component boundaries and clamping (Vuln max 50, ML max 30, Drift max 12, State max 8)
7. Exact risk level and policy decision threshold boundaries (0.0, 19.9, 20.0, 44.9, 45.0, 69.9, 70.0, 100.0)
8. Mandatory policy decision override logic (CRITICAL findings / rekey failures -> TERMINATE)
9. Database session risk evaluation and persistence
10. Assessment lookup by ID (get_assessment_by_id)
11. Audit export functionality (export_assessments)
12. Dynamic evidence-based layer health check (get_layer_status)
"""

from __future__ import annotations

import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.base import SessionLocal
from app.db.init_db import initialize_database
from app.layers.layer10_risk_engine import (
    DECISION_TO_ALIAS,
    EvaluationInput,
    PolicyDecision,
    PolicyDecisionAlias,
    RiskEvaluator,
    get_detailed_status,
    get_layer_status,
    get_risk_engine_service,
)
from app.models.ipsec_session import IPsecSession
from app.models.risk import RiskAssessmentRow
from app.models.vulnerability import VulnerabilityFindingRow


def print_section(title: str) -> None:
    print(f"\n{'='*70}\n[LAYER 10 VERIFICATION] {title}\n{'='*70}")


def main() -> int:
    service = get_risk_engine_service()

    print_section("Step 1: Database Initialization & Integrity Check")
    initialize_database()
    db = SessionLocal()

    try:
        # Clean any prior verification test rows
        db.query(RiskAssessmentRow).filter(RiskAssessmentRow.session_id.like("verify-l10-%")).delete()
        db.query(VulnerabilityFindingRow).filter(VulnerabilityFindingRow.affected_session_id.like("verify-l10-%")).delete()
        db.query(IPsecSession).filter(IPsecSession.id.like("verify-l10-%")).delete()
        db.commit()
        print("[OK] Database connection verified. Tables accessible.")

        print_section("Step 2: Empty Input Safety (Zero-Risk Baseline)")
        empty_input = EvaluationInput(session_id="verify-l10-empty")
        total_score, level, decision, quality, conf, breakdown, signals, evidence, recs, avail, unavail = (
            RiskEvaluator.evaluate(empty_input)
        )
        assert total_score == 0.0, f"Expected 0.0, got {total_score}"
        assert level == "LOW", f"Expected LOW, got {level}"
        assert decision == "ALLOW", f"Expected ALLOW, got {decision}"
        alias = DECISION_TO_ALIAS[decision]
        assert alias == "ALLOW", f"Expected ALLOW alias, got {alias}"
        assert breakdown.total_risk_score == 0.0
        print(f"[OK] Empty input returns score={total_score}, level={level}, decision={decision} (Alias: {alias})")

        print_section("Step 3: Confidence Score Weighting Verification")
        full_conf_findings = [
            {"id": 1, "severity": "HIGH", "status": "OPEN", "confidence": 1.0, "recurrence_count": 1, "title": "Full conf"}
        ]
        half_conf_findings = [
            {"id": 2, "severity": "HIGH", "status": "OPEN", "confidence": 0.5, "recurrence_count": 1, "title": "Half conf"}
        ]
        score_full, _, _, _, _ = RiskEvaluator.calculate_vulnerability_score(full_conf_findings)
        score_half, _, _, _, _ = RiskEvaluator.calculate_vulnerability_score(half_conf_findings)
        print(f"[INFO] High finding (base 20.0): 100% conf -> {score_full}, 50% conf -> {score_half}")
        assert score_full == 20.0, f"Expected 20.0, got {score_full}"
        assert score_half == 10.0, f"Expected 10.0, got {score_half}"
        print("[OK] Confidence score weighting correctly scales vulnerability points linearly.")

        print_section("Step 4: Recurrence Damping Logic")
        # Base HIGH = 20.0. For recurrence=4, repeat occurrences add:
        # min(20.0 * 0.2 * log2(4), 20.0 * 0.5) = min(8.0, 10.0) = 8.0 -> total 28.0
        rec1 = [{"id": 10, "rule_id": "R1", "affected_object_id": "SA-1", "severity": "HIGH", "status": "OPEN", "recurrence_count": 1}]
        rec4 = [
            {"id": 11, "rule_id": "R1", "affected_object_id": "SA-1", "severity": "HIGH", "status": "OPEN", "recurrence_count": 4}
        ]
        score_rec1, _, _, _, _ = RiskEvaluator.calculate_vulnerability_score(rec1)
        score_rec4, _, _, _, _ = RiskEvaluator.calculate_vulnerability_score(rec4)
        print(f"[INFO] Recurrence 1: {score_rec1}, Recurrence 4: {score_rec4}")
        assert score_rec1 == 20.0
        assert math.isclose(score_rec4, 28.0, abs_tol=0.01)
        print("[OK] Recurrence damping functions as designed with logarithmic damping.")

        print_section("Step 5: Finding Status Triage Filter")
        open_crit = [{"id": 1, "severity": "CRITICAL", "status": "OPEN", "confidence": 1.0, "recurrence_count": 1, "title": "Open"}]
        res_crit = [{"id": 2, "severity": "CRITICAL", "status": "RESOLVED", "confidence": 1.0, "recurrence_count": 1, "title": "Resolved"}]
        fp_crit = [{"id": 3, "severity": "CRITICAL", "status": "FALSE_POSITIVE", "confidence": 1.0, "recurrence_count": 1, "title": "FP"}]
        sup_crit = [{"id": 4, "severity": "CRITICAL", "status": "SUPPRESSED", "confidence": 1.0, "recurrence_count": 1, "title": "Suppressed"}]

        score_open, _, _, has_crit_open, _ = RiskEvaluator.calculate_vulnerability_score(open_crit)
        score_res, _, ev_res, has_crit_res, _ = RiskEvaluator.calculate_vulnerability_score(res_crit)
        score_fp, _, _, has_crit_fp, _ = RiskEvaluator.calculate_vulnerability_score(fp_crit)
        score_sup, _, _, has_crit_sup, _ = RiskEvaluator.calculate_vulnerability_score(sup_crit)

        assert score_open == 35.0 and has_crit_open is True
        assert score_res == 0.0 and has_crit_res is False
        assert score_fp == 0.0 and has_crit_fp is False
        assert score_sup == 0.0 and has_crit_sup is False

        # Evidence is preserved for auditability
        assert len(ev_res) == 1, "Resolved finding must remain in audit evidence"
        print("[OK] Status filter verified: RESOLVED / FALSE_POSITIVE / SUPPRESSED do not elevate score or trigger TERMINATE.")

        print_section("Step 6: Component Max Sub-Score Caps & Global Clamping")
        many_crit = [
            {"id": i, "severity": "CRITICAL", "status": "OPEN", "confidence": 1.0, "recurrence_count": 1, "title": f"Crit {i}"}
            for i in range(5)
        ]
        input_caps = EvaluationInput(
            session_id="verify-l10-caps",
            vulnerabilities=many_crit,  # sum would be 175 -> capped at 50.0
            ml_data={"classification": "ANOMALOUS", "raw_score": 1.0, "display_score": 100.0, "model_id": "IF-01"},  # capped at 30.0
            drift_data={"drift_detected": True, "severity": "CRITICAL", "overall_drift_score": 0.95, "features_drifting": 8},  # capped at 12.0
            sas=[{"state": "EXPIRED", "spi_in": "0x1", "spi_out": "0x2", "rekey_errors": 5}],  # capped at 8.0
            lifecycle_events=[{"event_type": "REKEY_FAILURE"}, {"event_type": "ANTI_REPLAY_VIOLATION"}],
        )
        tot, lvl, dec, _, _, bd, _, _, _, _, _ = RiskEvaluator.evaluate(input_caps)
        assert bd.vulnerability_score == 50.0, f"Vuln score {bd.vulnerability_score} exceeded cap 50.0"
        assert bd.ml_score == 30.0, f"ML score {bd.ml_score} exceeded cap 30.0"
        assert bd.drift_score == 12.0, f"Drift score {bd.drift_score} exceeded cap 12.0"
        assert bd.state_score == 8.0, f"State score {bd.state_score} exceeded cap 8.0"
        assert tot == 100.0, f"Total score {tot} exceeded cap 100.0"
        print(f"[OK] Caps verified: Vuln={bd.vulnerability_score}/50, ML={bd.ml_score}/30, Drift={bd.drift_score}/12, State={bd.state_score}/8, Total={tot}/100")

        print_section("Step 7: Exact Threshold Boundaries & Policy Decisions")
        test_boundaries = [
            (0.0, "LOW", "ALLOW", "ALLOW"),
            (19.9, "LOW", "ALLOW", "ALLOW"),
            (20.0, "MEDIUM", "INSPECT", "WARN"),
            (44.9, "MEDIUM", "INSPECT", "WARN"),
            (45.0, "HIGH", "RESTRICT", "ISOLATE"),
            (69.9, "HIGH", "RESTRICT", "ISOLATE"),
            (70.0, "CRITICAL", "TERMINATE", "BLOCK"),
            (100.0, "CRITICAL", "TERMINATE", "BLOCK"),
        ]
        for score, exp_lvl, exp_dec, exp_alias in test_boundaries:
            lvl = RiskEvaluator.classify_risk_level(score)
            dec, alias = RiskEvaluator.determine_decision(score, has_critical=False, has_high=False)
            assert lvl == exp_lvl, f"Score {score}: expected {exp_lvl}, got {lvl}"
            assert dec == exp_dec, f"Score {score}: expected {exp_dec}, got {dec}"
            assert alias == exp_alias, f"Score {score}: expected {exp_alias}, got {alias}"
            print(f"  - Score {score:5.1f} -> Level: {lvl:<8} Decision: {dec:<9} Alias: {alias}")
        print("[OK] All 8 exact boundary conditions strictly verified.")

        print_section("Step 8: Mandatory Decision Overrides")
        # Low score (15.0) but with CRITICAL finding -> must force TERMINATE (BLOCK)
        dec_crit, alias_crit = RiskEvaluator.determine_decision(15.0, has_critical=True, has_high=False)
        assert dec_crit == "TERMINATE" and alias_crit == "BLOCK"
        print(f"[OK] Critical finding override verified: Score=15.0 + Critical -> {dec_crit} ({alias_crit})")

        # Low score (10.0) but with HIGH finding -> must force at least INSPECT (WARN)
        dec_high, alias_high = RiskEvaluator.determine_decision(10.0, has_critical=False, has_high=True)
        assert dec_high == "INSPECT" and alias_high == "WARN"
        print(f"[OK] High finding elevation verified: Score=10.0 + High -> {dec_high} ({alias_high})")

        print_section("Step 9: Database Session Risk Evaluation & Persistence")
        test_session_id = "verify-l10-sess-001"
        sess = IPsecSession(
            id=test_session_id,
            capture_id="verify-cap-001",
            ordinal=1,
            source="192.168.10.10",
            destination="192.168.20.20",
            direction="BIDIRECTIONAL",
            state="ACTIVE",
            correlation="CORRELATED",
            packet_count=100,
            byte_count=15000,
            ike_packets=20,
            esp_packets=80,
            detail_json="{}",
            discovered_at=datetime.now(timezone.utc),
        )
        db.add(sess)

        finding = VulnerabilityFindingRow(
            id="verify-l10-finding-001",
            rule_id="RULE-CRYPTO-001",
            rule_version="1.0",
            title="Deprecated 3DES Cipher in Active SA",
            description="Negotiated 3DES cipher violates RFC 8221.",
            category="CRYPTO",
            severity="CRITICAL",
            confidence="CRITICAL",
            status="OPEN",
            affected_object_type="SecurityAssociation",
            affected_object_id="sa-spi-verify-001",
            affected_session_id=test_session_id,
            dedup_hash="verify-l10-hash-001",
            occurrence_count=1,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.commit()

        assessment_resp = service.evaluate_session(db, test_session_id, force_refresh=True)
        assert assessment_resp.session_id == test_session_id
        assert assessment_resp.risk_score >= 30.0
        assert assessment_resp.decision == "TERMINATE"  # Critical finding forces TERMINATE
        assert assessment_resp.decision_alias == "BLOCK"
        assert assessment_resp.is_advisory is True
        assert assessment_resp.severity_summary["CRITICAL"] >= 1
        print(f"[OK] Persisted assessment ID: {assessment_resp.id}")
        print(f"  - Score: {assessment_resp.risk_score}, Level: {assessment_resp.risk_level}")
        print(f"  - Decision: {assessment_resp.decision} ({assessment_resp.decision_alias}), Advisory: {assessment_resp.is_advisory}")

        print_section("Step 10: Assessment Lookup by ID (get_assessment_by_id)")
        fetched = service.get_assessment_by_id(db, assessment_resp.id)
        assert fetched is not None, f"Expected to find assessment {assessment_resp.id}"
        assert fetched.id == assessment_resp.id
        assert fetched.session_id == test_session_id

        missing = service.get_assessment_by_id(db, "NONEXISTENT-ID")
        assert missing is None, "Expected None for missing ID"
        print(f"[OK] get_assessment_by_id verified: found={fetched.id}, nonexistent=None")

        print_section("Step 11: Audit Export Functionality (export_assessments)")
        export_data = service.export_assessments(db, session_id=test_session_id)
        assert export_data.export_version == "1.0.0"
        assert export_data.total_assessments >= 1
        assert export_data.metadata["is_advisory"] is True
        assert len(export_data.assessments) >= 1
        assert export_data.assessments[0].session_id == test_session_id

        # Verify JSON serializability
        export_json = json.dumps(export_data.model_dump(), default=str)
        assert len(export_json) > 100
        print(f"[OK] Export audit trail verified ({len(export_json)} bytes JSON, {export_data.total_assessments} assessments)")

        print_section("Step 12: Dynamic Evidence-Based Layer Health Check")
        operational_str = get_layer_status(db)
        assert operational_str == "OPERATIONAL", f"Expected OPERATIONAL, got {operational_str}"

        status_info = get_detailed_status(db)
        assert status_info["status"] == "OPERATIONAL", f"Expected OPERATIONAL, got {status_info['status']}"
        assert status_info["is_advisory"] is True, "Expected is_advisory=True"
        assert status_info["checks"]["evaluator_loaded"] is True
        assert status_info["checks"]["dry_run_passed"] is True
        assert status_info["checks"]["database_connected"] is True
        assert status_info["checks"]["tables_verified"] is True
        print(f"[OK] Dynamic status: {operational_str}, Advisory: {status_info['is_advisory']}")
        print(f"  - Diagnostic Checks: {status_info['checks']}")

        # Cleanup verification test rows
        db.query(RiskAssessmentRow).filter(RiskAssessmentRow.session_id.like("verify-l10-%")).delete()
        db.query(VulnerabilityFindingRow).filter(VulnerabilityFindingRow.affected_session_id.like("verify-l10-%")).delete()
        db.query(IPsecSession).filter(IPsecSession.id.like("verify-l10-%")).delete()
        db.commit()
        print("[OK] Test rows cleaned up successfully.")

    finally:
        db.close()

    print(f"\n{'='*70}\n[SUCCESS] ALL 12 LAYER 10 VERIFICATION STEPS PASSED PERFECTLY!\n{'='*70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
