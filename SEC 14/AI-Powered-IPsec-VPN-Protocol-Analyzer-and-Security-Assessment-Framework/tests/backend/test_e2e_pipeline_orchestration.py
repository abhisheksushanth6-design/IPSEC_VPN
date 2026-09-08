"""Regression test suite for End-to-End Pipeline Orchestration & Layer 5-10 Integration.

Covers all 8 priority areas:
1. Layer 2 live-capture downstream orchestration (L3 -> L4 -> L5 -> L6 -> L7 -> L8 -> L9 -> L10)
2. Layer 5 feature extraction & persistence
3. Layer 6 fingerprinting & behavioral identification
4. Layer 7 baseline precondition enforcement (no fake drift)
5. Layer 8 XGBoost checksum synchronization, integrity check, & inference
6. Layer 10 signal aggregation, confidence scoring, & quality semantics
7. Current-capture filtering in evaluate_all_sessions & API
8. Full 14-layer architecture end-to-end integration
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

import packet_builders as B
from app.db.base import SessionLocal
from app.layers.layer02_packet_capture.service import LiveCaptureService
from app.layers.layer06_session_fingerprinting.fingerprint import build_session_fingerprint
from app.layers.layer06_session_fingerprinting.service import build_baseline_profile
from app.layers.layer08_ai_ml.cicids_bundle import ensure_cicids_model_registered
from app.layers.layer08_ai_ml.cicids_features import CICIDS_MODEL_ID
from app.layers.layer08_ai_ml.registry import model_registry
from app.layers.layer08_ai_ml.schemas import AnomalyInferenceRequest
from app.layers.layer08_ai_ml.service import AIAnomalyService
from app.layers.layer10_risk_engine.evaluator import EvaluationInput, RiskEvaluator
from app.layers.layer10_risk_engine.service import get_risk_engine_service
from app.models.baseline import (
    BaselineFeatureRow,
    BaselineProfileRow,
    BaselineSessionLinkRow,
    SessionFingerprintRow,
)
from app.models.drift import DriftAnalysisRow
from app.models.feature_vector import FeatureVectorRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import AnomalyAnalysisRow, MLModelRow
from app.models.risk import RiskAssessmentRow
from app.models.security_association import SecurityAssociationRow
from app.services.baseline_service import baseline_service
from app.services.drift_service import DriftService
from app.services.feature_service import feature_service
from app.services.fingerprint_service import fingerprint_service
from app.services.packet_service import packet_service
from test_fingerprint import _make_sample_session_vector


TEST_FRAMES = [
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0), 500, 500), 17)),
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0, flags=0x20, r_spi=b"\x02" * 8), 500, 500), 17, src=B.DST4, dst=B.SRC4)),
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=35, message_id=1, payloads=[(46, b"\x00" * 32)]), 500, 500), 17)),
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=35, message_id=1, flags=0x20, r_spi=b"\x02" * 8, payloads=[(46, b"\x00" * 32)]), 500, 500), 17, src=B.DST4, dst=B.SRC4)),
    B.ethernet(B.ipv4(B.esp(spi=0xC0FFEE01, seq=1), 50)),
    B.ethernet(B.ipv4(B.esp(spi=0xDEADBE01, seq=1), 50, src=B.DST4, dst=B.SRC4)),
]


# ==============================================================================
# 1. Layer 2 Live-Capture Downstream Orchestration
# ==============================================================================

def test_layer02_live_capture_downstream_orchestration() -> None:
    """Verify that stop_capture triggers downstream Layers 05 to 10 for discovered sessions."""
    svc = LiveCaptureService()

    svc._state = "CAPTURING"
    svc._source_vm = "TestVM"
    svc._nic_number = 1
    svc._output_file = "test_capture.pcap"
    svc._capture_id = "CAP-TEST-DOWNSTREAM"

    with patch.object(svc.capture_engine, "stop_trace", return_value=(True, "OK")), \
         patch("app.layers.layer02_packet_capture.service.os.path.isfile", return_value=True), \
         patch("app.layers.layer02_packet_capture.service.os.path.getsize", return_value=5000), \
         patch("app.layers.layer02_packet_capture.service.count_pcap_packets", return_value=50), \
         patch("builtins.open", MagicMock()), \
         patch("app.layers.layer02_packet_capture.service.packet_service.load") as mock_l3_load, \
         patch("app.layers.layer02_packet_capture.service.session_service.discover") as mock_s_disc, \
         patch("app.layers.layer02_packet_capture.service.sa_lifecycle_service.discover") as mock_sa_disc:

        mock_s_disc.return_value = MagicMock(statistics=MagicMock(total=1))

        orig_cid = packet_service._capture_id
        packet_service._capture_id = "test_analysis_id_123"

        try:
            mock_session = MagicMock(id="IPSEC-MOCK-SESSION-01", capture_id="test_analysis_id_123")

            with patch("app.services.feature_service.feature_service.extract") as mock_f_extract, \
                 patch("app.services.fingerprint_service.fingerprint_service.get_or_create_for_session") as mock_fp, \
                 patch("app.layers.layer08_ai_ml.service.AIAnomalyService.run_inference") as mock_ai, \
                 patch("app.layers.layer09_vulnerability_engine.service.VulnerabilityService.analyze_session") as mock_vuln, \
                 patch("app.layers.layer10_risk_engine.service.RiskEngineService.evaluate_session") as mock_risk, \
                 patch("sqlalchemy.orm.Session.scalars") as mock_scalars:

                mock_scalars.return_value.all.return_value = [mock_session]

                resp = svc.stop_capture()

                assert resp.ingestion_status == "COMPLETED"
                assert mock_l3_load.called
                assert mock_s_disc.called
                assert mock_sa_disc.called
                assert mock_f_extract.called
                assert mock_fp.called
                assert mock_ai.called
                assert mock_vuln.called
                assert mock_risk.called
        finally:
            packet_service._capture_id = orig_cid


# ==============================================================================
# 2. Layer 5 Feature Extraction
# ==============================================================================

def test_layer05_extraction(client) -> None:
    """Verify feature_service.extract extracts and persists valid feature vectors for sessions."""
    client.post(
        "/api/packets/upload",
        files={"file": ("features.pcap", B.pcap(TEST_FRAMES), "application/octet-stream")},
    )
    client.post("/api/sessions/discover")
    client.post("/api/sas/discover")

    sessions = client.get("/api/sessions").json()["items"]
    assert len(sessions) > 0
    target_session_id = sessions[0]["id"]

    # Extract features
    vec_schema = feature_service.extract("SESSION", target_session_id)
    assert vec_schema is not None
    assert vec_schema.entity_type == "SESSION"
    assert vec_schema.entity_id == target_session_id
    assert vec_schema.feature_count > 0
    assert vec_schema.available_count > 0

    # Verify database persistence
    with SessionLocal() as db:
        row = db.get(FeatureVectorRow, vec_schema.id)
        assert row is not None
        assert row.entity_id == target_session_id
        assert row.feature_count == vec_schema.feature_count


# ==============================================================================
# 3. Layer 6 Fingerprinting
# ==============================================================================

def test_layer06_fingerprinting(client) -> None:
    """Verify fingerprint_service creates and persists SessionFingerprintRow with signature."""
    sessions = client.get("/api/sessions").json()["items"]
    assert len(sessions) > 0
    target_session_id = sessions[0]["id"]

    fp = fingerprint_service.get_or_create_for_session(target_session_id)
    assert fp is not None
    assert fp.fingerprint_signature is not None and len(fp.fingerprint_signature) > 0
    assert fp.fingerprint_id is not None
    assert len(fp.features) > 0

    with SessionLocal() as db:
        row = db.scalar(
            select(SessionFingerprintRow).where(SessionFingerprintRow.session_id == target_session_id)
        )
        assert row is not None
        assert row.signature == fp.fingerprint_signature


# ==============================================================================
# 4. Layer 7 Baseline Precondition Enforcement
# ==============================================================================

def test_layer07_baseline_precondition(client) -> None:
    """Verify Layer 7 drift detection is strictly conditional on an active baseline profile."""
    drift_svc = DriftService()
    risk_svc = get_risk_engine_service()

    sessions = client.get("/api/sessions").json()["items"]
    assert len(sessions) > 0
    target_session_id = sessions[0]["id"]

    with SessionLocal() as db:
        # Part A: Without active baseline
        db.query(DriftAnalysisRow).delete()
        db.query(BaselineProfileRow).update({BaselineProfileRow.is_active: False})
        db.commit()

        status = drift_svc.get_status()
        assert status.state in ("NOT INITIALIZED", "INSUFFICIENT DATA")

        # Layer 10 must mark Layer 7 UNAVAILABLE (not fabricate zero drift)
        res_no_base = risk_svc.evaluate_session(db, target_session_id, force_refresh=True)
        assert "LAYER_07_DRIFT_DETECTION" in res_no_base.unavailable_signals
        assert "LAYER_07_DRIFT_DETECTION" not in res_no_base.available_signals
        assert res_no_base.breakdown.drift_score == 0.0

        # Part B: With active baseline profile constructed from 3 fingerprints
        base_id = f"BASE-E2E-TEST-{uuid.uuid4().hex[:8]}"
        v1 = _make_sample_session_vector(session_id=f"SESS-BASE-01-{uuid.uuid4().hex[:4]}", packet_count=50, byte_count=20000)
        v2 = _make_sample_session_vector(session_id=f"SESS-BASE-02-{uuid.uuid4().hex[:4]}", packet_count=60, byte_count=25000)
        v3 = _make_sample_session_vector(session_id=f"SESS-BASE-03-{uuid.uuid4().hex[:4]}", packet_count=55, byte_count=22000)
        fp1 = build_session_fingerprint(v1, "cap-test")
        fp2 = build_session_fingerprint(v2, "cap-test")
        fp3 = build_session_fingerprint(v3, "cap-test")
        fingerprint_service._persist_fingerprint(fp1)
        fingerprint_service._persist_fingerprint(fp2)
        fingerprint_service._persist_fingerprint(fp3)

        profile = build_baseline_profile(
            baseline_id=base_id,
            name="E2E Baseline",
            fingerprints=[fp1, fp2, fp3],
            minimum_sessions=3,
        )
        baseline_service._persist_profile(profile, fingerprints=[fp1, fp2, fp3], activate=True)

        # Drift analysis now executes cleanly
        drift_res = drift_svc.analyze(target_session_id, baseline_id=base_id)
        assert drift_res is not None
        assert drift_res.session_id == target_session_id

        # Layer 10 now incorporates Layer 7
        res_with_base = risk_svc.evaluate_session(db, target_session_id, force_refresh=True)
        assert "LAYER_07_DRIFT_DETECTION" in res_with_base.available_signals
        assert "LAYER_07_DRIFT_DETECTION" not in res_with_base.unavailable_signals


# ==============================================================================
# 5. Layer 8 XGBoost Checksum Synchronization, Integrity & Inference
# ==============================================================================

def test_layer08_xgboost_checksum_and_inference(client) -> None:
    """Verify CIC-IDS XGBoost artifact checksum sync, integrity check, and inference execution."""
    with SessionLocal() as db:
        # Checksum sync & integrity
        model = db.scalar(select(MLModelRow).where(MLModelRow.id == CICIDS_MODEL_ID))
        if model is not None and model.model_artifact_path:
            artifact_path = Path(model.model_artifact_path)
            if artifact_path.is_file():
                actual_cs = model_registry.compute_file_checksum(artifact_path)

                # Set deliberate mismatch
                model.model_checksum = "stale_hash_mismatch_to_test_auto_sync"
                db.commit()

                # Call ensure_cicids_model_registered
                updated_model = ensure_cicids_model_registered(db, force_active=True)
                assert updated_model is not None
                assert updated_model.model_checksum == actual_cs

                # Verify load_model succeeds without ModelIntegrityError
                obj, meta = model_registry.load_model(
                    model_id=updated_model.id,
                    artifact_path_str=updated_model.model_artifact_path,
                    expected_checksum=updated_model.model_checksum,
                )
                assert obj is not None

        # Inference on session
        sessions = client.get("/api/sessions").json()["items"]
        assert len(sessions) > 0
        target_session_id = sessions[0]["id"]

        ai_svc = AIAnomalyService(db)
        inf_req = AnomalyInferenceRequest(session_id=target_session_id, model_id=CICIDS_MODEL_ID)
        inf_res = ai_svc.run_inference(inf_req)

        assert inf_res is not None
        assert inf_res.session_id == target_session_id
        assert inf_res.model_id == CICIDS_MODEL_ID
        assert inf_res.classification in ("NORMAL", "ANOMALOUS")
        assert 0.0 <= inf_res.raw_score <= 1.0
        assert 0.0 <= inf_res.display_score <= 100.0
        assert len(inf_res.feature_contributions) == 30
        assert "CIC-IDS" in inf_res.explanation_summary


# ==============================================================================
# 6. Layer 10 Signal Aggregation, Confidence Scoring & Quality Semantics
# ==============================================================================

def test_layer10_signal_aggregation() -> None:
    """Verify that RiskEvaluator accurately aggregates empirical signals and bounds scores."""
    # Test fingerprint recognition without baseline profile
    inp_fp = EvaluationInput(
        session_id="S-TEST-FP",
        session_info={"source": "10.0.0.1", "destination": "10.0.0.2", "state": "ESTABLISHED"},
        sas=[{"id": "SA-01", "state": "ESTABLISHED", "protocol": "ESP"}],
        has_features=True,
        feature_count=15,
        has_baseline=False,
        baseline_id=None,
        has_fingerprint=True,
        fingerprint_id="FP-S-TEST-FP-001",
        ml_data={"raw_score": 0.05, "classification": "NORMAL", "model_id": CICIDS_MODEL_ID},
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
    ) = RiskEvaluator.evaluate(inp_fp)

    # Layer 6 is AVAILABLE due to fingerprint
    assert "LAYER_06_BASELINE_PROFILING" in avail
    # Layer 7 is UNAVAILABLE due to lack of baseline (no fake zero-drift)
    assert "LAYER_07_DRIFT_DETECTION" in unavail
    # Signals available: SA (L4), Features (L5), Fingerprint (L6), ML (L8), Vuln (L9)
    assert "LAYER_04_SA_LIFECYCLE" in avail
    assert "LAYER_05_FEATURE_EXTRACTION" in avail
    assert "LAYER_08_AI_ML_ANOMALY" in avail
    assert "LAYER_09_VULNERABILITY_ENGINE" in avail
    # Data quality is PARTIAL because Layer 7 is missing
    assert quality == "PARTIAL"
    assert conf == 0.83  # 5 out of 6 intelligence signals (round(5/6, 2) = 0.83)
    assert decision == "ALLOW"
    assert level == "LOW"


# ==============================================================================
# 7. Current-Capture Filtering in evaluate_all_sessions & API
# ==============================================================================

def test_current_capture_filtering(client) -> None:
    """Verify that evaluate_all_sessions scopes evaluation to the requested capture ID."""
    risk_svc = get_risk_engine_service()

    with SessionLocal() as db:
        s_hist = IPsecSession(
            id="IPSEC-HIST-99",
            capture_id="CAP-HISTORICAL",
            ordinal=1,
            source="192.168.10.1",
            destination="192.168.10.2",
            direction="INBOUND",
            state="ESTABLISHED",
            correlation="DIRECT",
            packet_count=5,
            byte_count=500,
            detail_json="{}",
        )
        s_curr = IPsecSession(
            id="IPSEC-CURR-01",
            capture_id="CAP-ACTIVE",
            ordinal=1,
            source="192.168.20.1",
            destination="192.168.20.2",
            direction="OUTBOUND",
            state="ESTABLISHED",
            correlation="DIRECT",
            packet_count=12,
            byte_count=1200,
            detail_json="{}",
        )
        db.merge(s_hist)
        db.merge(s_curr)
        db.commit()

        # Service level filtering
        results = risk_svc.evaluate_all_sessions(db, capture_id="CAP-ACTIVE")
        evaluated_ids = {r.session_id for r in results}
        assert "IPSEC-CURR-01" in evaluated_ids
        assert "IPSEC-HIST-99" not in evaluated_ids

    # API level filtering
    api_res = client.post("/api/risk/evaluate-all?capture_id=CAP-ACTIVE")
    assert api_res.status_code == 200
    api_ids = {item["session_id"] for item in api_res.json()}
    assert "IPSEC-CURR-01" in api_ids
    assert "IPSEC-HIST-99" not in api_ids


# ==============================================================================
# 8. Full 14-Layer Integration
# ==============================================================================

def test_full_14_layer_integration(client) -> None:
    """End-to-end traversal of all 14 architectural layers in sequence."""
    # Layer 1: Environment Readiness
    l1_res = client.get("/api/environment/status")
    assert l1_res.status_code == 200
    assert l1_res.json()["layer_number"] == 1

    # Layer 2: Packet Capture Status
    l2_res = client.get("/api/live-capture/status")
    assert l2_res.status_code == 200
    assert "state" in l2_res.json()

    # Layer 3: Protocol & Packet Analysis
    l3_res = client.get("/api/packets/status")
    assert l3_res.status_code == 200
    assert l3_res.json()["state"] == "COMPLETED"
    assert l3_res.json()["statistics"]["total_packets"] > 0

    # Layer 4: SA Lifecycle & Sessions
    l4_res = client.get("/api/sessions")
    assert l4_res.status_code == 200
    sessions = l4_res.json()["items"]
    assert len(sessions) > 0
    sid = sessions[0]["id"]

    # Layer 5: Feature Extraction
    feature_service.extract("SESSION", sid)
    l5_res = client.get("/api/features/entities?entity_type=SESSION")
    assert l5_res.status_code == 200

    # Layer 6: Session Fingerprinting
    fingerprint_service.get_or_create_for_session(sid)
    l6_res = client.get(f"/api/sessions/{sid}/fingerprint")
    assert l6_res.status_code == 200
    assert "signature" in l6_res.json()

    # Layer 7: Drift Detection
    l7_res = client.get("/api/drift/status")
    assert l7_res.status_code == 200

    # Layer 8: AI / ML Anomaly Detection (CIC-IDS XGBoost)
    l8_res = client.get("/api/ml/status")
    assert l8_res.status_code == 200
    assert l8_res.json()["active_model"]["id"] == CICIDS_MODEL_ID

    # Layer 9: Vulnerability Engine
    l9_res = client.get("/api/vulnerabilities/status")
    assert l9_res.status_code == 200

    # Layer 10: Risk Assessment Engine
    risk_res = client.post(f"/api/risk/evaluate/{sid}")
    assert risk_res.status_code == 200
    l10_res = client.get(f"/api/risk/sessions/{sid}")
    assert l10_res.status_code == 200
    assert l10_res.json()["session_id"] == sid
    assert "risk_score" in l10_res.json()
    assert "decision" in l10_res.json()

    # Layer 11: Security Databases (SQLite)
    with SessionLocal() as db:
        assert db.query(IPsecSession).count() > 0
        assert db.query(RiskAssessmentRow).count() > 0

    # Layer 12: Backend & API (System Status)
    l12_res = client.get("/api/system/status")
    assert l12_res.status_code == 200
    assert len(l12_res.json()["architecture_layers"]) == 14

    # Layer 13: Web Dashboard Summary
    l13_res = client.get("/api/dashboard/summary")
    assert l13_res.status_code == 200
    assert "posture" in l13_res.json()
    assert l13_res.json()["metrics"]["active_vpn_sessions"] > 0

    # Layer 14: Report Generation
    l14_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    assert l14_res.status_code == 201
    assert "id" in l14_res.json()
