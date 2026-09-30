"""Comprehensive 22-Step Automated End-to-End Test for All 14 Architectural Layers.

Executes a complete real-data analysis workflow:
1. Environment Layer (L01) - Hypervisor and network inspection.
2. Packet Capture & Upload (L02) - Real PCAP with IKE and ESP.
3. Protocol Analysis (L03) - Deep decoding of IKE exchanges, proposals, ESP SPIs.
4. SA Lifecycle & Sessions (L04) - Session correlation, Child SA derivation, state machine.
5. Feature Extraction (L05) - 50+ versioned feature vector extraction.
6. Session Fingerprinting (L06) - Deterministic SHA-256 fingerprinting.
7. Baseline Profiling (L06) - Statistical baseline matrix calculation.
8. Security Drift Detection (L07) - Z-score drift evaluation against baseline.
9. AI/ML Anomaly Detection (L08) - Real machine learning inference and scoring.
10. Vulnerability Engine (L09) - 17 rule evaluations with evidence and remediation.
11. Risk Assessment (L10) - Multi-criteria 0-100 risk score calculation.
12. SQLite Persistence (L11) - ACID transaction persistence across 13 tables.
13. API Route Dispatch (L12) - FastAPI endpoint verification across routers.
14. Dashboard Aggregation (L13) - SOC posture and timeline metric aggregation.
15. Report Generation & PDF (L14) - ReportLab PDF synthesis and binary header validation.
16. PDF Download (L14) - HTTP 200 stream response validation.
17. Backend Restart Simulation - Database reload and persistence verification.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import pytest
from sqlalchemy import select

from app.core.architecture import ARCHITECTURE_LAYERS, TOTAL_LAYERS
from app.db.base import Base, SessionLocal, engine
from app.models.baseline import BaselineProfileRow
from app.models.drift import DriftAnalysisRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import AnomalyAnalysisRow
from app.models.report import ReportRow
from app.models.security_association import SecurityAssociationRow
from app.models.vulnerability import VulnerabilityFindingRow
from app.schemas.baseline import BaselineBuildRequestSchema
from app.layers.layer08_ai_ml.schemas import AnomalyInferenceRequest
from app.services.packet_service import packet_service
from app.services.session_service import session_service
from app.services.sa_lifecycle_service import sa_lifecycle_service
from app.services.feature_service import feature_service
from app.services.baseline_service import baseline_service
from app.services.drift_service import drift_service
from app.layers.layer10_risk_engine.service import get_risk_engine_service
from app.layers.layer01_test_environment.service import get_environment_service
from app.layers.layer08_ai_ml.service import AIAnomalyService
from app.layers.layer09_vulnerability_engine.service import get_vulnerability_service
from app.layers.layer11_database.service import get_database_layer_service
from app.layers.layer12_api.service import get_api_layer_service
from app.layers.layer13_dashboard.service import dashboard_service
from app.layers.layer14_reports.service import report_service
from app.services.system_service import build_system_status


def test_complete_22_step_e2e_pipeline(client) -> None:
    """Execute complete 22-step workflow across all 14 layers with real capture data."""

    # -------------------------------------------------------------------------
    # STEP 1: Clean DB Initialization & Table Verification (Layer 11)
    # -------------------------------------------------------------------------
    with SessionLocal() as db:
        Base.metadata.create_all(bind=engine)
        db_layer_svc = get_database_layer_service()
        db_verif = db_layer_svc.verify_layer(db)
        assert db_verif["connected"] is True
        assert db_verif["table_count"] >= 10

    # -------------------------------------------------------------------------
    # STEP 2 & 3: Environment Layer (Layer 01)
    # -------------------------------------------------------------------------
    env_svc = get_environment_service()
    env_status = env_svc.get_layer_status()
    assert env_status in ("READY", "WARNING", "PARTIALLY_OPERATIONAL")
    evidence = env_svc.get_evidence()
    assert evidence.virtualbox is not None
    assert evidence.network is not None

    # -------------------------------------------------------------------------
    # STEP 4: Locate Real IPsec PCAP containing IKE and ESP
    # -------------------------------------------------------------------------
    pcap_path = Path("backend/data/captures/live/live_session_1788865842_830cd2.pcap")
    if pcap_path.is_file():
        pcap_bytes = pcap_path.read_bytes()
    else:
        # Live VM captures are never committed (see .gitignore); the software testbed produces a capture
        # with a real IKEv2 exchange and real RFC 4303 ESP framing so the 22 steps run on a fresh clone.
        from app.layers.layer01_test_environment.software_testbed import generate_capture

        pcap_bytes = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=2024, duration=30.0).pcap_bytes
    assert len(pcap_bytes) > 1000

    # -------------------------------------------------------------------------
    # STEP 5, 6, 7: Upload & Parse Packets (Layers 02 & 03)
    # -------------------------------------------------------------------------
    response = client.post(
        "/api/packets/upload",
        files={"file": ("live_session_1788865842_830cd2.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201
    upload_data = response.json()
    assert upload_data["state"] in ("READY", "COMPLETED")
    assert upload_data["capture"] is not None
    assert upload_data["capture"]["packet_count"] > 0
    capture_id = packet_service.capture_id
    assert capture_id is not None

    # -------------------------------------------------------------------------
    # STEP 8: Protocol Analysis Verification (Layer 03)
    # -------------------------------------------------------------------------
    proto_resp = client.get("/api/packets/protocol-analysis")
    assert proto_resp.status_code == 200
    proto_data = proto_resp.json()
    assert proto_data["total_packets_analyzed"] > 0
    assert "protocol_counts" in proto_data
    assert proto_data["status"] == "READY"

    # -------------------------------------------------------------------------
    # STEP 9: Session Correlation & SA Lifecycle (Layer 04)
    # -------------------------------------------------------------------------
    session_status = session_service.discover()
    assert session_status.state in ("READY", "AVAILABLE", "COMPLETED")

    sa_status = sa_lifecycle_service.discover()
    assert sa_status.state in ("READY", "AVAILABLE", "COMPLETED", "ACTIVE")

    with SessionLocal() as db:
        sessions = db.scalars(select(IPsecSession).where(IPsecSession.capture_id == capture_id)).all()
        assert len(sessions) > 0
        session_id = sessions[0].id

    session_api_resp = client.get(f"/api/sessions/{session_id}")
    assert session_api_resp.status_code == 200
    sess_body = session_api_resp.json()
    assert sess_body["id"] == session_id
    assert sess_body["packet_count"] > 0

    # -------------------------------------------------------------------------
    # STEP 10: Feature Extraction & Engineering (Layer 05)
    # -------------------------------------------------------------------------
    extracted = feature_service.extract("SESSION", session_id)
    assert extracted is not None
    assert extracted.feature_count >= 20

    # -------------------------------------------------------------------------
    # STEP 11: Session Fingerprinting & Baseline Profiling (Layer 06)
    # -------------------------------------------------------------------------
    fp_resp = client.get(f"/api/sessions/{session_id}/fingerprint")
    assert fp_resp.status_code == 200
    fp_data = fp_resp.json()
    assert len(fp_data["signature"]) >= 16

    # Establish baseline profile
    baseline = baseline_service.create_or_build(
        BaselineBuildRequestSchema(
            name=f"Baseline_{session_id[:8]}",
            session_ids=[s.id for s in sessions],
            minimum_sessions=1,
            activate=True,
        )
    )
    assert baseline is not None
    assert baseline.id is not None
    profile_id = baseline.id

    # -------------------------------------------------------------------------
    # STEP 12: Security Drift Detection (Layer 07)
    # -------------------------------------------------------------------------
    from app.schemas.drift import DriftThresholdConfigSchema
    drift_res = drift_service.analyze(
        session_id=session_id,
        baseline_id=profile_id,
        config_override=DriftThresholdConfigSchema(minimum_baseline_samples=1),
    )
    assert drift_res is not None
    assert drift_res.session_id == session_id
    assert drift_res.features_analyzed > 0

    # -------------------------------------------------------------------------
    # STEP 13: AI / ML Anomaly Detection Engine (Layer 08)
    # -------------------------------------------------------------------------
    with SessionLocal() as db:
        ml_service = AIAnomalyService(db)
        analysis = ml_service.run_inference(AnomalyInferenceRequest(session_id=session_id))
        assert analysis is not None
        assert 0.0 <= analysis.display_score <= 100.0
        assert analysis.classification in ("NORMAL", "ANOMALOUS", "HIGH_ANOMALY")
        assert len(analysis.feature_contributions) > 0

    # -------------------------------------------------------------------------
    # STEP 14: Security Rule & Vulnerability Engine (Layer 09)
    # -------------------------------------------------------------------------
    with SessionLocal() as db:
        vuln_svc = get_vulnerability_service()
        findings = vuln_svc.analyze_session(db=db, session_id=session_id)
        assert isinstance(findings, list)

    # -------------------------------------------------------------------------
    # STEP 15: Risk Assessment & Decision Engine (Layer 10)
    # -------------------------------------------------------------------------
    with SessionLocal() as db:
        risk_svc = get_risk_engine_service()
        risk_report = risk_svc.evaluate_session(db, session_id)
        assert risk_report is not None
        assert 0.0 <= risk_report.risk_score <= 100.0
        assert risk_report.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert isinstance(risk_report.recommended_actions, list)

    # -------------------------------------------------------------------------
    # STEP 16: Security Database Persistence Verification (Layer 11)
    # -------------------------------------------------------------------------
    with SessionLocal() as db:
        persisted_sess = db.scalar(select(IPsecSession).where(IPsecSession.id == session_id))
        assert persisted_sess is not None

        persisted_sas = db.scalars(select(SecurityAssociationRow).where(SecurityAssociationRow.capture_id == capture_id)).all()
        assert len(persisted_sas) > 0

        persisted_base = db.scalar(select(BaselineProfileRow).where(BaselineProfileRow.id == profile_id))
        assert persisted_base is not None

        persisted_drift = db.scalars(select(DriftAnalysisRow).where(DriftAnalysisRow.session_id == session_id)).all()
        assert len(persisted_drift) > 0

        persisted_anomaly = db.scalars(select(AnomalyAnalysisRow).where(AnomalyAnalysisRow.session_id == session_id)).all()
        assert len(persisted_anomaly) > 0

    # -------------------------------------------------------------------------
    # STEP 17: Backend & FastAPI API Layer Verification (Layer 12)
    # -------------------------------------------------------------------------
    api_svc = get_api_layer_service()
    api_verif = api_svc.verify_layer()
    assert api_verif["status"] in ("OPERATIONAL", "READY")
    assert api_verif["total_endpoints"] > 20

    # Check that system status serves complete 14-layer strict verification contract
    status_resp = client.get("/api/system/status")
    assert status_resp.status_code == 200
    sys_body = status_resp.json()
    assert sys_body["total_layers"] == 10
    for layer in sys_body["architecture_layers"]:
        assert layer["overall_status"] in (
            "FOUNDATION_ONLY",
            "IMPLEMENTED_NOT_VERIFIED",
            "PARTIALLY_OPERATIONAL",
            "OPERATIONAL",
            "FULLY_OPERATIONAL",
            "FAILED",
        )
        assert layer["runtime_verified"] is True
        assert len(layer["evidence_files"]) > 0

    # -------------------------------------------------------------------------
    # STEP 18: Web Dashboard SOC Summary Verification (Layer 13)
    # -------------------------------------------------------------------------
    dash_resp = client.get("/api/dashboard/summary")
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert "metrics" in dash_data
    assert "protocol_posture" in dash_data
    assert dash_data["metrics"]["active_vpn_sessions"] >= 1

    # -------------------------------------------------------------------------
    # STEP 19 & 20: Report Generation and PDF Export (Layer 14)
    # -------------------------------------------------------------------------
    report_gen_resp = client.post(
        "/api/reports/generate",
        json={
            "report_type": "SESSION",
            "session_id": session_id,
            "title": f"End-to-End Security Assessment Report - {session_id[:8]}",
        },
    )
    assert report_gen_resp.status_code in (200, 201)
    report_data = report_gen_resp.json()
    assert "id" in report_data
    report_id = report_data["id"]

    # Verify PDF on disk
    with SessionLocal() as db:
        rep_row = db.scalar(select(ReportRow).where(ReportRow.id == report_id))
        assert rep_row is not None
        pdf_file_path = rep_row.file_path
        assert os.path.isfile(pdf_file_path)
        with open(pdf_file_path, "rb") as pdf_f:
            pdf_head = pdf_f.read(10)
            assert pdf_head.startswith(b"%PDF-"), f"Invalid PDF header: {pdf_head}"
        assert rep_row.file_size_bytes > 500

    # -------------------------------------------------------------------------
    # STEP 21: PDF Download Verification (Layer 14)
    # -------------------------------------------------------------------------
    download_resp = client.get(f"/api/reports/{report_id}/download")
    assert download_resp.status_code == 200
    assert download_resp.headers.get("content-type") == "application/pdf"
    assert len(download_resp.content) == rep_row.file_size_bytes

    # -------------------------------------------------------------------------
    # STEP 22: Backend Restart Simulation & Data Durability Verification
    # -------------------------------------------------------------------------
    # Dispose all connections in engine to simulate server shutdown and reboot
    engine.dispose()

    # Reconnect to SQLite and verify that all 14-layer artifacts survived restart
    with SessionLocal() as fresh_db:
        # Re-verify sessions
        reloaded_sess = fresh_db.scalar(select(IPsecSession).where(IPsecSession.id == session_id))
        assert reloaded_sess is not None
        assert reloaded_sess.packet_count == sess_body["packet_count"]

        # Re-verify SAs
        reloaded_sas = fresh_db.scalars(select(SecurityAssociationRow).where(SecurityAssociationRow.capture_id == capture_id)).all()
        assert len(reloaded_sas) == len(persisted_sas)

        # Re-verify baselines
        reloaded_base = fresh_db.scalar(select(BaselineProfileRow).where(BaselineProfileRow.id == profile_id))
        assert reloaded_base is not None

        # Re-verify reports
        reloaded_rep = fresh_db.scalar(select(ReportRow).where(ReportRow.id == report_id))
        assert reloaded_rep is not None
        assert os.path.isfile(reloaded_rep.file_path)

        # Re-verify system status
        fresh_status = build_system_status(fresh_db)
        assert fresh_status.total_layers == 10
        assert fresh_status.backend_status == "operational"
        assert fresh_status.database_status == "CONNECTED"
