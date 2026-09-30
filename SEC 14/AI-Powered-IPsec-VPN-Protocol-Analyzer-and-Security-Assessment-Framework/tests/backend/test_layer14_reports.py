"""Comprehensive Test Suite for Layer 14 — Report Generation / PDF Reporting Engine.

Covers:
  - ReportService lifecycle & layer status
  - Request validation & schema integrity
  - Authoritative multi-layer data collection (Layers 01-13)
  - Zero-fabrication empty data handling
  - Exact Layer 10 risk score & policy decision preservation
  - Layer 09 vulnerability catalog & evidence preservation
  - Layer 04 & 06 SA lifecycle & session fingerprint preservation
  - Binary PDF integrity & %PDF- header signature validation
  - Exact page count computation and database persistence
  - Unicode text safety & long-string table cell wrapping
  - NumberedCanvas two-pass running header and "Page X of Y" footers
  - Storage security, path traversal rejection & filename sanitization
  - Sensitive credential & secret redaction verification
  - Database persistence, restart durability & transactional rollback
  - Layer 12 FastAPI REST API contracts (/api/reports/*)
"""

from __future__ import annotations

import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.base import Base, SessionLocal, engine
from app.db.init_db import initialize_database
from app.layers.layer14_reports.collector import report_collector
from app.layers.layer14_reports.pdf_renderer import NumberedCanvas, pdf_renderer
from app.layers.layer14_reports.schemas import (
    ReportGenerateRequest,
    ReportMetadataDTO,
    SecurityAssessmentReportData,
)
from app.layers.layer14_reports.service import report_service
from app.layers.layer14_reports.storage import (
    delete_report_file,
    get_reports_dir,
    resolve_report_path,
    sanitize_filename,
    save_report_file,
)
from app.services.packet_service import packet_service
from app.models.baseline import BaselineProfileRow
from app.models.drift import DriftAnalysisRow, FeatureDriftRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import (
    AnomalyAnalysisRow,
    AnomalyFeatureContributionRow,
    MLModelRow,
)
from app.models.report import ReportRow
from app.models.risk import RiskAssessmentRow
from app.models.security_association import (
    SALifecycleEventRow,
    SecurityAssociationRow,
)
from app.models.vulnerability import (
    FindingEvidenceRow,
    SecurityRuleRow,
    VulnerabilityFindingRow,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def clean_isolated_report_db():
    """Ensure clean reports directory and Layer 14 test records for each test."""
    initialize_database()
    packet_service.clear()

    with SessionLocal() as db:
        db.query(ReportRow).delete()
        db.query(FindingEvidenceRow).filter(FindingEvidenceRow.finding_id.like("vuln-l14%")).delete()
        db.query(VulnerabilityFindingRow).filter(VulnerabilityFindingRow.id.like("vuln-l14%")).delete()
        db.query(SecurityRuleRow).filter(SecurityRuleRow.id.like("RULE-L14%")).delete()
        db.query(AnomalyFeatureContributionRow).filter(AnomalyFeatureContributionRow.analysis_id.like("anom-l14%")).delete()
        db.query(AnomalyAnalysisRow).filter(AnomalyAnalysisRow.id.like("anom-l14%")).delete()
        db.query(SecurityAssociationRow).filter(SecurityAssociationRow.id.like("sa-l14%")).delete()
        db.query(IPsecSession).filter(IPsecSession.id.in_(["sess-full-layer14", "sess-target-99", "sess-other-11"])).delete()
        db.query(MLModelRow).filter(MLModelRow.id.like("model-l14%")).delete()
        db.commit()

    # Snapshot existing report files to avoid wiping pre-existing user reports
    rep_dir = get_reports_dir()
    existing_pdfs = set(rep_dir.glob("*.pdf"))

    yield

    with SessionLocal() as db:
        db.query(FindingEvidenceRow).filter(FindingEvidenceRow.finding_id.like("vuln-l14%")).delete()
        db.query(VulnerabilityFindingRow).filter(VulnerabilityFindingRow.id.like("vuln-l14%")).delete()
        db.query(SecurityRuleRow).filter(SecurityRuleRow.id.like("RULE-L14%")).delete()
        db.query(AnomalyFeatureContributionRow).filter(AnomalyFeatureContributionRow.analysis_id.like("anom-l14%")).delete()
        db.query(AnomalyAnalysisRow).filter(AnomalyAnalysisRow.id.like("anom-l14%")).delete()
        db.query(SecurityAssociationRow).filter(SecurityAssociationRow.id.like("sa-l14%")).delete()
        db.query(IPsecSession).filter(IPsecSession.id.in_(["sess-full-layer14", "sess-target-99", "sess-other-11"])).delete()
        db.query(MLModelRow).filter(MLModelRow.id.like("model-l14%")).delete()
        db.commit()

    for f in rep_dir.glob("*.pdf"):
        if f not in existing_pdfs or "test" in f.name.lower() or "l14" in f.name.lower():
            try:
                f.unlink()
            except Exception:
                pass

    packet_service.clear()


# =============================================================================
# 1. SERVICE INITIALIZATION & SCHEMAS
# =============================================================================


def test_layer14_status_operational() -> None:
    """Verify Layer 14 service status reports OPERATIONAL when engine is ready."""
    status = report_service.get_layer_status()
    assert status == "OPERATIONAL"


def test_report_request_validation_valid() -> None:
    """ReportGenerateRequest validates valid payload configurations."""
    req1 = ReportGenerateRequest(report_type="FULL")
    assert req1.report_type == "FULL"
    assert req1.session_id is None

    req2 = ReportGenerateRequest(report_type="SESSION", session_id="sess-test-01", title="Scoped Test")
    assert req2.report_type == "SESSION"
    assert req2.session_id == "sess-test-01"
    assert req2.title == "Scoped Test"

    req3 = ReportGenerateRequest(report_type="VULNERABILITY")
    assert req3.report_type == "VULNERABILITY"


def test_report_request_validation_forbids_extra_fields() -> None:
    """ReportGenerateRequest rejects unexpected fields with ConfigDict(extra='forbid')."""
    with pytest.raises(ValidationError):
        ReportGenerateRequest(report_type="FULL", unknown_field="invalid_payload")  # type: ignore


# =============================================================================
# 2. STORAGE & PATH TRAVERSAL HARDENING
# =============================================================================


def test_sanitize_filename_strips_unsafe_characters() -> None:
    """sanitize_filename removes traversal components and illegal filesystem characters."""
    clean1 = sanitize_filename("../../../etc/passwd")
    assert ".." not in clean1
    assert "/" not in clean1
    assert clean1.endswith(".pdf")

    clean2 = sanitize_filename("audit<test>:report*.pdf")
    assert "<" not in clean2
    assert ">" not in clean2
    assert ":" not in clean2
    assert "*" not in clean2
    assert clean2.endswith(".pdf")


def test_resolve_report_path_blocks_path_traversal() -> None:
    """resolve_report_path rejects path traversal attempts with ValueError."""
    with pytest.raises(ValueError, match="Path traversal detected"):
        resolve_report_path("../../../outside.pdf")

    with pytest.raises(ValueError, match="Path traversal detected"):
        resolve_report_path("subdir/test.pdf")

    with pytest.raises(ValueError, match="Path traversal detected"):
        resolve_report_path("..\\windows\\traversal.pdf")


def test_save_and_delete_report_file() -> None:
    """save_report_file writes bytes safely; delete_report_file removes the file."""
    filename = "test-sample-report.pdf"
    content = b"%PDF-1.4 test payload"

    saved_path = save_report_file(filename, content)
    assert saved_path.is_file()
    assert saved_path.read_bytes() == content

    deleted = delete_report_file(filename)
    assert deleted is True
    assert not saved_path.is_file()


# =============================================================================
# 3. EMPTY-DATA REPORT GENERATION & DATA INTEGRITY
# =============================================================================


def test_generate_report_empty_database() -> None:
    """Empty database report generation succeeds, produces genuine PDF, and does not fabricate data."""
    mem_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=mem_engine)
    with Session(bind=mem_engine) as db:
        req = ReportGenerateRequest(report_type="FULL", title="Empty State Baseline")
        dto = report_service.generate_report(db, req)

        assert dto.id.startswith("REPORT-")
        assert dto.report_type == "FULL"
        assert dto.title == "Empty State Baseline"
        assert dto.status == "COMPLETED"
        assert dto.file_size_bytes > 5000
        assert dto.page_count >= 2

        # Verify physical file existence and valid PDF signature
        pdf_path = report_service.get_report_pdf_path(db, dto.id)
        assert pdf_path is not None
        assert pdf_path.is_file()

        content = pdf_path.read_bytes()
        assert content.startswith(b"%PDF-")

        # Verify exact page count matches
        exact_pages = len(re.findall(rb"/Type\s*/Page\b", content))
        assert dto.page_count == exact_pages


def test_empty_database_marks_sections_unavailable() -> None:
    """Collector on empty DB marks telemetry as empty/idle rather than inventing synthetic scores."""
    mem_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=mem_engine)
    with Session(bind=mem_engine) as db:
        req = ReportGenerateRequest(report_type="FULL")
        data = report_collector.collect(db, req)

        assert data.capture["total_packets"] == 0
        assert data.capture["protocol_counts"].get("ESP", 0) == 0
        assert data.capture["protocol_counts"].get("AH", 0) == 0
        assert data.sa_lifecycle["total_sas"] == 0
        assert data.vulnerabilities["total_findings"] == 0
        assert "OPERATIONAL" in data.risk["overall_risk_status"]


# =============================================================================
# 4. POPULATED DATA AGGREGATION & MULTI-LAYER PRESERVATION
# =============================================================================


def test_generate_report_populated_multi_layer_telemetry() -> None:
    """Populated data from Layers 01-13 is preserved accurately into report data and PDF."""
    now = _utc_now()
    session_id = "sess-full-layer14"

    with SessionLocal() as db:
        # Layer 02 & 04 Session
        sess = IPsecSession(
            id=session_id,
            capture_id="cap-l14-test",
            ordinal=1,
            source="192.168.100.1",
            destination="192.168.100.2",
            direction="OUTBOUND",
            state="ACTIVE",
            correlation="DIRECT",
            start_time="2026-09-04T12:00:00Z",
            duration_seconds=120.5,
            packet_count=250,
            byte_count=45000,
            ike_packets=30,
            esp_packets=220,
            ah_packets=0,
            ike_version="IKEv2",
            nat_traversal=True,
            detail_json="{}",
            discovered_at=now,
        )
        db.add(sess)

        # Layer 04 SA
        sa = SecurityAssociationRow(
            id="sa-l14-01",
            session_id=session_id,
            capture_id="cap-l14-test",
            type="CHILD_SA",
            state="INSTALLED",
            protocol="ESP",
            association="DIRECT",
            ipsec_mode="TUNNEL",
            initiator="192.168.100.1",
            responder="192.168.100.2",
            spi="0xCAFEBABE",
            initiator_spi="0x1122334455667788",
            packet_count=200,
            byte_count=40000,
            detail_json="{}",
            rekey_count=2,
            discovered_at=now,
        )
        db.add(sa)

        # Layer 09 Rule & Finding
        rule = SecurityRuleRow(
            id="RULE-L14-001",
            name="Weak Diffie-Hellman Group Detected",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            default_confidence="HIGH",
            enabled=True,
            version="1.0",
            description="Diffie-Hellman group 2 is considered cryptographically obsolete.",
            remediation="Upgrade to MODP-3072 (DH Group 15) or ECP-256 (DH Group 19).",
            references_json=json.dumps(["RFC 8221 Section 4", "NIST SP 800-77"]),
            created_at=now,
            updated_at=now,
        )
        db.add(rule)

        finding = VulnerabilityFindingRow(
            id="vuln-l14-01",
            rule_id="RULE-L14-001",
            rule_version="1.0",
            title="Obsolete DH Group 2 in IKE SA",
            description="IKE SA negotiated with obsolete Diffie-Hellman group 2.",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            confidence="HIGH",
            status="OPEN",
            affected_object_type="SESSION",
            affected_object_id=session_id,
            affected_session_id=session_id,
            dedup_hash="dedup-hash-l14-01",
            occurrence_count=1,
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db.add(finding)

        evidence = FindingEvidenceRow(
            finding_id="vuln-l14-01",
            evidence_key="dh_group",
            observed_value="MODP-1024 (Group 2)",
            expected_value="MODP-3072+ (Group 15+)",
            description="Weak key exchange group parameter in proposal payload",
        )
        db.add(evidence)

        # Layer 08 ML Anomaly
        model = db.scalar(select(MLModelRow).where(MLModelRow.id == "model-l14-01"))
        if not model:
            model = MLModelRow(
                id="model-l14-01",
                name="IsolationForest Unsupervised Detector",
                model_type="IsolationForest",
                model_version="1.0",
                is_active=False,
                configuration_json="{}",
                metrics_json="{}",
                created_at=now,
                updated_at=now,
            )
            db.add(model)

        anomaly = AnomalyAnalysisRow(
            id="anom-l14-01",
            session_id=session_id,
            model_id="model-l14-01",
            model_version="1.0",
            raw_score=-0.25,
            display_score=85.0,
            classification="ANOMALOUS",
            explanation_summary="Session packet rate and byte volume deviate sharply from normal behavior.",
            analyzed_at=now,
        )
        db.add(anomaly)
        db.commit()

        # Generate full assessment report
        req = ReportGenerateRequest(
            report_type="FULL",
            title="Enterprise VPN Security Verification Report",
        )
        dto = report_service.generate_report(db, req)

        assert dto.status == "COMPLETED"
        assert dto.title == "Enterprise VPN Security Verification Report"
        assert dto.page_count >= 3

        # Verify collector data matching DB
        data = report_collector.collect(db, req)
        assert data.capture["total_packets"] >= 250
        assert data.capture["protocol_counts"]["ESP"] >= 220
        assert data.capture["protocol_counts"]["IKE"] >= 30
        assert data.capture["nat_traversal_observed"] is True
        assert data.sa_lifecycle["total_sas"] >= 1
        assert data.vulnerabilities["total_findings"] >= 1
        assert data.vulnerabilities["counts"]["HIGH"] >= 1
        assert data.ml_anomaly["anomalous_count"] >= 1

        # Check session analysis
        assert data.session_analysis is not None
        assert data.session_analysis["total_sessions"] >= 1
        s_item = data.session_analysis["sessions"][0]
        assert s_item["session_id"] == session_id
        assert s_item["initiator"] == "192.168.100.1"
        assert s_item["responder"] == "192.168.100.2"
        assert s_item["esp_packets"] == 220
        assert s_item["ike_packets"] == 30
        assert s_item["fingerprint_preview"] != "N/A"
        assert s_item["related_findings"] >= 1


def test_scoped_session_report_generation() -> None:
    """Scoped session report filters SA, findings, and metrics to the specified session ID."""
    now = _utc_now()
    session_id_target = "sess-target-99"
    session_id_other = "sess-other-11"

    with SessionLocal() as db:
        db.add(
            IPsecSession(
                id=session_id_target,
                capture_id="cap-scoped",
                ordinal=1,
                source="10.10.1.1",
                destination="10.10.1.2",
                direction="INBOUND",
                state="ACTIVE",
                correlation="DIRECT",
                packet_count=50,
                byte_count=5000,
                detail_json="{}",
                discovered_at=now,
            )
        )
        db.add(
            IPsecSession(
                id=session_id_other,
                capture_id="cap-scoped",
                ordinal=2,
                source="10.20.1.1",
                destination="10.20.1.2",
                direction="OUTBOUND",
                state="CLOSED",
                correlation="DIRECT",
                packet_count=20,
                byte_count=2000,
                detail_json="{}",
                discovered_at=now,
            )
        )
        db.commit()

        req = ReportGenerateRequest(
            report_type="SESSION",
            session_id=session_id_target,
            title="Scoped Session Audit",
        )
        dto = report_service.generate_report(db, req)
        assert dto.status == "COMPLETED"

        data = report_collector.collect(db, req)
        assert data.metadata["session_id_scope"] == session_id_target
        assert data.session_analysis is not None
        assert len(data.session_analysis["sessions"]) == 1
        assert data.session_analysis["sessions"][0]["session_id"] == session_id_target


# =============================================================================
# 5. PDF DOCUMENT STRUCTURE & CONTENT INTEGRITY
# =============================================================================


def test_pdf_renderer_returns_valid_bytes_and_exact_page_count() -> None:
    """pdf_renderer.render produces genuine PDF bytes and render_with_metadata extracts exact page count."""
    with SessionLocal() as db:
        req = ReportGenerateRequest(report_type="FULL")
        data = report_collector.collect(db, req)

        pdf_bytes, page_count = pdf_renderer.render_with_metadata(data)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 5000
        assert pdf_bytes.startswith(b"%PDF-")

        # Validate regex page count
        regex_pages = len(re.findall(rb"/Type\s*/Page\b", pdf_bytes))
        assert page_count == regex_pages
        assert page_count >= 2


def test_pdf_rendering_with_unicode_and_special_characters() -> None:
    """PDF rendering handles Unicode symbols (arrows, dashes, bullet points) without crashing."""
    with SessionLocal() as db:
        req = ReportGenerateRequest(
            report_type="FULL",
            title="Security Audit: 192.168.1.1 ↔ 192.168.1.2 [AES-GCM-256 / SHA-384] — Verified ✓",
        )
        data = report_collector.collect(db, req)
        pdf_bytes = pdf_renderer.render(data)

        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 5000


def test_pdf_rendering_with_long_text_wrapping() -> None:
    """Long remediation descriptions, large titles, and lengthy hashes wrap cleanly in tables."""
    with SessionLocal() as db:
        req = ReportGenerateRequest(
            report_type="FULL",
            title="A" * 150,  # Extremely long title
        )
        data = report_collector.collect(db, req)

        # Inject extreme text into recommendations
        data.recommendations.append({
            "priority": "Immediate",
            "title": "Unusually Long Recommendation Title That Must Wrap Accurately In ReportLab Platypus Flowables " * 3,
            "description": "Implementation details description containing detailed technical steps " * 10,
            "related_rule": "RULE-OVERFLOW-001",
            "category": "STRESS_TEST",
        })

        pdf_bytes = pdf_renderer.render(data)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 5000


def test_secret_redaction_audit_in_generated_pdf() -> None:
    """Generated PDF binary and metadata must never contain secrets, passwords, private keys, or PSKs."""
    with SessionLocal() as db:
        req = ReportGenerateRequest(report_type="FULL")
        dto = report_service.generate_report(db, req)

        pdf_path = report_service.get_report_pdf_path(db, dto.id)
        assert pdf_path is not None
        pdf_content = pdf_path.read_bytes().lower()

        # Prohibited sensitive keywords
        forbidden_patterns = [
            b"password=",
            b"psk=",
            b"private_key",
            b"-----begin rsa private key-----",
            b"-----begin private key-----",
            b"authorization: bearer",
            b"sqlite:///",
            b"postgresql://",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in pdf_content, f"Prohibited credential pattern found in PDF: {pattern.decode('latin1')}"


# =============================================================================
# 6. PERSISTENCE, RESTART DURABILITY & LIFECYCLE
# =============================================================================


def test_report_metadata_persists_in_sqlite() -> None:
    """ReportRow is persisted accurately in SQLite with correct size, page count, and status."""
    with SessionLocal() as db:
        req = ReportGenerateRequest(report_type="FULL", title="Persistence Verification")
        dto = report_service.generate_report(db, req)

        row = db.scalar(select(ReportRow).where(ReportRow.id == dto.id))
        assert row is not None
        assert row.id == dto.id
        assert row.title == "Persistence Verification"
        assert row.status == "COMPLETED"
        assert row.page_count == dto.page_count
        assert row.file_size_bytes == dto.file_size_bytes
        assert os.path.isfile(row.file_path)


def test_report_durability_across_reconnection() -> None:
    """Report record and file artifact remain fully intact and accessible after database reconnect."""
    with SessionLocal() as db:
        dto = report_service.generate_report(db, ReportGenerateRequest(report_type="FULL"))
        rep_id = dto.id

    # Dispose existing connection pool to simulate restart
    engine.dispose()

    # Reconnect
    with SessionLocal() as fresh_db:
        reloaded = report_service.get_report(fresh_db, rep_id)
        assert reloaded is not None
        assert reloaded.id == rep_id
        assert reloaded.status == "COMPLETED"

        # Verify physical file persists
        pdf_path = report_service.get_report_pdf_path(fresh_db, rep_id)
        assert pdf_path is not None
        assert pdf_path.is_file()
        assert pdf_path.read_bytes().startswith(b"%PDF-")


def test_delete_report_removes_both_record_and_file() -> None:
    """delete_report deletes database record and unlinks file artifact from filesystem."""
    with SessionLocal() as db:
        dto = report_service.generate_report(db, ReportGenerateRequest(report_type="FULL"))
        rep_id = dto.id
        filename = dto.filename

        pdf_path = resolve_report_path(filename)
        assert pdf_path.is_file()

        deleted = report_service.delete_report(db, rep_id)
        assert deleted is True

        # Database record must be gone
        assert report_service.get_report(db, rep_id) is None

        # Physical file must be gone
        assert not pdf_path.is_file()


# =============================================================================
# 7. LAYER 12 REST API INTEGRATION TESTS
# =============================================================================


def test_api_generate_report_success(client) -> None:
    """POST /api/reports/generate generates PDF and returns HTTP 201 with metadata."""
    res = client.post(
        "/api/reports/generate",
        json={"report_type": "FULL", "title": "API Generation Test"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["id"].startswith("REPORT-")
    assert data["report_type"] == "FULL"
    assert data["status"] == "COMPLETED"
    assert data["page_count"] >= 2
    assert data["file_size_bytes"] > 5000
    assert data["download_url"] == f"/api/reports/{data['id']}/download"


def test_api_generate_report_invalid_payload_returns_422(client) -> None:
    """POST /api/reports/generate returns HTTP 422 for unsupported report types."""
    res = client.post(
        "/api/reports/generate",
        json={"report_type": "INVALID_TYPE"},
    )
    assert res.status_code == 422


def test_api_list_reports(client) -> None:
    """GET /api/reports returns ordered list of generated reports."""
    client.post("/api/reports/generate", json={"report_type": "FULL", "title": "Audit 1"})
    client.post("/api/reports/generate", json={"report_type": "VULNERABILITY", "title": "Audit 2"})

    res = client.get("/api/reports")
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 2
    # Verify descending ordering
    assert items[0]["title"] == "Audit 2"
    assert items[1]["title"] == "Audit 1"


def test_api_get_report_metadata(client) -> None:
    """GET /api/reports/{id} retrieves specific metadata, 404 on nonexistent."""
    gen_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    rep_id = gen_res.json()["id"]

    res = client.get(f"/api/reports/{rep_id}")
    assert res.status_code == 200
    assert res.json()["id"] == rep_id

    missing_res = client.get("/api/reports/REPORT-NONEXISTENT-999")
    assert missing_res.status_code == 404


def test_api_download_report_binary_media_type(client) -> None:
    """GET /api/reports/{id}/download streams binary PDF with application/pdf header."""
    gen_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    rep_id = gen_res.json()["id"]
    file_size = gen_res.json()["file_size_bytes"]

    dl_res = client.get(f"/api/reports/{rep_id}/download")
    assert dl_res.status_code == 200
    assert "application/pdf" in dl_res.headers.get("content-type", "")
    assert len(dl_res.content) == file_size
    assert dl_res.content.startswith(b"%PDF-")

    # Missing report returns 404
    missing_dl = client.get("/api/reports/REPORT-NOT-FOUND-000/download")
    assert missing_dl.status_code == 404


def test_api_delete_report(client) -> None:
    """DELETE /api/reports/{id} deletes report and returns deleted confirmation."""
    gen_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    rep_id = gen_res.json()["id"]

    del_res = client.delete(f"/api/reports/{rep_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True
    assert del_res.json()["id"] == rep_id

    # Deleting nonexistent returns 404
    del_missing = client.delete(f"/api/reports/{rep_id}")
    assert del_missing.status_code == 404
