"""Backend tests for Layer 14 — Report Generation (PDF) API endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.init_db import initialize_database
from app.layers.layer14_reports.storage import get_reports_dir, resolve_report_path
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import AnomalyAnalysisRow, AnomalyFeatureContributionRow
from app.models.report import ReportRow
from app.models.security_association import SecurityAssociationRow
from app.models.vulnerability import FindingEvidenceRow, SecurityRuleRow, VulnerabilityFindingRow


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def clean_reports_db():
    """Ensure a clean database and reports storage state for reporting tests."""
    initialize_database()
    db = SessionLocal()
    try:
        db.query(ReportRow).delete()
        db.query(FindingEvidenceRow).delete()
        db.query(VulnerabilityFindingRow).delete()
        db.query(SecurityRuleRow).delete()
        db.query(AnomalyFeatureContributionRow).delete()
        db.query(AnomalyAnalysisRow).delete()
        db.query(SecurityAssociationRow).delete()
        db.query(IPsecSession).delete()
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        # Clean up files created during test
        reports = db.scalars(select(ReportRow)).all()
        for r in reports:
            try:
                p = resolve_report_path(r.filename)
                if p.is_file():
                    p.unlink()
            except Exception:
                pass
        db.query(ReportRow).delete()
        db.query(FindingEvidenceRow).delete()
        db.query(VulnerabilityFindingRow).delete()
        db.query(SecurityRuleRow).delete()
        db.query(AnomalyFeatureContributionRow).delete()
        db.query(AnomalyAnalysisRow).delete()
        db.query(SecurityAssociationRow).delete()
        db.query(IPsecSession).delete()
        db.commit()
    finally:
        db.close()


def test_generate_report_empty_db(client) -> None:
    """Generate report on empty database succeeds with valid PDF bytes and zero fabrication."""
    res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    assert res.status_code == 201
    data = res.json()

    assert data["id"].startswith("REPORT-")
    assert data["report_type"] == "FULL"
    assert data["status"] == "COMPLETED"
    assert data["file_size_bytes"] > 5000  # Valid multi-page PDF is at least several kilobytes
    assert data["download_url"] == f"/api/reports/{data['id']}/download"

    # Verify physical file on disk
    pdf_path = resolve_report_path(data["filename"])
    assert pdf_path.is_file()
    content = pdf_path.read_bytes()
    assert content.startswith(b"%PDF-")


def test_list_reports_endpoint(client) -> None:
    """List reports endpoint returns generated records."""
    client.post("/api/reports/generate", json={"report_type": "FULL", "title": "Test Audit"})
    res = client.get("/api/reports")
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1
    assert items[0]["title"] == "Test Audit"


def test_get_report_metadata(client) -> None:
    """Retrieve metadata for a specific report."""
    gen_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    rep_id = gen_res.json()["id"]

    res = client.get(f"/api/reports/{rep_id}")
    assert res.status_code == 200
    assert res.json()["id"] == rep_id


def test_download_report_endpoint(client) -> None:
    """Download report endpoint returns application/pdf content."""
    gen_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    rep_id = gen_res.json()["id"]

    dl_res = client.get(f"/api/reports/{rep_id}/download")
    assert dl_res.status_code == 200
    assert "application/pdf" in dl_res.headers.get("content-type", "")
    assert dl_res.content.startswith(b"%PDF-")


def test_download_nonexistent_report(client) -> None:
    """Download nonexistent report returns 404."""
    res = client.get("/api/reports/REPORT-DOES-NOT-EXIST/download")
    assert res.status_code == 404


def test_delete_report_endpoint(client) -> None:
    """Delete report endpoint removes database record and disk file."""
    gen_res = client.post("/api/reports/generate", json={"report_type": "FULL"})
    rep_id = gen_res.json()["id"]
    filename = gen_res.json()["filename"]

    pdf_path = resolve_report_path(filename)
    assert pdf_path.is_file()

    del_res = client.delete(f"/api/reports/{rep_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    assert not pdf_path.is_file()
    assert client.get(f"/api/reports/{rep_id}").status_code == 404


def test_generate_report_populated_db(client) -> None:
    """Generate report with populated analysis data creates comprehensive PDF."""
    now = _utc_now()
    with SessionLocal() as db_session:
        session = IPsecSession(
            id="sess-rep-01",
            capture_id="cap-rep-01",
            ordinal=1,
            source="10.0.0.1",
            destination="10.0.0.2",
            direction="OUTBOUND",
            state="ACTIVE",
            correlation="DIRECT",
            start_time="2026-09-04T10:00:00Z",
            duration_seconds=60.0,
            packet_count=100,
            byte_count=10000,
            ike_packets=20,
            esp_packets=80,
            ah_packets=0,
            ike_version="IKEv2",
            nat_traversal=False,
            detail_json="{}",
            discovered_at=now,
        )
        db_session.add(session)

        rule = SecurityRuleRow(
            id="RULE-REP-001",
            name="Insecure Cipher Test",
            category="CRYPTO",
            severity="HIGH",
            default_confidence="HIGH",
            enabled=True,
            version="1.0",
            description="Test description",
            remediation="Upgrade to AES-GCM",
            references_json="[]",
            created_at=now,
            updated_at=now,
        )
        db_session.add(rule)

        finding = VulnerabilityFindingRow(
            id="vuln-rep-01",
            rule_id="RULE-REP-001",
            rule_version="1.0",
            title="Deprecated Cipher Observed",
            description="Legacy 3DES cipher observed in tunnel negotiation.",
            category="CRYPTO",
            severity="HIGH",
            confidence="HIGH",
            status="OPEN",
            affected_object_type="SESSION",
            affected_object_id="sess-rep-01",
            affected_session_id="sess-rep-01",
            dedup_hash="hash-rep-001",
            occurrence_count=1,
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db_session.add(finding)
        db_session.commit()

    res = client.post(
        "/api/reports/generate",
        json={"report_type": "SESSION", "session_id": "sess-rep-01", "title": "Session Assessment"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["title"] == "Session Assessment"
    assert data["file_size_bytes"] > 8000
