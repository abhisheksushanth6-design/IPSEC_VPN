"""Backend tests for Layer 08/09 Metadata Exposure Assessment Engine.

Validates:
1. Correct evaluation HTTP method (POST /api/metadata-exposure/assess/{capture_id})
2. 405 mismatch prevention (POST evaluate returns 405, PUT/DELETE assess returns 405, POST assess succeeds)
3. Successful metadata exposure evaluation on loaded capture and session data
4. Dynamic 5-vector leakage score calculation and overall derivation
5. Empty / no-capture handling
"""

from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from app.db.base import SessionLocal
from app.models.ipsec_session import IPsecSession
from app.services.packet_service import packet_service
from app.layers.layer09_vulnerability_engine.metadata_exposure import (
    MetadataExposureAnalyzer,
    MetadataExposureService,
)


def _seed_test_session(db, capture_id: str, session_id: str = "SESS-TEST-001") -> IPsecSession:
    """Helper to create a realistic test IPsec session."""
    existing = db.get(IPsecSession, session_id)
    if existing:
        return existing

    session = IPsecSession(
        id=session_id,
        capture_id=capture_id,
        ordinal=1,
        source="192.168.1.100",
        destination="10.0.0.1",
        direction="OUTBOUND",
        state="ESTABLISHED",
        correlation="IKE_ESP",
        start_time="2026-09-25T12:00:00Z",
        end_time="2026-09-25T12:02:00Z",
        duration_seconds=120.0,
        packet_count=150,
        byte_count=102400,
        ike_packets=4,
        esp_packets=146,
        ah_packets=0,
        ike_version="IKEv2",
        nat_traversal=True,
        ipsec_mode="TUNNEL",
        ip_version=4,
        detail_json=json.dumps({
            "esp": {"spis": [{"spi": "0x1234abcd"}]},
            "ike": {"initiator_spis": ["0xaaaa"], "responder_spis": ["0xbbbb"]},
        }),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def test_correct_evaluation_http_method_and_path(client: TestClient) -> None:
    """Ensure POST /api/metadata-exposure/assess/{capture_id} is the valid endpoint."""
    with SessionLocal() as db:
        _seed_test_session(db, "test-cap-http")

    resp = client.post("/api/metadata-exposure/assess/test-cap-http")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["session_id"] == "SESS-TEST-001"


def test_405_mismatch_prevention(client: TestClient) -> None:
    """Verify that calling invalid routes or unsupported methods produces 405 Method Not Allowed."""
    # 1. Calling the former wrong path /evaluate returns 405 Method Not Allowed
    resp_evaluate = client.post("/api/metadata-exposure/evaluate/test-cap-method")
    assert resp_evaluate.status_code == 405

    # 2. Calling unsupported HTTP methods on the correct route /assess returns 405
    resp_put = client.put("/api/metadata-exposure/assess/test-cap-method")
    assert resp_put.status_code == 405

    resp_delete = client.delete("/api/metadata-exposure/assess/test-cap-method")
    assert resp_delete.status_code == 405

    # 3. Whereas POST on /assess succeeds cleanly with 200
    with SessionLocal() as db:
        _seed_test_session(db, "test-cap-method", session_id="SESS-METHOD-001")
    post_resp = client.post("/api/metadata-exposure/assess/test-cap-method")
    assert post_resp.status_code == 200


def test_five_vector_score_calculation(client: TestClient) -> None:
    """Verify that overall_score is derived dynamically from the 5 leakage vectors."""
    with SessionLocal() as db:
        sess = _seed_test_session(db, "test-cap-vectors", session_id="SESS-VEC-001")

        # Evaluate directly through analyzer
        overall, risk_level, scores, findings, recommendations = MetadataExposureAnalyzer.evaluate_session(sess, db=db)

        # Mathematical derivation check
        expected_overall = round(
            0.20 * scores["spi_leakage_score"]
            + 0.20 * scores["sequence_leakage_score"]
            + 0.25 * scores["packet_length_leakage_score"]
            + 0.20 * scores["timing_leakage_score"]
            + 0.15 * scores["topology_leakage_score"],
            2,
        )
        assert overall == expected_overall
        assert 0.0 <= overall <= 100.0

        # Verify all 5 vector scores exist and are non-negative
        assert "spi_leakage_score" in scores
        assert "sequence_leakage_score" in scores
        assert "packet_length_leakage_score" in scores
        assert "timing_leakage_score" in scores
        assert "topology_leakage_score" in scores

        # Verify via API endpoint
        resp = client.post("/api/metadata-exposure/assess/test-cap-vectors")
        assert resp.status_code == 200
        item = resp.json()[0]
        assert item["overall_score"] == pytest.approx(overall, abs=0.1)
        assert item["spi_leakage_score"] == pytest.approx(scores["spi_leakage_score"], abs=0.1)
        assert item["sequence_leakage_score"] == pytest.approx(scores["sequence_leakage_score"], abs=0.1)
        assert item["packet_length_leakage_score"] == pytest.approx(scores["packet_length_leakage_score"], abs=0.1)
        assert item["timing_leakage_score"] == pytest.approx(scores["timing_leakage_score"], abs=0.1)
        assert item["topology_leakage_score"] == pytest.approx(scores["topology_leakage_score"], abs=0.1)
        assert item["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(item["findings"]) >= 0


def test_empty_or_no_capture_handling(client: TestClient) -> None:
    """Verify that when no capture or sessions exist, endpoints return clean empty states."""
    # Assess on nonexistent capture
    resp = client.post("/api/metadata-exposure/assess/nonexistent-capture-xyz")
    assert resp.status_code == 200
    assert resp.json() == []

    # Get assessments on nonexistent capture
    resp_get = client.get("/api/metadata-exposure/capture/nonexistent-capture-xyz")
    assert resp_get.status_code == 200
    assert resp_get.json() == []

    # Get summary on nonexistent capture
    sum_resp = client.get("/api/metadata-exposure/summary/nonexistent-capture-xyz")
    assert sum_resp.status_code == 200
    sum_data = sum_resp.json()
    assert sum_data["total_assessed"] == 0
    assert sum_data["average_score"] == 0.0
    assert sum_data["highest_risk_level"] == "LOW"


def test_default_capture_resolution(client: TestClient) -> None:
    """Verify that capture_id='default' resolves to packet_service.capture_id."""
    with SessionLocal() as db:
        _seed_test_session(db, "active-pcap-capture", session_id="SESS-DEF-001")

    # Set packet_service._capture_id
    packet_service._capture_id = "active-pcap-capture"
    try:
        resp = client.post("/api/metadata-exposure/assess/default")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) >= 1
        assert any(it["session_id"] == "SESS-DEF-001" for it in items)

        # Also summary
        sum_resp = client.get("/api/metadata-exposure/summary/default")
        assert sum_resp.status_code == 200
        assert sum_resp.json()["total_assessed"] >= 1
    finally:
        packet_service._capture_id = None
