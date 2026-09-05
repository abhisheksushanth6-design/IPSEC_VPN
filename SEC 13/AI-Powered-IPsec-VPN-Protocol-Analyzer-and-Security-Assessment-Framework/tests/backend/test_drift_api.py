"""API endpoint tests for Layer 07 — Security Drift Detection."""

from __future__ import annotations

import pytest

from test_session_api import TWO_SESSIONS, upload


@pytest.fixture(autouse=True)
def _clean_all(client):
    client.delete("/api/packets")
    client.delete("/api/sessions")
    client.delete("/api/features")
    client.delete("/api/baselines")
    client.delete("/api/drift")
    yield
    client.delete("/api/packets")
    client.delete("/api/sessions")
    client.delete("/api/features")
    client.delete("/api/baselines")
    client.delete("/api/drift")


def test_api_drift_status_uninitialized(client) -> None:
    """GET /api/drift/status returns NOT INITIALIZED before baselines exist."""
    r = client.get("/api/drift/status")
    assert r.status_code == 200
    data = r.json()
    assert data["state"] == "NOT INITIALIZED"
    assert data["total_analyses"] == 0
    assert data["sessions_evaluated"] == 0


def test_api_drift_config(client) -> None:
    """GET /api/drift/config returns centralized threshold parameters."""
    r = client.get("/api/drift/config")
    assert r.status_code == 200
    cfg = r.json()
    assert cfg["config_version"] == "1.0"
    assert cfg["z_score_low"] == 2.0
    assert cfg["z_score_moderate"] == 3.0
    assert cfg["z_score_high"] == 4.0
    assert cfg["enable_percentile_check"] is True


def test_api_drift_missing_baseline_raises_400(client) -> None:
    """POST /api/drift/analyze without an active baseline returns 400."""
    res = client.post("/api/drift/analyze", json={"session_id": "SESS-NO-BASE"})
    assert res.status_code == 400
    data = res.json()
    assert "DRIFT_PRECONDITION_FAILED" in str(data)


def test_api_drift_lifecycle_and_endpoints(client) -> None:
    """Full lifecycle: upload traffic, correlate session, build baseline, evaluate drift."""
    from app.services.drift_service import drift_service
    drift_service.config.minimum_baseline_samples = 1

    # 1. Upload traffic and discover sessions
    up = upload(client, TWO_SESSIONS)
    assert up.status_code == 201

    disc = client.post("/api/sessions/discover")
    assert disc.status_code == 200
    sessions_data = client.get("/api/sessions").json()["items"]
    assert len(sessions_data) >= 1
    session_id = sessions_data[0]["id"]

    # 2. Build active reference baseline
    b_res = client.post(
        "/api/baselines",
        json={"name": "Reference Production Baseline", "minimum_sessions": 1, "activate": True},
    )
    assert b_res.status_code in (200, 201)
    baseline_id = b_res.json()["id"]

    # 3. Drift engine status should now be READY
    st_ready = client.get("/api/drift/status").json()
    assert st_ready["state"] == "READY"
    assert st_ready["active_baseline_id"] == baseline_id

    # 4. Trigger drift analysis via POST /api/drift/analyze
    analyze_res = client.post("/api/drift/analyze", json={"session_id": session_id})
    assert analyze_res.status_code == 201
    analysis = analyze_res.json()
    assert analysis["session_id"] == session_id
    assert analysis["baseline_id"] == baseline_id
    assert analysis["status"] in ("WITHIN BASELINE", "DRIFT DETECTED")
    assert analysis["severity"] in ("NONE", "LOW", "MODERATE", "HIGH")
    assert analysis["features_analyzed"] > 0
    analysis_id = analysis["id"]

    # 5. List drift analyses via GET /api/drift
    list_res = client.get("/api/drift")
    assert list_res.status_code == 200
    items = list_res.json()
    assert len(items) >= 1
    assert items[0]["id"] == analysis_id

    # 6. Fetch specific analysis details via GET /api/drift/{id}
    detail_res = client.get(f"/api/drift/{analysis_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == analysis_id
    assert len(detail["feature_results"]) == analysis["features_analyzed"]

    # 7. Fetch feature results via GET /api/drift/{id}/features
    feat_res = client.get(f"/api/drift/{analysis_id}/features")
    assert feat_res.status_code == 200
    assert len(feat_res.json()) == analysis["features_analyzed"]

    # 8. Fetch latest for session via GET /api/drift/session/{session_id}
    sess_res = client.get(f"/api/drift/session/{session_id}")
    assert sess_res.status_code == 200
    assert sess_res.json()["id"] == analysis_id

    # 9. Engine status should now be AVAILABLE
    st_avail = client.get("/api/drift/status").json()
    assert st_avail["state"] == "AVAILABLE"
    assert st_avail["total_analyses"] >= 1

    # 10. Delete drift evaluations
    del_res = client.delete("/api/drift")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "CLEARED"

    # 11. Listing should now be empty
    assert client.get("/api/drift").json() == []


def test_api_drift_not_found(client) -> None:
    """GET /api/drift/{unknown} returns 404."""
    r = client.get("/api/drift/DA-UNKNOWN-ID")
    assert r.status_code == 404
