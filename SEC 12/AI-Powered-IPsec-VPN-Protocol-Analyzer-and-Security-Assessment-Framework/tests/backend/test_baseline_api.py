"""End-to-end API tests for Layer 06 Baseline Profiling & Session Fingerprinting."""

from __future__ import annotations

import io
import pytest

from test_session_api import TWO_SESSIONS, upload


@pytest.fixture(autouse=True)
def _clean_all(client):
    client.delete("/api/packets")
    client.delete("/api/sessions")
    client.delete("/api/features")
    client.delete("/api/baselines")
    yield
    client.delete("/api/packets")
    client.delete("/api/sessions")
    client.delete("/api/features")
    client.delete("/api/baselines")


def test_baseline_status_uninitialized(client) -> None:
    res = client.get("/api/baselines/status")
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "NOT INITIALIZED"
    assert data["total_baselines"] == 0
    assert data["total_fingerprints"] == 0


def test_list_baselines_empty(client) -> None:
    res = client.get("/api/baselines")
    assert res.status_code == 200
    assert res.json() == []


def test_build_baseline_requires_capture(client) -> None:
    res = client.post("/api/baselines", json={"name": "No Capture Baseline"})
    assert res.status_code == 409
    assert res.json()["error"] == "PACKET_DATA_UNAVAILABLE"


def test_baseline_full_lifecycle(client) -> None:
    # 1. Upload capture
    up = upload(client, TWO_SESSIONS)
    assert up.status_code == 201

    # 2. Discover sessions
    disc = client.post("/api/sessions/discover")
    assert disc.status_code == 200
    sessions_data = client.get("/api/sessions").json()["items"]
    assert len(sessions_data) >= 1
    session_id = sessions_data[0]["id"]

    # 3. Baseline status reflects sessions exist -> READY
    st = client.get("/api/baselines/status").json()
    assert st["state"] == "READY"

    # 4. Fetch / generate fingerprint for session
    fp_res = client.get(f"/api/sessions/{session_id}/fingerprint")
    assert fp_res.status_code == 200
    fp_data = fp_res.json()
    assert fp_data["session_id"] == session_id
    assert fp_data["feature_version"] == "1.0"
    assert len(fp_data["signature"]) == 64
    fingerprint_id = fp_data["id"]

    # 5. List fingerprints
    fps = client.get("/api/fingerprints").json()
    assert len(fps) >= 1
    assert any(f["id"] == fingerprint_id for f in fps)

    # 6. Build a baseline with minimum_sessions=1
    build_res = client.post(
        "/api/baselines",
        json={
            "name": "Reference Production Baseline",
            "description": "Baseline compiled from observed traffic.",
            "minimum_sessions": 1,
            "activate": True,
        },
    )
    assert build_res.status_code == 200
    baseline = build_res.json()
    baseline_id = baseline["id"]
    assert baseline["name"] == "Reference Production Baseline"
    assert baseline["status"] == "READY"
    assert baseline["is_active"] is True
    assert baseline["session_count"] >= 1
    assert len(baseline["features"]) > 0
    assert baseline["coverage"]["total_sessions"] >= 1

    # 7. Check status is now AVAILABLE
    st2 = client.get("/api/baselines/status").json()
    assert st2["state"] == "AVAILABLE"
    assert st2["total_baselines"] == 1
    assert st2["active_baseline_id"] == baseline_id

    # 8. Query baseline features endpoint
    feat_res = client.get(f"/api/baselines/{baseline_id}/features")
    assert feat_res.status_code == 200
    feats = feat_res.json()
    assert len(feats) > 0
    pkt_feat = next((f for f in feats if f["name"] == "packet_count"), None)
    assert pkt_feat is not None
    assert pkt_feat["numeric_stats"] is not None
    assert pkt_feat["numeric_stats"]["count"] >= 1

    # 9. Query baseline sessions endpoint
    sess_res = client.get(f"/api/baselines/{baseline_id}/sessions")
    assert sess_res.status_code == 200
    b_sessions = sess_res.json()
    assert len(b_sessions) >= 1
    assert b_sessions[0]["session_id"] == session_id

    # 10. Descriptive comparison between fingerprint and baseline
    comp_res = client.get(f"/api/baselines/{baseline_id}/compare/{fingerprint_id}")
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["baseline_id"] == baseline_id
    assert comp_data["fingerprint_id"] == fingerprint_id
    assert len(comp_data["features"]) > 0

    # 11. Activation endpoint
    act_res = client.post(f"/api/baselines/{baseline_id}/activate")
    assert act_res.status_code == 200
    assert act_res.json()["is_active"] is True
