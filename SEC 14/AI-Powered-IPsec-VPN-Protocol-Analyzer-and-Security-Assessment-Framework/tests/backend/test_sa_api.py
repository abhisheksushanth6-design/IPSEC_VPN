"""SA lifecycle API tests."""

from __future__ import annotations

import io

import pytest

from test_sa_lifecycle import auth_req, auth_resp, child_req, child_resp, esp_frame, plaintext_delete, sa_init_req, sa_init_resp
from test_session_correlation import T0, pcap_at

LIFECYCLE = pcap_at([
    sa_init_req(T0), sa_init_resp(T0 + 0.1), auth_req(T0 + 0.2), auth_resp(T0 + 0.3),
    (esp_frame(spi=0xA1, seq=1), T0 + 1), (esp_frame(spi=0xA1, seq=2), T0 + 2),
    child_req(T0 + 5), child_resp(T0 + 5.1), (esp_frame(spi=0xA2, seq=1), T0 + 6),
    plaintext_delete(T0 + 9),
])


def upload(client, data: bytes):
    return client.post("/api/packets/upload", files={"file": ("sa.pcap", io.BytesIO(data), "application/octet-stream")})


@pytest.fixture(autouse=True)
def _clean(client):
    client.delete("/api/packets")
    yield
    client.delete("/api/packets")


def test_status_progression(client) -> None:
    assert client.get("/api/sas/status").json()["state"] == "NOT INITIALIZED"
    assert client.post("/api/sas/discover").status_code == 409
    upload(client, LIFECYCLE)
    body = client.get("/api/sas/status").json()
    assert body["state"] == "READY" and body["packets_available"] is True and body["sessions_available"] is False
    body = client.post("/api/sas/discover").json()
    assert body["state"] == "ACTIVE"
    assert body["statistics"] == {"total": 3, "ike": 1, "child": 2, "active": 2, "established": 0, "negotiating": 0, "rekeying": 0, "terminated": 1, "failed": 0, "detected": 0, "unknown": 0}


def test_list_detail_timeline_and_packets(client) -> None:
    upload(client, LIFECYCLE)
    client.post("/api/sas/discover")
    page = client.get("/api/sas").json()
    assert page["total"] == 3
    ike = next(i for i in page["items"] if i["type"] == "IKE")
    assert ike["state"] == "TERMINATED" and ike["rekey_count"] == 1 and ike["ike_version"] == "2.0"

    detail = client.get(f"/api/sas/{ike['id']}").json()
    assert [h["state"] for h in detail["state_history"]] == ["DETECTED", "NEGOTIATING", "ESTABLISHED", "ACTIVE", "REKEYING", "ACTIVE", "TERMINATED"]
    assert len(detail["child_sas"]) == 2 and detail["parent"] is None
    assert detail["security_parameters_available"] is False
    assert detail["packets_total"] == 7 and [p["number"] for p in detail["packets"]] == [1, 2, 3, 4, 7, 8, 10]
    assert all(p["spi"] for p in detail["packets"])

    timeline = client.get(f"/api/sas/{ike['id']}/timeline").json()
    assert [e["event_type"] for e in timeline if e["previous_state"] != e["new_state"]] == [
        "SA DETECTED", "NEGOTIATION START", "SA ESTABLISHED", "IPSEC TRAFFIC OBSERVED", "REKEY START", "REKEY COMPLETE", "DELETE OBSERVED"]
    assert len(client.get(f"/api/sas/{ike['id']}/packets").json()) == 7

    child = next(i for i in page["items"] if i["spi"] == "0x000000a2")
    cd = client.get(f"/api/sas/{child['id']}").json()
    assert cd["parent"]["id"] == ike["id"] and cd["association"] == "CORRELATED"
    assert any(e["event_type"] == "CREATED AFTER REKEY" for e in cd["timeline"])


def test_session_association_when_sessions_discovered(client) -> None:
    upload(client, LIFECYCLE)
    client.post("/api/sessions/discover")
    client.post("/api/sas/discover")
    session_id = client.get("/api/sessions").json()["items"][0]["id"]
    assert client.get("/api/sas/status").json()["sessions_available"] is True
    linked = client.get(f"/api/sas/for-session/{session_id}").json()
    assert len(linked["associations"]) == 3
    ike = client.get("/api/sas", params={"type": "IKE"}).json()["items"][0]
    assert ike["session_id"] == session_id


def test_no_session_association_without_session_discovery(client) -> None:
    upload(client, LIFECYCLE)
    client.post("/api/sas/discover")
    assert all(i["session_id"] is None for i in client.get("/api/sas").json()["items"])


def test_for_packet(client) -> None:
    upload(client, LIFECYCLE)
    client.post("/api/sas/discover")
    packets = client.get("/api/packets").json()["items"]
    esp = next(p for p in packets if p["number"] == 5)
    refs = client.get(f"/api/sas/for-packet/{esp['id']}").json()
    assert len(refs) == 1 and refs[0]["type"] == "CHILD" and refs[0]["spi"] == "0x000000a1"


def test_filters_search_sort(client) -> None:
    upload(client, LIFECYCLE)
    client.post("/api/sas/discover")
    assert client.get("/api/sas", params={"type": "child"}).json()["total"] == 2
    assert client.get("/api/sas", params={"state": "terminated"}).json()["total"] == 1
    assert client.get("/api/sas", params={"spi": "a2"}).json()["total"] == 1
    assert client.get("/api/sas", params={"search": "0101010101010101"}).json()["total"] == 1
    assert client.get("/api/sas", params={"protocol": "ESP"}).json()["total"] == 2
    desc = client.get("/api/sas", params={"sort": "packet_count", "order": "desc"}).json()["items"]
    assert [i["packet_count"] for i in desc] == [7, 2, 1]


def test_ids_stable_and_clear(client) -> None:
    upload(client, LIFECYCLE)
    a = sorted(i["id"] for i in (client.post("/api/sas/discover"), client.get("/api/sas"))[1].json()["items"])
    b = sorted(i["id"] for i in (client.post("/api/sas/discover"), client.get("/api/sas"))[1].json()["items"])
    assert a == b
    assert client.delete("/api/sas").json()["state"] == "READY"
    r = client.get("/api/sas/SA-NOPE")
    assert r.status_code == 404 and r.json()["error"] == "SA_NOT_FOUND"


def test_layer_statuses(client) -> None:
    layers = client.get("/api/system/status").json()["architecture_layers"]
    assert layers[3]["status"] in ("IN DEVELOPMENT", "OPERATIONAL", "READY")
    assert layers[4]["status"] in ("IN DEVELOPMENT", "OPERATIONAL", "READY")  # Layer 05 (Section 8)
    assert layers[5]["status"] in ("IN DEVELOPMENT", "OPERATIONAL", "READY")  # Layer 06 (Section 9)
    assert layers[6]["status"] in ("IN DEVELOPMENT", "OPERATIONAL", "READY")  # Layer 07 (Section 10)
    assert layers[7]["status"] == "OPERATIONAL"  # Layer 08 (Section 11)
    assert layers[8]["status"] == "OPERATIONAL"  # Layer 09 (Section 12)
    assert layers[9]["status"] in ("OPERATIONAL", "NOT INITIALIZED", "READY")  # Layer 10
