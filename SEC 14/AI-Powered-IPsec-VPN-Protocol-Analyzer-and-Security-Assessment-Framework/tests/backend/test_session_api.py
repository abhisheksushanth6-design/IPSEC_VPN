"""IPsec sessions API tests."""

from __future__ import annotations

import io

import pytest

from packet_builders import DST4, SRC4, esp, ethernet, ikev2, ipv4, pcap, tcp, udp
from test_session_correlation import pcap_at, T0

TWO_SESSIONS = pcap_at([
    (ethernet(ipv4(udp(ikev2(flags=0x08), 500, 500), proto=17)), T0),
    (ethernet(ipv4(udp(ikev2(exchange=35, payloads=[(46, b"\x00" * 8)], flags=0x20, message_id=1), 500, 500), proto=17, src=DST4, dst=SRC4)), T0 + 1),
    (ethernet(ipv4(esp(spi=0xAAAA0001, seq=1), proto=50)), T0 + 2),
    (ethernet(ipv4(esp(spi=0x12345678, seq=1), proto=50, src="192.0.2.30", dst="198.51.100.40")), T0 + 3),
    (ethernet(ipv4(tcp(), proto=6)), T0 + 4),
])


def upload(client, data: bytes, name: str = "sessions.pcap"):
    return client.post("/api/packets/upload", files={"file": (name, io.BytesIO(data), "application/octet-stream")})


@pytest.fixture(autouse=True)
def _clean(client):
    client.delete("/api/packets")
    client.delete("/api/sessions")
    yield
    client.delete("/api/packets")
    client.delete("/api/sessions")


def test_status_not_initialized_without_packets(client) -> None:
    body = client.get("/api/sessions/status").json()
    assert body["state"] == "NOT INITIALIZED" and body["packets_available"] is False and body["statistics"] is None


def test_discover_requires_packets(client) -> None:
    r = client.post("/api/sessions/discover")
    assert r.status_code == 409 and r.json()["error"] == "PACKET_DATA_UNAVAILABLE"


def test_ready_after_upload_then_available_after_discover(client) -> None:
    upload(client, TWO_SESSIONS)
    assert client.get("/api/sessions/status").json()["state"] == "READY"
    assert client.get("/api/sessions").json()["total"] == 0
    body = client.post("/api/sessions/discover").json()
    assert body["state"] == "AVAILABLE"
    assert body["statistics"] == {"total": 2, "active": 2, "established": 0, "negotiating": 0, "terminated": 0, "discovered": 0, "unknown": 0}
    assert body["discovered_at"]


def test_list_detail_and_packet_association(client) -> None:
    upload(client, TWO_SESSIONS)
    client.post("/api/sessions/discover")
    page = client.get("/api/sessions").json()
    assert page["total"] == 2
    first = page["items"][0]
    assert first["source"] == SRC4 and first["destination"] == DST4
    assert first["packet_count"] == 3 and first["ike_packets"] == 2 and first["esp_packets"] == 1
    assert first["direction"] == "BIDIRECTIONAL" and first["ike_version"] == "2.0"

    detail = client.get(f"/api/sessions/{first['id']}").json()
    assert detail["packets_available"] is True and detail["packets_total"] == 3
    assert [p["number"] for p in detail["packets"]] == [1, 2, 3]
    assert detail["ike"]["exchange_types"] == ["IKE_SA_INIT", "IKE_AUTH"]
    assert detail["esp"]["spis"][0]["spi"] == "0xaaaa0001"
    assert detail["ah"] is None
    assert [e["label"] for e in detail["timeline"]][0] == "First packet"
    assert detail["evidence"]

    # Packet → session lookup, including a packet outside any session.
    packets = client.get("/api/packets").json()["items"]
    esp_packet = next(p for p in packets if p["number"] == 3)
    tcp_packet = next(p for p in packets if p["number"] == 5)
    assert client.get(f"/api/sessions/for-packet/{esp_packet['id']}").json()["session_id"] == first["id"]
    assert client.get(f"/api/sessions/for-packet/{tcp_packet['id']}").json()["session_id"] is None


def test_session_ids_stable_across_rediscovery(client) -> None:
    upload(client, TWO_SESSIONS)
    a = [s["id"] for s in (client.post("/api/sessions/discover"), client.get("/api/sessions"))[1].json()["items"]]
    b = [s["id"] for s in (client.post("/api/sessions/discover"), client.get("/api/sessions"))[1].json()["items"]]
    assert a == b


def test_filters_search_and_sort(client) -> None:
    upload(client, TWO_SESSIONS)
    client.post("/api/sessions/discover")
    assert client.get("/api/sessions", params={"protocol": "IKE"}).json()["total"] == 1
    assert client.get("/api/sessions", params={"state": "active"}).json()["total"] == 2
    assert client.get("/api/sessions", params={"source": "192.0.2.30"}).json()["total"] == 1
    assert client.get("/api/sessions", params={"ike_version": "2.0"}).json()["total"] == 1
    assert client.get("/api/sessions", params={"search": "0x12345678"}).json()["total"] == 1
    desc = client.get("/api/sessions", params={"sort": "packet_count", "order": "desc"}).json()["items"]
    assert [i["packet_count"] for i in desc] == [3, 1]


def test_unknown_session_404(client) -> None:
    r = client.get("/api/sessions/IPSEC-NOPE")
    assert r.status_code == 404 and r.json()["error"] == "SESSION_NOT_FOUND"


def test_clearing_packets_clears_sessions(client) -> None:
    upload(client, TWO_SESSIONS)
    client.post("/api/sessions/discover")
    client.delete("/api/packets")
    assert client.get("/api/sessions/status").json()["state"] == "NOT INITIALIZED"
    assert client.get("/api/sessions").json()["total"] == 0


def test_architecture_layers_04_to_10_unchanged(client) -> None:
    layers = client.get("/api/system/status").json()["architecture_layers"]
    assert layers[5]["name"] == "IPsec Session Fingerprinting"
    assert layers[5]["status"] in ("IN DEVELOPMENT", "OPERATIONAL", "READY")  # Layer 06 (Section 9)
    assert layers[6]["status"] in ("IN DEVELOPMENT", "OPERATIONAL", "READY")  # Layer 07 (Section 10)
    assert layers[7]["status"] == "OPERATIONAL"  # Layer 08 (Section 11)
    assert layers[8]["status"] == "OPERATIONAL"  # Layer 09 (Section 12)
    assert layers[9]["status"] in ("OPERATIONAL", "NOT INITIALIZED", "READY")  # Layer 10
