"""Packet-analysis API tests through the FastAPI test client."""

from __future__ import annotations

import io

import pytest

from packet_builders import ah, esp, ethernet, icmp, ikev2, ipv4, pcap, tcp, udp

MIXED = pcap([
    ethernet(ipv4(udp(ikev2(), 500, 500), proto=17)),
    ethernet(ipv4(esp(spi=0xC0FFEE01), proto=50)),
    ethernet(ipv4(ah(), proto=51)),
    ethernet(ipv4(tcp(dport=443), proto=6)),
    ethernet(ipv4(udp(b"dns", 5353, 53), proto=17)),
    ethernet(ipv4(icmp(8), proto=1)),
    ethernet(b"\x45\x00"),
])


def upload(client, data: bytes, name: str = "test.pcap"):
    return client.post("/api/packets/upload", files={"file": (name, io.BytesIO(data), "application/octet-stream")})


@pytest.fixture(autouse=True)
def _clean(client):
    client.delete("/api/packets")
    yield
    client.delete("/api/packets")


def test_status_not_initialized_before_upload(client) -> None:
    body = client.get("/api/packets/status").json()
    assert body["state"] == "NOT INITIALIZED"
    assert body["statistics"] is None
    assert body["protocol_counts"] is None
    assert body["supported_formats"] == ["pcap", "pcapng"]


def test_upload_parses_and_reports_real_counts(client) -> None:
    r = upload(client, MIXED)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "COMPLETED"
    assert body["capture"]["format"] == "pcap"
    assert body["capture"]["filename"] == "test.pcap"
    assert body["statistics"] == {
        "total_packets": 7, "ipsec_packets": 3, "ike_packets": 1, "esp_packets": 1,
        "ah_packets": 1, "malformed_packets": 1,
    }
    assert body["protocol_counts"] == {"IKE": 1, "ESP": 1, "AH": 1, "TCP": 1, "UDP": 1, "ICMP": 1, "OTHER": 1}


def test_list_and_detail(client) -> None:
    upload(client, MIXED)
    page = client.get("/api/packets").json()
    assert page["total"] == 7 and [i["number"] for i in page["items"]] == list(range(1, 8))

    first = page["items"][0]
    assert first["protocol"] == "IKE" and first["ipsec_type"] == "IKE"
    detail = client.get(f"/api/packets/{first['id']}").json()
    assert detail["ipsec"]["ike"]["exchange_name"] == "IKE_SA_INIT"
    assert [p["name"] for p in detail["ipsec"]["ike"]["payloads"]] == ["SA", "KE", "Nonce"]
    assert detail["transport"]["kind"] == "UDP"
    assert detail["raw"]["hex"]


def test_filters(client) -> None:
    upload(client, MIXED)
    assert client.get("/api/packets", params={"protocol": "esp"}).json()["total"] == 1
    assert client.get("/api/packets", params={"ipsec": "NON-IPSEC"}).json()["total"] == 4
    assert client.get("/api/packets", params={"ipsec": "AH"}).json()["total"] == 1
    assert client.get("/api/packets", params={"port": 443}).json()["total"] == 1
    assert client.get("/api/packets", params={"source": "192.0.2"}).json()["total"] == 6
    assert client.get("/api/packets", params={"search": "0xc0ffee01"}).json()["total"] == 1
    assert client.get("/api/packets", params={"search": "IKE_SA_INIT"}).json()["total"] == 1


def test_sorting_and_pagination(client) -> None:
    upload(client, MIXED)
    desc = client.get("/api/packets", params={"sort": "length", "order": "desc"}).json()
    lengths = [i["length"] for i in desc["items"]]
    assert lengths == sorted(lengths, reverse=True)
    p2 = client.get("/api/packets", params={"page": 2, "page_size": 3}).json()
    assert p2["page"] == 2 and p2["total_pages"] == 3 and [i["number"] for i in p2["items"]] == [4, 5, 6]


def test_malformed_packet_is_reported_not_hidden(client) -> None:
    upload(client, MIXED)
    items = client.get("/api/packets").json()["items"]
    bad = [i for i in items if i["parse_status"] != "OK"]
    assert len(bad) == 1
    detail = client.get(f"/api/packets/{bad[0]['id']}").json()
    assert detail["parse_status"] == "MALFORMED"
    assert detail["parse_affected_protocol"] == "IPv4"
    assert detail["flags"]["malformed"] is True


def test_reanalyze_and_clear(client) -> None:
    upload(client, MIXED)
    assert client.post("/api/packets/analyze").json()["statistics"]["total_packets"] == 7
    assert client.delete("/api/packets").json()["state"] == "NOT INITIALIZED"
    assert client.get("/api/packets").json()["total"] == 0
    r = client.post("/api/packets/analyze")
    assert r.status_code == 409 and r.json()["error"] == "NO_PACKET_SOURCE"


def test_unsupported_extension_rejected(client) -> None:
    r = upload(client, MIXED, name="capture.txt")
    assert r.status_code == 415 and r.json()["error"] == "CAPTURE_FORMAT_UNSUPPORTED"


def test_invalid_content_rejected(client) -> None:
    r = upload(client, b"definitely not a capture file", name="bad.pcap")
    assert r.status_code == 422 and r.json()["error"] == "PACKET_PARSE_ERROR"
    assert client.get("/api/packets/status").json()["state"] == "NOT INITIALIZED"


def test_oversize_rejected(client) -> None:
    from app.services.packet_service import MAX_UPLOAD_BYTES
    r = upload(client, b"\x00" * (MAX_UPLOAD_BYTES + 1), name="huge.pcap")
    assert r.status_code == 413 and r.json()["error"] == "UPLOAD_TOO_LARGE"


def test_filename_is_sanitised(client) -> None:
    r = upload(client, MIXED, name="../../etc/../evil name?.pcap")
    assert r.status_code == 201
    assert "/" not in r.json()["capture"]["filename"]
    assert r.json()["capture"]["filename"].endswith(".pcap")


def test_unknown_packet_404(client) -> None:
    r = client.get("/api/packets/does-not-exist")
    assert r.status_code == 404 and r.json()["error"] == "PACKET_NOT_FOUND"


def test_architecture_reports_layer03_in_development(client) -> None:
    layers = client.get("/api/system/status").json()["architecture_layers"]
    assert layers[2]["number"] == 3 and layers[2]["status"] == "IN DEVELOPMENT"
    assert layers[4]["status"] == "IN DEVELOPMENT"  # Layer 05 (Section 8)
    assert layers[5]["status"] == "IN DEVELOPMENT"  # Layer 06 (Section 9)
    assert layers[6]["status"] == "IN DEVELOPMENT"  # Layer 07 (Section 10)
    for layer in layers[7:10]:
        assert layer["status"] == "NOT INITIALIZED"
