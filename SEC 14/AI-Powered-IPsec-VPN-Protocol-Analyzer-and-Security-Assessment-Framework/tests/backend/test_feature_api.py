"""Feature Extraction & Engineering API.

These drive the real HTTP surface end to end: upload a capture, discover
sessions and SAs, extract, read back, export and clear. Nothing is mocked, so
a change that breaks the wiring between the service and Layer 05 fails here.
"""

from __future__ import annotations

import packet_builders as B
import pytest

CAPTURE_FRAMES = [
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0), 500, 500), 17)),
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0, flags=0x20, r_spi=b"\x02" * 8), 500, 500), 17, src=B.DST4, dst=B.SRC4)),
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=35, message_id=1, payloads=[(46, b"\x00" * 32)]), 500, 500), 17)),
    B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=35, message_id=1, flags=0x20, r_spi=b"\x02" * 8, payloads=[(46, b"\x00" * 32)]), 500, 500), 17, src=B.DST4, dst=B.SRC4)),
    B.ethernet(B.ipv4(B.esp(spi=0xC0FFEE01, seq=1), 50)),
    B.ethernet(B.ipv4(B.esp(spi=0xDEADBE01, seq=1), 50, src=B.DST4, dst=B.SRC4)),
]


@pytest.fixture()
def loaded(client):
    """A capture with sessions and SAs discovered, features cleared."""
    client.delete("/api/features")
    client.post(
        "/api/packets/upload",
        files={"file": ("features.pcap", B.pcap(CAPTURE_FRAMES), "application/octet-stream")},
    )
    client.post("/api/sessions/discover")
    client.post("/api/sas/discover")
    client.delete("/api/features")
    yield client
    client.delete("/api/features")
    client.delete("/api/packets")


def first_entity(client, entity_type: str) -> str:
    items = client.get(f"/api/features/entities?entity_type={entity_type}").json()["items"]
    assert items, f"no {entity_type} entities discovered"
    return items[0]["entity_id"]


# ----- status ---------------------------------------------------------------


def test_status_is_not_initialized_without_a_capture(client) -> None:
    client.delete("/api/features")
    client.delete("/api/packets")
    body = client.get("/api/features/status").json()
    assert body["state"] == "NOT INITIALIZED"
    assert body["packets_available"] is False
    assert body["statistics"] is None
    assert body["feature_version"] == "1.0"


def test_status_is_ready_then_available(loaded) -> None:
    assert loaded.get("/api/features/status").json()["state"] == "READY"
    loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    )
    body = loaded.get("/api/features/status").json()
    assert body["state"] == "AVAILABLE"
    assert body["statistics"]["session_vectors"] == 1
    assert body["statistics"]["total_features"] > 0


def test_registry_is_served(client) -> None:
    definitions = client.get("/api/features/definitions").json()
    assert len(definitions) == client.get("/api/features/status").json()["registered_features"]
    sample = next(d for d in definitions if d["name"] == "packets_per_second")
    assert sample["unit"] == "packets/second"
    assert sample["formula"] == "packet_count / session_duration_seconds"
    assert sample["level"] == "SESSION"


# ----- entities -------------------------------------------------------------


def test_entities_list_real_sources(loaded) -> None:
    for entity_type in ("SESSION", "SA", "PACKET"):
        body = loaded.get(f"/api/features/entities?entity_type={entity_type}").json()
        assert body["source_available"] is True
        assert body["items"]
        assert all(item["extracted"] is False for item in body["items"])


def test_entities_report_absence_honestly(client) -> None:
    client.delete("/api/packets")
    body = client.get("/api/features/entities?entity_type=SESSION").json()
    assert body["source_available"] is False
    assert body["items"] == []
    assert "No capture is loaded" in body["detail"]


# ----- extraction -----------------------------------------------------------


def test_extract_session_returns_a_vector(loaded) -> None:
    response = loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "EXTRACTED"
    assert body["feature_version"] == "1.0"

    vector = body["feature_vector"]
    assert vector["entity_type"] == "SESSION"
    assert vector["feature_count"] == len(vector["features"])
    features = {f["name"]: f for f in vector["features"]}
    assert features["packet_count"]["value"] == 6
    assert features["ike_packet_count"]["value"] == 4
    assert features["esp_packet_count"]["value"] == 2
    assert features["packets_per_second"]["availability"] == "AVAILABLE"
    # Definitions are joined in for display.
    assert features["packet_count"]["display_name"] == "Packet Count"
    assert features["packet_count"]["unit"] == "packets"


def test_extract_sa_and_packet(loaded) -> None:
    for entity_type in ("SA", "PACKET"):
        response = loaded.post(
            "/api/features/extract",
            json={"entity_type": entity_type, "entity_id": first_entity(loaded, entity_type)},
        )
        assert response.status_code == 200
        vector = response.json()["feature_vector"]
        assert vector["entity_type"] == entity_type
        assert vector["features"]


def test_extraction_records_source_lineage(loaded) -> None:
    vector = loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    ).json()["feature_vector"]
    names = {s["name"]: s for s in vector["sources"]}
    assert names["Session record"]["available"] is True
    assert names["Session packets"]["available"] is True
    assert names["IKE observations"]["available"] is True


def test_normalized_values_are_absent(loaded) -> None:
    """Section 8 builds the normalization surface; it fits no parameters."""
    vector = loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    ).json()["feature_vector"]
    assert all(f["normalized_value"] is None for f in vector["features"])


def test_extraction_is_idempotent(loaded) -> None:
    entity_id = first_entity(loaded, "SESSION")
    body = {"entity_type": "SESSION", "entity_id": entity_id}
    first = loaded.post("/api/features/extract", json=body).json()["feature_vector"]
    second = loaded.post("/api/features/extract", json=body).json()["feature_vector"]
    assert first["id"] == second["id"]
    assert [(f["name"], f["value"]) for f in first["features"]] == [
        (f["name"], f["value"]) for f in second["features"]
    ]
    assert loaded.get("/api/features").json()["total"] == 1


def test_unknown_entity_is_rejected(loaded) -> None:
    response = loaded.post(
        "/api/features/extract", json={"entity_type": "SESSION", "entity_id": "SESSION-does-not-exist"}
    )
    assert response.status_code == 404
    assert response.json()["error"] == "ENTITY_NOT_FOUND"


def test_extraction_requires_packet_data(client) -> None:
    client.delete("/api/packets")
    response = client.post("/api/features/extract", json={"entity_type": "SESSION", "entity_id": "S1"})
    assert response.status_code == 409
    assert response.json()["error"] == "PACKET_DATA_UNAVAILABLE"


# ----- retrieval, export and clear ------------------------------------------


def test_vector_can_be_read_back(loaded) -> None:
    entity_id = first_entity(loaded, "SESSION")
    created = loaded.post(
        "/api/features/extract", json={"entity_type": "SESSION", "entity_id": entity_id}
    ).json()["feature_vector"]

    by_id = loaded.get(f"/api/features/{created['id']}").json()
    by_entity = loaded.get(f"/api/features/entity/SESSION/{entity_id}").json()
    assert by_id["id"] == by_entity["id"] == created["id"]
    # Values survive the round trip with their types intact.
    stored = {f["name"]: f["value"] for f in by_id["features"]}
    original = {f["name"]: f["value"] for f in created["features"]}
    assert stored == original
    assert isinstance(stored["packet_count"], int)
    assert isinstance(stored["ike_ratio"], float)
    assert isinstance(stored["nat_traversal_observed"], bool)


def test_missing_vector_is_reported(loaded) -> None:
    assert loaded.get("/api/features/FV-nope").status_code == 404
    assert loaded.get("/api/features/entity/SESSION/nope").status_code == 404


def test_export_json_and_csv(loaded) -> None:
    loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    )
    payload = loaded.get("/api/features/export?format=json").json()
    assert payload["feature_version"] == "1.0"
    assert len(payload["feature_vectors"]) == 1

    csv_response = loaded.get("/api/features/export?format=csv")
    assert csv_response.headers["content-type"].startswith("text/csv")
    lines = csv_response.text.strip().splitlines()
    assert lines[0].startswith("entity_type,entity_id")
    assert len(lines) > 1


def test_export_without_data_is_refused(loaded) -> None:
    response = loaded.get("/api/features/export?format=json")
    assert response.status_code == 409
    assert response.json()["error"] == "NO_FEATURE_DATA_AVAILABLE"


def test_clear_removes_vectors(loaded) -> None:
    loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    )
    assert loaded.get("/api/features").json()["total"] == 1
    body = loaded.delete("/api/features").json()
    assert body["state"] == "READY"
    assert loaded.get("/api/features").json()["total"] == 0


def test_no_future_intelligence_is_returned(loaded) -> None:
    """No baseline, drift, anomaly, vulnerability or risk anywhere in the payload."""
    vector = loaded.post(
        "/api/features/extract",
        json={"entity_type": "SESSION", "entity_id": first_entity(loaded, "SESSION")},
    ).json()["feature_vector"]
    text = str(vector).lower()
    for forbidden in ("baseline", "drift", "anomaly", "risk_score", "threat", "severity", "vulnerab"):
        assert forbidden not in text, forbidden
