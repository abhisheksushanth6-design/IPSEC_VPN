"""The locked 14-layer architecture.

These tests pin the exact number, order, names and statuses. A rename,
reorder, merge or duplicate anywhere in the source of truth fails here.
"""

from __future__ import annotations

from app.core.architecture import ARCHITECTURE_LAYERS, LayerStatus, TOTAL_LAYERS, layer_by_number

LOCKED_SEQUENCE = [
    (1, "IPsec VPN Test Environment", LayerStatus.OPERATIONAL),
    (2, "Packet Capture & Data Collection", LayerStatus.OPERATIONAL),
    (3, "Packet & Protocol Analysis", LayerStatus.OPERATIONAL),
    (4, "Security State & SA Lifecycle Engine", LayerStatus.OPERATIONAL),
    (5, "Feature Extraction & Engineering", LayerStatus.OPERATIONAL),
    (6, "Session Fingerprinting & Baseline Profiling", LayerStatus.OPERATIONAL),
    (7, "Security Drift Detection", LayerStatus.OPERATIONAL),
    (8, "AI / ML Anomaly Detection Engine", LayerStatus.OPERATIONAL),
    (9, "Security Rule & Vulnerability Engine", LayerStatus.OPERATIONAL),
    (10, "Risk Assessment & Decision Engine", LayerStatus.OPERATIONAL),
    (11, "Security Databases (SQLite)", LayerStatus.OPERATIONAL),
    (12, "Backend & API (FastAPI)", LayerStatus.OPERATIONAL),
    (13, "Web Dashboard", LayerStatus.OPERATIONAL),
    (14, "Report Generation (PDF)", LayerStatus.OPERATIONAL),
]


def test_exactly_fourteen_layers() -> None:
    assert TOTAL_LAYERS == 14
    assert len(ARCHITECTURE_LAYERS) == 14


def test_exact_sequence_names_and_statuses() -> None:
    actual = [(l.number, l.name, l.status) for l in ARCHITECTURE_LAYERS]
    assert actual == LOCKED_SEQUENCE


def test_numbers_are_contiguous_and_unique() -> None:
    assert [l.number for l in ARCHITECTURE_LAYERS] == list(range(1, 15))
    assert len({l.name for l in ARCHITECTURE_LAYERS}) == 14
    assert len({l.package for l in ARCHITECTURE_LAYERS}) == 14


def test_every_layer_has_a_description() -> None:
    for layer in ARCHITECTURE_LAYERS:
        assert layer.description.strip()


def test_layer_lookup() -> None:
    assert layer_by_number(8).name == "AI / ML Anomaly Detection Engine"


def test_api_serves_the_locked_sequence(client) -> None:
    payload = client.get("/api/system/status").json()
    served = [(l["number"], l["name"]) for l in payload["architecture_layers"]]
    assert served == [(n, name) for n, name, _ in LOCKED_SEQUENCE]
    layer_map = {l["number"]: l["status"] for l in payload["architecture_layers"]}
    assert layer_map[1] in ("READY", "WARNING", "ERROR", "NOT INITIALIZED")
    assert layer_map[2] in ("READY", "CAPTURING", "ERROR", "NOT INITIALIZED")
    assert layer_map[10] in ("READY", "OPERATIONAL", "NOT INITIALIZED")
    assert payload["total_layers"] == 14
