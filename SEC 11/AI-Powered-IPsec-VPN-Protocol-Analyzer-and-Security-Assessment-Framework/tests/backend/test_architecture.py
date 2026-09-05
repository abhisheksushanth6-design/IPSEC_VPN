"""The locked 14-layer architecture.

These tests pin the exact number, order, names and statuses. A rename,
reorder, merge or duplicate anywhere in the source of truth fails here.
"""

from __future__ import annotations

from app.core.architecture import ARCHITECTURE_LAYERS, LayerStatus, TOTAL_LAYERS, layer_by_number

LOCKED_SEQUENCE = [
    (1, "IPsec VPN Test Environment", LayerStatus.NOT_INITIALIZED),
    (2, "Packet Capture & Data Collection", LayerStatus.NOT_INITIALIZED),
    (3, "Packet & Protocol Analysis", LayerStatus.IN_DEVELOPMENT),
    (4, "Security State & SA Lifecycle Engine", LayerStatus.IN_DEVELOPMENT),
    (5, "Feature Extraction & Engineering", LayerStatus.IN_DEVELOPMENT),
    (6, "Session Fingerprinting & Baseline Profiling", LayerStatus.IN_DEVELOPMENT),
    (7, "Security Drift Detection", LayerStatus.IN_DEVELOPMENT),
    (8, "AI / ML Anomaly Detection Engine", LayerStatus.OPERATIONAL),
    (9, "Security Rule & Vulnerability Engine", LayerStatus.NOT_INITIALIZED),
    (10, "Risk Assessment & Decision Engine", LayerStatus.NOT_INITIALIZED),
    (11, "Security Databases (SQLite)", LayerStatus.FOUNDATION_CREATED),
    (12, "Backend & API (FastAPI)", LayerStatus.FOUNDATION_CREATED),
    (13, "Web Dashboard", LayerStatus.FOUNDATION_CREATED),
    (14, "Report Generation (PDF)", LayerStatus.FOUNDATION_READY),
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
    served = [(l["number"], l["name"], l["status"]) for l in payload["architecture_layers"]]
    assert served == [(n, name, status.value) for n, name, status in LOCKED_SEQUENCE]
    assert payload["initialized_layers"] == 10
