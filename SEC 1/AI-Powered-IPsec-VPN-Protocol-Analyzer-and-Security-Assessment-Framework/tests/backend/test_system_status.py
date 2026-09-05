"""GET /api/system/status."""

from __future__ import annotations

from app.core.architecture import ARCHITECTURE_LAYERS


def test_status_reports_required_fields(client) -> None:
    payload = client.get("/api/system/status").json()
    for field in (
        "backend_status",
        "database_status",
        "application_mode",
        "architecture_layers",
    ):
        assert field in payload


def test_status_reflects_real_state(client) -> None:
    payload = client.get("/api/system/status").json()
    assert payload["backend_status"] == "operational"
    assert payload["database_status"] == "CONNECTED"
    assert payload["application_mode"] == "DEMO"


def test_all_fourteen_layers_are_reported(client) -> None:
    payload = client.get("/api/system/status").json()
    layers = payload["architecture_layers"]
    assert payload["total_layers"] == 14
    assert len(layers) == 14
    assert [layer["number"] for layer in layers] == list(range(1, 15))
    assert [layer["name"] for layer in layers] == [
        layer.name for layer in ARCHITECTURE_LAYERS
    ]


def test_analysis_layers_are_not_initialized(client) -> None:
    layers = client.get("/api/system/status").json()["architecture_layers"]
    for layer in layers:
        if layer["number"] <= 10:
            assert layer["status"] == "NOT INITIALIZED"
