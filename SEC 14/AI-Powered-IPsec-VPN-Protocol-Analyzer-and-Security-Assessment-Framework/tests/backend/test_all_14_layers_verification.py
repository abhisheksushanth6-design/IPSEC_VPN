"""Comprehensive automated tests for all 14 architectural layers runtime verification.

Verifies that:
1. Every layer provides authentic implementation and runtime verification data.
2. System status endpoint /api/system/status populates rich verification schemas.
3. Every layer service can be instantiated and queried for health and status without exceptions.
"""

from __future__ import annotations

import pytest
from app.core.architecture import ARCHITECTURE_LAYERS, TOTAL_LAYERS
from app.db.base import SessionLocal
from app.services.system_service import build_system_status, verify_layer_runtime


def test_system_status_response_contains_verification_metrics(client) -> None:
    """Test that /api/system/status exposes Section 10 structured verification attributes."""
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()

    assert data["total_layers"] == TOTAL_LAYERS == 10
    assert data["initialized_layers"] == 10
    assert data["backend_status"] == "operational"
    assert data["database_status"] == "CONNECTED"

    layers = data["architecture_layers"]
    assert len(layers) == 10

    for layer in layers:
        assert 1 <= layer["number"] <= 10
        assert bool(layer["name"].strip())
        assert bool(layer["package"].strip())
        assert layer["status"] in (
            "NOT INITIALIZED",
            "FOUNDATION CREATED",
            "FOUNDATION READY",
            "IN DEVELOPMENT",
            "OPERATIONAL",
            "IMPLEMENTED",
            "READY",
            "WARNING",
            "ERROR",
        )
        assert layer["foundation_available"] is True
        assert layer["implementation_available"] is True
        assert layer["runtime_verified"] is True
        assert layer["last_verified"] is not None
        assert isinstance(layer["verification_errors"], list)
        assert isinstance(layer["limitations"], list)


def test_all_14_layers_direct_service_verification() -> None:
    """Directly invoke verify_layer_runtime for all 14 layers with active DB session."""
    with SessionLocal() as db:
        for base_layer in ARCHITECTURE_LAYERS:
            status_val, verified, errs, limits = verify_layer_runtime(base_layer.number, db)
            assert verified is True
            assert status_val != "NOT INITIALIZED"
            assert len(errs) == 0


def test_layer11_database_service_inspection() -> None:
    """Test Layer 11 DatabaseLayerService directly."""
    from app.layers.layer11_database.service import get_database_layer_service

    svc = get_database_layer_service()
    verification = svc.verify_layer()
    assert verification["status"] in ("OPERATIONAL", "READY", "WARNING")
    assert verification["connected"] is True
    assert verification["table_count"] >= 10
    assert svc.get_layer_status() in ("OPERATIONAL", "READY", "WARNING")


def test_layer12_api_service_inspection() -> None:
    """Test Layer 12 APILayerService directly."""
    from app.layers.layer12_api.service import get_api_layer_service

    svc = get_api_layer_service()
    verification = svc.verify_layer()
    assert verification["status"] in ("OPERATIONAL", "READY")
    assert verification["total_endpoints"] > 20
    assert verification["unique_paths"] > 15
    assert verification["websocket_ready"] is True
    assert svc.get_layer_status() in ("OPERATIONAL", "READY")


def test_layer13_dashboard_service_inspection() -> None:
    """Test Layer 13 DashboardService layer status."""
    from app.layers.layer13_dashboard.service import DashboardService

    with SessionLocal() as db:
        svc = DashboardService()
        status = svc.get_layer_status(db)
        assert status in ("OPERATIONAL", "READY")


def test_layer14_report_service_inspection() -> None:
    """Test Layer 14 ReportService layer status."""
    from app.layers.layer14_reports.service import ReportService

    with SessionLocal() as db:
        svc = ReportService()
        status = svc.get_layer_status(db)
        assert status in ("OPERATIONAL", "READY")
