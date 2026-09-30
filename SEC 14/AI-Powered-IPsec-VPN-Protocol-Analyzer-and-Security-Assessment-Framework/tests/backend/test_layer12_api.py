"""Comprehensive test suite for Layer 12 — Backend & API (FastAPI).

Verifies:
- Application startup, lifespan, and FastAPI instance configuration.
- Total HTTP route inventory and coverage of all 21 prefix groups.
- OpenAPI schema generation, structure, and zero duplicate operation IDs.
- Health, system status, and environment endpoint contracts.
- Request validation, query/body rejection (422), and structured error envelopes.
- 404 handling on non-existent resources with structured error envelopes.
- Response serialization fidelity (JSON, ISO datetimes, float precision).
- Sensitive data protection (no leaked secrets, tokens, or traceback internals).
- CORS middleware configuration and preflight OPTIONS handling.
- WebSocket event route presence (/ws/events) and connection manager readiness.
- Multi-layer API endpoint availability across Layers 1–11.
- APILayerService telemetry, route registry, detailed health checks, and verify_layer.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from app.api.router import api_router
from app.core.config import get_settings
from app.layers.layer12_api.service import (
    EXPECTED_ROUTE_PREFIXES,
    APILayerService,
    get_api_layer_service,
)
from app.main import app
from app.websocket.manager import connection_manager


# =============================================================================
# 1. Application Startup, Lifespan & Configuration
# =============================================================================


class TestApplicationConfiguration:
    """Validates FastAPI application instance, lifespan, and metadata."""

    def test_fastapi_app_instance(self) -> None:
        """Verify FastAPI instance attributes and API metadata."""
        settings = get_settings()
        assert app is not None
        assert app.title == settings.project_name
        assert app.version == "1.0.0"
        assert app.docs_url == "/docs"
        assert app.redoc_url == "/redoc"
        assert app.openapi_url == "/openapi.json"

    def test_app_lifespan_state(self, client: TestClient) -> None:
        """Verify app runs and responds to basic requests without lifespan errors."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "operational"


# =============================================================================
# 2. Route Registry & 21 Prefix Groups Coverage
# =============================================================================


class TestRouteRegistry:
    """Validates aggregate route inventory and prefix coverage."""

    def test_total_route_count(self) -> None:
        """Verify that total registered HTTP routes exceed minimum threshold."""
        service = get_api_layer_service()
        inventory = service.get_route_inventory()
        assert len(inventory) >= 130, f"Expected >= 130 routes, found {len(inventory)}"

    def test_unique_paths_count(self) -> None:
        """Verify unique path count across the API router."""
        service = get_api_layer_service()
        stats = service.get_route_statistics()
        assert stats["unique_paths"] >= 120, f"Expected >= 120 unique paths, found {stats['unique_paths']}"

    def test_all_21_route_prefixes_mounted(self) -> None:
        """Verify that every one of the 21 expected route prefix groups is mounted."""
        service = get_api_layer_service()
        stats = service.get_route_statistics()
        missing = stats["missing_prefixes"]
        assert not missing, f"Missing prefix groups in API router: {missing}"
        assert len(stats["registered_prefixes"]) == len(EXPECTED_ROUTE_PREFIXES)

    def test_http_methods_diversity(self) -> None:
        """Verify that standard HTTP methods are represented across routes."""
        service = get_api_layer_service()
        stats = service.get_route_statistics()
        breakdown = stats["method_breakdown"]
        assert breakdown.get("GET", 0) >= 80, "Expected at least 80 GET routes"
        assert breakdown.get("POST", 0) >= 15, "Expected at least 15 POST routes"
        assert (breakdown.get("DELETE", 0) + breakdown.get("PATCH", 0)) >= 5, (
            "Expected at least 5 modifying routes (DELETE/PATCH)"
        )


# =============================================================================
# 3. OpenAPI Schema & Duplicate Operation ID Integrity
# =============================================================================


class TestOpenAPISchema:
    """Validates OpenAPI 3.x schema generation and uniqueness of operation IDs."""

    def test_openapi_generation(self) -> None:
        """Verify OpenAPI schema can be generated and is valid."""
        schema = app.openapi()
        assert isinstance(schema, dict)
        assert schema.get("openapi", "").startswith("3.")
        assert "paths" in schema
        assert "components" in schema

    def test_openapi_schema_metadata(self) -> None:
        """Verify OpenAPI schema metadata matches application settings."""
        settings = get_settings()
        schema = app.openapi()
        info = schema.get("info", {})
        assert info.get("title") == settings.project_name
        assert info.get("version") == "1.0.0"
        paths = schema.get("paths", {})
        assert len(paths) >= 120, f"Expected >= 120 documented paths, found {len(paths)}"

    def test_zero_duplicate_operation_ids(self) -> None:
        """Verify that every operationId across all paths and methods is unique."""
        schema = app.openapi()
        operation_ids: Dict[str, str] = {}
        duplicates: List[str] = []

        for path, path_item in schema.get("paths", {}).items():
            for method, operation in path_item.items():
                if method.lower() in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    if isinstance(operation, dict):
                        op_id = operation.get("operationId")
                        if op_id:
                            if op_id in operation_ids:
                                duplicates.append(f"{op_id} (used at {operation_ids[op_id]} and {method.upper()} {path})")
                            else:
                                operation_ids[op_id] = f"{method.upper()} {path}"

        assert not duplicates, f"Found duplicate OpenAPI operation IDs: {duplicates}"

    def test_components_schemas_present(self) -> None:
        """Verify components schemas are generated for data models."""
        schema = app.openapi()
        schemas = schema.get("components", {}).get("schemas", {})
        assert len(schemas) >= 80, f"Expected >= 80 component schemas, found {len(schemas)}"
        assert "HealthResponse" in schemas
        assert "SystemStatusResponse" in schemas


# =============================================================================
# 4. Health, System Status & Environment Endpoints
# =============================================================================


class TestCoreSystemEndpoints:
    """Validates core system health, status, and environment contracts."""

    def test_health_endpoint(self, client: TestClient) -> None:
        """Verify GET /api/health contract and layer statuses."""
        settings = get_settings()
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "operational"
        assert data.get("project") == settings.project_name

    def test_system_status_endpoint(self, client: TestClient) -> None:
        """Verify GET /api/system/status contract."""
        response = client.get("/api/system/status")
        assert response.status_code == 200
        data = response.json()
        assert data.get("backend_status").lower() == "operational"
        assert data.get("database_status") in {"CONNECTED", "CONNECTED (UNSEEDED)"}
        assert data.get("application_mode") == "STANDALONE"
        assert data.get("total_layers") == 14
        assert len(data.get("architecture_layers", [])) == 14

    def test_environment_status_endpoint(self, client: TestClient) -> None:
        """Verify GET /api/environment/status contract."""
        response = client.get("/api/environment/status")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)


# =============================================================================
# 5. Request Validation & Structured Error Envelopes
# =============================================================================


class TestRequestValidationAndErrors:
    """Validates Pydantic request validation and uniform error envelope contracts."""

    def test_validation_error_on_invalid_query_param(self, client: TestClient) -> None:
        """Verify 422 Unprocessable Entity with structured envelope on type error."""
        response = client.get("/api/packets?page=not_an_int")
        assert response.status_code == 422
        data = response.json()
        assert "error" in data
        assert data["error"] == "Request validation failed"
        assert "detail" in data
        assert isinstance(data["detail"], list)

    def test_validation_error_on_out_of_range_query_param(self, client: TestClient) -> None:
        """Verify 422 rejection when query parameter violates bounds."""
        response = client.get("/api/packets?page_size=-10")
        assert response.status_code == 422
        data = response.json()
        assert "error" in data
        assert data["error"] == "Request validation failed"

    def test_validation_error_on_invalid_json_body(self, client: TestClient) -> None:
        """Verify 422 rejection when required JSON body fields are missing or invalid."""
        response = client.post("/api/baselines", json={"invalid_field": "test"})
        assert response.status_code == 422
        data = response.json()
        assert "error" in data
        assert data["error"] == "Request validation failed"

    def test_not_found_on_unknown_session(self, client: TestClient) -> None:
        """Verify 404 response on unknown session ID with structured envelope."""
        random_id = str(uuid.uuid4())
        response = client.get(f"/api/sessions/{random_id}")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        err_str = (str(data.get("error", "")) + " " + str(data.get("message", ""))).lower()
        assert "not_found" in err_str or "not found" in err_str

    def test_not_found_on_unknown_packet(self, client: TestClient) -> None:
        """Verify 404 response on unknown packet ID with structured envelope."""
        random_id = str(uuid.uuid4())
        response = client.get(f"/api/packets/{random_id}")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        err_str = (str(data.get("error", "")) + " " + str(data.get("message", ""))).lower()
        assert "not_found" in err_str or "not found" in err_str

    def test_not_found_on_unknown_finding(self, client: TestClient) -> None:
        """Verify 404 response on unknown vulnerability finding ID with structured envelope."""
        random_id = str(uuid.uuid4())
        response = client.get(f"/api/vulnerabilities/findings/{random_id}")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        err_str = (str(data.get("error", "")) + " " + str(data.get("message", ""))).lower()
        assert "not_found" in err_str or "not found" in err_str


# =============================================================================
# 6. Response Serialization & Sensitive Data Protection
# =============================================================================


class TestResponseSerializationAndSecurity:
    """Validates serialization contracts and sensitive credential protection."""

    def test_json_content_type_header(self, client: TestClient) -> None:
        """Verify responses use application/json content type."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    def test_datetime_serialization_isoformat(self, client: TestClient) -> None:
        """Verify timestamp strings in responses follow ISO 8601 format."""
        response = client.get("/api/dashboard/summary")
        assert response.status_code == 200
        data = response.json()
        ts = data.get("posture", {}).get("last_refresh")
        assert ts is not None
        # Verify valid ISO 8601 format
        parsed_dt = datetime.fromisoformat(ts)
        assert parsed_dt is not None

    def test_no_sensitive_secrets_leaked_in_responses(self, client: TestClient) -> None:
        """Verify responses do not leak sensitive database URLs or credentials."""
        response = client.get("/api/system/status")
        assert response.status_code == 200
        raw_text = response.text.lower()
        assert "password=" not in raw_text
        assert "secret_key" not in raw_text
        assert "traceback" not in raw_text

    def test_cors_preflight_handling(self, client: TestClient) -> None:
        """Verify CORS preflight OPTIONS request returns appropriate headers."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert "GET" in response.headers.get("access-control-allow-methods", "")


# =============================================================================
# 7. WebSocket Event Transport
# =============================================================================


class TestWebSocketTransport:
    """Validates WebSocket route mounting and connection manager readiness."""

    def test_websocket_route_presence(self) -> None:
        """Verify /ws/events route is registered in the application."""
        ws_routes = [r for r in app.routes if getattr(r, "path", "") == "/ws/events"]
        assert len(ws_routes) >= 1, "WebSocket route /ws/events must be registered"

    def test_websocket_connection_manager_readiness(self) -> None:
        """Verify connection manager is instantiated and active."""
        assert connection_manager is not None
        assert hasattr(connection_manager, "connection_count")
        assert isinstance(connection_manager.connection_count, int)
        assert hasattr(connection_manager, "broadcast")
        assert hasattr(connection_manager, "connect")
        assert hasattr(connection_manager, "disconnect")


# =============================================================================
# 8. Multi-Layer Endpoint Contracts (Layers 1–11)
# =============================================================================


class TestMultiLayerRouteContracts:
    """Validates baseline HTTP contracts across all integrated pipeline layers."""

    def test_live_capture_endpoints(self, client: TestClient) -> None:
        """Verify Layer 2 live capture endpoints."""
        res_status = client.get("/api/live-capture/status")
        assert res_status.status_code == 200
        assert "state" in res_status.json()

        res_ifaces = client.get("/api/live-capture/interfaces")
        assert res_ifaces.status_code == 200
        assert "interfaces" in res_ifaces.json()
        assert isinstance(res_ifaces.json()["interfaces"], list)

    def test_packets_endpoints(self, client: TestClient) -> None:
        """Verify Layer 3 packet analysis endpoints."""
        res_status = client.get("/api/packets/status")
        assert res_status.status_code == 200

        res_pkts = client.get("/api/packets?page=1&page_size=5")
        assert res_pkts.status_code == 200
        data = res_pkts.json()
        assert "items" in data and isinstance(data["items"], list)

    def test_sessions_endpoints(self, client: TestClient) -> None:
        """Verify Layer 4 session correlation endpoints."""
        res_status = client.get("/api/sessions/status")
        assert res_status.status_code == 200

        res_sessions = client.get("/api/sessions?limit=5")
        assert res_sessions.status_code == 200
        data = res_sessions.json()
        assert "items" in data and isinstance(data["items"], list)

    def test_sas_endpoints(self, client: TestClient) -> None:
        """Verify Layer 5 SA lifecycle endpoints."""
        res_status = client.get("/api/sas/status")
        assert res_status.status_code == 200

        res_sas = client.get("/api/sas?limit=5")
        assert res_sas.status_code == 200
        data = res_sas.json()
        assert "items" in data and isinstance(data["items"], list)

    def test_features_endpoints(self, client: TestClient) -> None:
        """Verify Layer 7 feature extraction endpoints."""
        res_defs = client.get("/api/features/definitions")
        assert res_defs.status_code == 200
        assert isinstance(res_defs.json(), list)

        res_feats = client.get("/api/features?limit=5")
        assert res_feats.status_code == 200
        data = res_feats.json()
        assert "items" in data and isinstance(data["items"], list)

    def test_baselines_endpoints(self, client: TestClient) -> None:
        """Verify Layer 8 baseline profiling endpoints."""
        res_status = client.get("/api/baselines/status")
        assert res_status.status_code == 200

        res_baselines = client.get("/api/baselines?limit=5")
        assert res_baselines.status_code == 200
        assert isinstance(res_baselines.json(), list)

    def test_drift_endpoints(self, client: TestClient) -> None:
        """Verify Layer 8 behavioral drift endpoints."""
        res_status = client.get("/api/drift/status")
        assert res_status.status_code == 200

        res_drift = client.get("/api/drift?limit=5")
        assert res_drift.status_code == 200
        assert isinstance(res_drift.json(), list)

    def test_ml_anomaly_endpoints(self, client: TestClient) -> None:
        """Verify Layer 9 ML anomaly detection endpoints."""
        res_status = client.get("/api/ml/status")
        assert res_status.status_code == 200

        res_models = client.get("/api/ml/models")
        assert res_models.status_code == 200

        res_anomalies = client.get("/api/ml/anomalies?limit=5")
        assert res_anomalies.status_code == 200
        assert isinstance(res_anomalies.json(), list)

    def test_vulnerabilities_endpoints(self, client: TestClient) -> None:
        """Verify Layer 10 vulnerability rule & findings endpoints."""
        res_status = client.get("/api/vulnerabilities/status")
        assert res_status.status_code == 200

        res_rules = client.get("/api/vulnerabilities/rules")
        assert res_rules.status_code == 200
        assert isinstance(res_rules.json(), list)

        res_findings = client.get("/api/vulnerabilities/findings?limit=5")
        assert res_findings.status_code == 200
        assert isinstance(res_findings.json(), list)

    def test_risk_endpoints(self, client: TestClient) -> None:
        """Verify Layer 10 composite risk assessment endpoints."""
        res_status = client.get("/api/risk/status")
        assert res_status.status_code == 200

        res_summary = client.get("/api/risk/summary")
        assert res_summary.status_code == 200

        res_assessments = client.get("/api/risk/assessments?limit=5")
        assert res_assessments.status_code == 200
        assert isinstance(res_assessments.json(), list)

    def test_dashboard_endpoints(self, client: TestClient) -> None:
        """Verify dashboard aggregated endpoints."""
        res_summary = client.get("/api/dashboard/summary")
        assert res_summary.status_code == 200

        res_metrics = client.get("/api/dashboard/metrics")
        assert res_metrics.status_code == 200

        res_timeline = client.get("/api/dashboard/timeline?limit=5")
        assert res_timeline.status_code == 200

        res_protocols = client.get("/api/dashboard/protocols")
        assert res_protocols.status_code == 200

        res_sessions = client.get("/api/dashboard/sessions?limit=5")
        assert res_sessions.status_code == 200

    def test_reports_endpoints(self, client: TestClient) -> None:
        """Verify reports endpoints."""
        res_reports = client.get("/api/reports?limit=5")
        assert res_reports.status_code == 200
        assert isinstance(res_reports.json(), list)


# =============================================================================
# 9. APILayerService Telemetry & Verification
# =============================================================================


class TestAPILayerService:
    """Validates APILayerService methods, verification routines, and diagnostics."""

    def test_api_layer_service_singleton(self) -> None:
        """Verify get_api_layer_service returns a consistent singleton instance."""
        s1 = get_api_layer_service()
        s2 = get_api_layer_service()
        assert s1 is s2
        assert isinstance(s1, APILayerService)

    def test_service_route_inventory(self) -> None:
        """Verify inventory method returns structured route entries."""
        service = get_api_layer_service()
        inventory = service.get_route_inventory()
        assert len(inventory) >= 130
        for entry in inventory:
            assert "path" in entry
            assert "methods" in entry
            assert "name" in entry

    def test_service_detailed_health(self) -> None:
        """Verify detailed health diagnostic structure and operational status."""
        service = get_api_layer_service()
        health = service.get_detailed_health()
        assert health["status"] == "OPERATIONAL"
        assert health["total_endpoints"] >= 130
        assert health["missing_prefixes"] == []
        assert health["openapi_valid"] is True
        assert health["duplicate_operation_ids"] == []
        assert health["cors_configured"] is True
        assert health["websocket_ready"] is True
        assert health["latency_ms"] >= 0.0

    def test_service_verify_layer(self) -> None:
        """Verify verify_layer returns OPERATIONAL status on healthy application state."""
        service = get_api_layer_service()
        verification = service.verify_layer()
        assert isinstance(verification, dict)
        assert verification["status"] == "OPERATIONAL"
        assert verification["total_endpoints"] >= 130

    def test_service_get_layer_status(self) -> None:
        """Verify get_layer_status returns OPERATIONAL."""
        service = get_api_layer_service()
        assert service.get_layer_status() == "OPERATIONAL"
