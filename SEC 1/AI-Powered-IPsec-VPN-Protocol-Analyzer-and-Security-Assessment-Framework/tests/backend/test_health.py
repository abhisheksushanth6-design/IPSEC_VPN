"""GET /api/health."""

from __future__ import annotations


def test_health_returns_exact_contract(client) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {
        "project": (
            "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework"
        ),
        "status": "operational",
    }
