"""Layer 12 — Backend & API (FastAPI).

Authoritative layer package for mounting, documenting, securing, and routing
FastAPI REST endpoints and WebSocket event connections for the IPsec framework.
"""

from app.layers.layer12_api.service import (
    APILayerService,
    get_api_layer_service,
)

LAYER_NUMBER = 12
LAYER_NAME = "Backend & API (FastAPI)"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "APILayerService",
    "get_api_layer_service",
]
