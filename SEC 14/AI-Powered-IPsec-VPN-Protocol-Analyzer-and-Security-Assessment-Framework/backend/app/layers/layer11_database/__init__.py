"""Layer 11 — Security Databases (SQLite).

Authoritative layer package for persisting, validating, and querying
structured IPsec configuration, analysis, security findings, baselines,
drift records, and ML model metadata in SQLite.
"""

from app.layers.layer11_database.service import (
    EXPECTED_CORE_TABLES,
    DatabaseLayerService,
    atomic_transaction,
    get_database_layer_service,
)

LAYER_NUMBER = 11
LAYER_NAME = "Security Databases (SQLite)"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "DatabaseLayerService",
    "get_database_layer_service",
    "atomic_transaction",
    "EXPECTED_CORE_TABLES",
]
