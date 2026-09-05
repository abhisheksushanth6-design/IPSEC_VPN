"""Authoritative definition of the locked 14-layer architecture.

This module is the single source of truth for layer numbers, names, package
directories and status. Nothing else in the codebase should re-declare the
layer names — import from here instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LayerStatus(str, Enum):
    """Implementation status of an architecture layer."""

    NOT_INITIALIZED = "NOT INITIALIZED"
    FOUNDATION_CREATED = "FOUNDATION CREATED"
    FOUNDATION_READY = "FOUNDATION READY"
    IMPLEMENTED = "IMPLEMENTED"


@dataclass(frozen=True)
class ArchitectureLayer:
    """A single layer of the locked architecture."""

    number: int
    name: str
    package: str
    status: LayerStatus
    description: str


ARCHITECTURE_LAYERS: tuple[ArchitectureLayer, ...] = (
    ArchitectureLayer(
        number=1,
        name="IPsec VPN Test Environment",
        package="layer01_test_environment",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Controlled IPsec tunnel environment used to generate traffic for "
            "analysis. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=2,
        name="Packet Capture & Data Collection",
        package="layer02_packet_capture",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Capture pipeline that collects raw traffic from the test "
            "environment. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=3,
        name="Packet & Protocol Analysis",
        package="layer03_protocol_analysis",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Decoding and inspection of IKE, ESP and AH protocol structures. "
            "Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=4,
        name="Security State & SA Lifecycle Engine",
        package="layer04_sa_lifecycle",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Tracks Security Association negotiation, rekey and teardown "
            "state. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=5,
        name="Feature Extraction & Engineering",
        package="layer05_feature_engineering",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Derives numerical and categorical features from analysed "
            "sessions. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=6,
        name="Session Fingerprinting & Baseline Profiling",
        package="layer06_session_fingerprinting",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Builds per-session fingerprints and learns normal-behaviour "
            "baselines. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=7,
        name="Security Drift Detection",
        package="layer07_drift_detection",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Compares live sessions against learned baselines to surface "
            "configuration drift. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=8,
        name="AI / ML Anomaly Detection Engine",
        package="layer08_ai_ml",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Machine-learning models that score sessions for anomalous "
            "behaviour. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=9,
        name="Security Rule & Vulnerability Engine",
        package="layer09_vulnerability_engine",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Deterministic rule evaluation for known IPsec weaknesses. "
            "Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=10,
        name="Risk Assessment & Decision Engine",
        package="layer10_risk_engine",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Aggregates findings into prioritised risk and remediation "
            "decisions. Not implemented."
        ),
    ),
    ArchitectureLayer(
        number=11,
        name="Security Databases (SQLite)",
        package="layer11_database",
        status=LayerStatus.FOUNDATION_CREATED,
        description=(
            "SQLite persistence layer. Engine, session factory and the "
            "system_settings table exist; security tables do not."
        ),
    ),
    ArchitectureLayer(
        number=12,
        name="Backend & API (FastAPI)",
        package="layer12_api",
        status=LayerStatus.FOUNDATION_CREATED,
        description=(
            "FastAPI application with configuration, CORS, error handling, "
            "health and system status endpoints."
        ),
    ),
    ArchitectureLayer(
        number=13,
        name="Web Dashboard",
        package="layer13_dashboard",
        status=LayerStatus.FOUNDATION_READY,
        description=(
            "React application shell with routing, theming and an API service "
            "layer. Dashboard views are not built."
        ),
    ),
    ArchitectureLayer(
        number=14,
        name="Report Generation (PDF)",
        package="layer14_reports",
        status=LayerStatus.FOUNDATION_READY,
        description=(
            "Placeholder package for the future ReportLab PDF pipeline. No "
            "report generation exists."
        ),
    ),
)

TOTAL_LAYERS = len(ARCHITECTURE_LAYERS)


def layer_by_number(number: int) -> ArchitectureLayer:
    """Return a single layer by its number, or raise KeyError."""
    for layer in ARCHITECTURE_LAYERS:
        if layer.number == number:
            return layer
    raise KeyError(f"No architecture layer numbered {number}")
