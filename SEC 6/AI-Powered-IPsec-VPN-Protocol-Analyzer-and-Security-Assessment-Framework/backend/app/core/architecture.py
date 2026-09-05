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
    IN_DEVELOPMENT = "IN DEVELOPMENT"
    OPERATIONAL = "OPERATIONAL"
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
            "Provides a controlled environment for generating, testing, and validating IPsec VPN behavior."
        ),
    ),
    ArchitectureLayer(
        number=2,
        name="Packet Capture & Data Collection",
        package="layer02_packet_capture",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Collects network traffic and IPsec-related packets for downstream analysis."
        ),
    ),
    ArchitectureLayer(
        number=3,
        name="Packet & Protocol Analysis",
        package="layer03_protocol_analysis",
        status=LayerStatus.IN_DEVELOPMENT,
        description=(
            "Examines packet structures, network headers, IKE exchanges, and IPsec protocol information. "
            "Decodes pcap/pcapng captures: IPv4/IPv6, TCP/UDP/ICMP, IKE, ESP, AH and NAT-T."
        ),
    ),
    ArchitectureLayer(
        number=4,
        name="Security State & SA Lifecycle Engine",
        package="layer04_sa_lifecycle",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Tracks Security Associations and their lifecycle states across VPN sessions."
        ),
    ),
    ArchitectureLayer(
        number=5,
        name="Feature Extraction & Engineering",
        package="layer05_feature_engineering",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Transforms protocol and session observations into structured features for security analysis."
        ),
    ),
    ArchitectureLayer(
        number=6,
        name="Session Fingerprinting & Baseline Profiling",
        package="layer06_session_fingerprinting",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Builds behavioral profiles of expected VPN session and protocol characteristics."
        ),
    ),
    ArchitectureLayer(
        number=7,
        name="Security Drift Detection",
        package="layer07_drift_detection",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Identifies deviations between observed behavior and established security baselines."
        ),
    ),
    ArchitectureLayer(
        number=8,
        name="AI / ML Anomaly Detection Engine",
        package="layer08_ai_ml",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Uses machine-learning techniques to identify potentially abnormal VPN behavior."
        ),
    ),
    ArchitectureLayer(
        number=9,
        name="Security Rule & Vulnerability Engine",
        package="layer09_vulnerability_engine",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Evaluates observations against security rules and vulnerability-detection logic."
        ),
    ),
    ArchitectureLayer(
        number=10,
        name="Risk Assessment & Decision Engine",
        package="layer10_risk_engine",
        status=LayerStatus.NOT_INITIALIZED,
        description=(
            "Combines security findings into an overall risk assessment and decision context."
        ),
    ),
    ArchitectureLayer(
        number=11,
        name="Security Databases (SQLite)",
        package="layer11_database",
        status=LayerStatus.FOUNDATION_CREATED,
        description=(
            "Stores structured configuration, analysis, security findings, and system information."
        ),
    ),
    ArchitectureLayer(
        number=12,
        name="Backend & API (FastAPI)",
        package="layer12_api",
        status=LayerStatus.FOUNDATION_CREATED,
        description=(
            "Provides the application backend, API services, business logic, and integration layer."
        ),
    ),
    ArchitectureLayer(
        number=13,
        name="Web Dashboard",
        package="layer13_dashboard",
        status=LayerStatus.FOUNDATION_CREATED,
        description=(
            "Provides the analyst-facing interface for monitoring, analysis, visualization, and security assessment."
        ),
    ),
    ArchitectureLayer(
        number=14,
        name="Report Generation (PDF)",
        package="layer14_reports",
        status=LayerStatus.FOUNDATION_READY,
        description=(
            "Generates structured security assessment reports for analysis results and findings."
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
