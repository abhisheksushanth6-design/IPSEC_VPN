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
        status=LayerStatus.OPERATIONAL,
        description=(
            "Provides a controlled environment for generating, testing, and validating IPsec VPN behavior "
            "across Tunnel/Transport modes, AES ciphers, DH groups, PFS configurations, and traffic profiles."
        ),
    ),
    ArchitectureLayer(
        number=2,
        name="Packet Capture & Data Collection",
        package="layer02_packet_capture",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Collects network traffic and IPsec-related packets (IKE negotiation, ESP, AH, and cleartext) "
            "from live hypervisor network interfaces and captured PCAP/PCAPNG streams for downstream analysis."
        ),
    ),
    ArchitectureLayer(
        number=3,
        name="Packet & Protocol Analysis",
        package="layer03_protocol_analysis",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Examines packet structures, network headers, IKE exchanges, and IPsec protocol information. "
            "Decodes IPv4/IPv6, TCP/UDP/ICMP, IKEv1/v2, ESP, AH, Tunnel/Transport modes, and cryptographic transforms."
        ),
    ),
    ArchitectureLayer(
        number=4,
        name="Security Association & Protocol State Analysis",
        package="layer04_sa_lifecycle",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Analyzes Security Association characteristics, parameters, protocol state, SA lifetimes, "
            "rekey transitions, and control-plane correlation between IKE and Child SAs."
        ),
    ),
    ArchitectureLayer(
        number=5,
        name="Feature Extraction & Engineering",
        package="layer05_feature_engineering",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Transforms protocol and session observations into structured feature vectors for security analysis, "
            "extracting timing, sizing, frequency, directionality, header, and SA-related statistical characteristics."
        ),
    ),
    ArchitectureLayer(
        number=6,
        name="IPsec Session Fingerprinting",
        package="layer06_session_fingerprinting",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Constructs compact, deterministic behavioral session fingerprints from observable flow characteristics "
            "(packet sizes, timing, bursts, directionality, and metadata) without payload decryption."
        ),
    ),
    ArchitectureLayer(
        number=7,
        name="AI-Based Protocol & Traffic Classification",
        package="layer08_ai_ml",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Performs multi-criteria AI identification of IPsec protocols, IKE versions, VPN modes (Tunnel/Transport), "
            "cryptographic configurations, and classifies encrypted ESP payloads (VoIP, Web browsing, Email, ICMP, "
            "Video streaming, Other) with calibrated confidence scores."
        ),
    ),
    ArchitectureLayer(
        number=8,
        name="Security Assessment Engine",
        package="layer09_vulnerability_engine",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Evaluates cryptographic strength, configuration compliance, SA parameters, key lifetime, "
            "replay protection, forward secrecy (PFS), cipher suite strength, and 5-vector metadata exposure."
        ),
    ),
    ArchitectureLayer(
        number=9,
        name="Risk Assessment & Decision Engine",
        package="layer10_risk_engine",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Computes overall security and risk scores, correlates findings with MITRE ATT&CK and NIST SP 800-77 "
            "threat matrix entries, and provides explainable evidence and actionable recommendations."
        ),
    ),
    ArchitectureLayer(
        number=10,
        name="Dashboard & Report Generation",
        package="layer14_reports",
        status=LayerStatus.OPERATIONAL,
        description=(
            "Presents interactive analyst dashboards and generates auditable Executive and Technical "
            "PDF security assessment reports distinguishing observed, inferred, predicted, and unavailable data."
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
