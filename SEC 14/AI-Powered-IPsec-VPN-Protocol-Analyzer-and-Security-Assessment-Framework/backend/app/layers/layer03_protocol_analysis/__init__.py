"""Layer 03 — Packet & Protocol Analysis.

Status: IN DEVELOPMENT.

Decodes capture files (pcap, pcapng) into normalised packet analysis results:
link layer, IPv4/IPv6, TCP/UDP/ICMP, and the IPsec family — IKE (ISAKMP
header and payload chain), ESP, AH and NAT-T encapsulation.

The parsers work from the byte layouts in the relevant RFCs and never infer
a protocol from a port number alone. Encrypted ESP payloads are reported as
such; nothing is decrypted, and no security judgement is made here.
"""

LAYER_NUMBER = 3
LAYER_NAME = "Packet & Protocol Analysis"

from app.layers.layer03_protocol_analysis.analyzer import (  # noqa: E402
    analyze_capture,
    analyze_frame,
)
from app.layers.layer03_protocol_analysis.errors import CaptureFormatError  # noqa: E402
from app.layers.layer03_protocol_analysis.models import (  # noqa: E402
    IKEProposal,
    IKETransform,
    IPsecStreamSummary,
    ProtocolAnalysisReport,
    ProtocolAnomaly,
    TunnelEndpointSummary,
)
from app.layers.layer03_protocol_analysis.protocol_engine import (  # noqa: E402
    analyze_protocol_telemetry,
)
from app.layers.layer03_protocol_analysis.service import (  # noqa: E402
    ProtocolAnalysisService,
    get_protocol_analysis_service,
)

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "analyze_capture",
    "analyze_frame",
    "analyze_protocol_telemetry",
    "CaptureFormatError",
    "IKEProposal",
    "IKETransform",
    "IPsecStreamSummary",
    "TunnelEndpointSummary",
    "ProtocolAnomaly",
    "ProtocolAnalysisReport",
    "ProtocolAnalysisService",
    "get_protocol_analysis_service",
]

