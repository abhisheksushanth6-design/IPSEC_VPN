"""Normalised packet model produced by the analyzer.

Plain dataclasses so the parser has no web-framework dependency; the API
layer converts these to Pydantic schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

ParseStatus = Literal["OK", "MALFORMED", "ERROR"]
DisplayProtocol = Literal["IKE", "ESP", "AH", "TCP", "UDP", "ICMP", "IP", "OTHER"]


@dataclass
class EthernetLayer:
    source_mac: str
    destination_mac: str
    ethertype: str
    vlan_id: Optional[int] = None


@dataclass
class IPLayer:
    version: int
    source: str
    destination: str
    protocol_number: int
    protocol_name: str
    total_length: int
    ttl: int
    header_length: Optional[int] = None
    identification: Optional[int] = None
    dont_fragment: Optional[bool] = None
    more_fragments: Optional[bool] = None
    fragment_offset: Optional[int] = None
    traffic_class: Optional[int] = None
    flow_label: Optional[int] = None
    extension_headers: list[str] = field(default_factory=list)


@dataclass
class TCPLayer:
    kind: Literal["TCP"]
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    flags: list[str]
    window: int
    header_length: int


@dataclass
class UDPLayer:
    kind: Literal["UDP"]
    source_port: int
    destination_port: int
    length: int
    checksum: int


@dataclass
class ICMPLayer:
    kind: Literal["ICMP"]
    type: int
    code: int
    checksum: int
    type_name: str


TransportLayer = TCPLayer | UDPLayer | ICMPLayer


@dataclass
class IKETransform:
    type_id: int
    type_name: str  # ENCR, PRF, INTEG, D-H, ESN
    transform_id: int
    transform_name: str
    key_length: Optional[int] = None


@dataclass
class IKEProposal:
    proposal_number: int
    protocol_id: int
    protocol_name: str  # IKE, ESP, AH
    spi: Optional[str] = None
    transforms: list[IKETransform] = field(default_factory=list)
    encryption_algorithms: list[str] = field(default_factory=list)
    integrity_algorithms: list[str] = field(default_factory=list)
    prf_algorithms: list[str] = field(default_factory=list)
    dh_groups: list[str] = field(default_factory=list)
    esn: Optional[str] = None
    # IKEv1 Phase 1 transforms carry these as cleartext attributes (RFC 2409 Appendix A).
    # IKEv2 never exposes them outside the encrypted SK payload, so they stay None.
    transform_number: Optional[int] = None
    auth_method: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    lifetime_kilobytes: Optional[int] = None


@dataclass
class IKEPayload:
    type_number: int
    name: str
    length: int
    critical: bool
    notify_type: Optional[int] = None
    notify_name: Optional[str] = None
    proposals: list[IKEProposal] = field(default_factory=list)
    # Key Exchange payload (IKEv2 type 34): the DH group is sent in cleartext
    # ahead of the public value, which lets it be cross-checked against the SA proposal.
    ke_dh_group: Optional[int] = None
    ke_dh_group_name: Optional[str] = None
    ke_data_length: Optional[int] = None


@dataclass
class IKELayer:
    version: str
    major_version: int
    minor_version: int
    exchange_type: int
    exchange_name: str
    initiator_spi: str
    responder_spi: str
    message_id: int
    flags: list[str] = field(default_factory=list)
    length: int = 0
    payloads: list[IKEPayload] = field(default_factory=list)
    payload_count: int = 0
    encrypted_payload: bool = False
    proposals: list[IKEProposal] = field(default_factory=list)



@dataclass
class ESPLayer:
    spi: str
    sequence_number: int
    payload_length: int
    encrypted: bool = True
    authentication_data: str = (
        "Not determinable: ICV length depends on the negotiated integrity algorithm."
    )


@dataclass
class AHLayer:
    next_header: int
    next_header_name: str
    payload_length: int
    spi: str
    sequence_number: int
    authentication_data: str
    icv_length: int


@dataclass
class IPsecAnalysis:
    type: Literal["IKE", "ESP", "AH"]
    nat_traversal: bool = False
    nat_traversal_note: Optional[str] = None
    udp_port: Optional[int] = None
    ike: Optional[IKELayer] = None
    esp: Optional[ESPLayer] = None
    ah: Optional[AHLayer] = None
    encapsulation_mode: Literal["TUNNEL", "TRANSPORT", "UNKNOWN"] = "TUNNEL"


@dataclass
class RawData:
    hex: str
    ascii: str
    length: int
    truncated: bool


@dataclass
class SecurityFlags:
    encrypted: bool = False
    authenticated: bool = False
    fragmented: bool = False
    nat_t: bool = False
    malformed: bool = False
    incomplete: bool = False


@dataclass
class PacketAnalysisResult:
    id: str
    number: int
    timestamp: str
    captured_length: int = 0
    original_length: int = 0
    source: str = ""
    destination: str = ""
    protocol: DisplayProtocol = "OTHER"
    length: int = 0
    info: str = ""
    layers: list[str] = field(default_factory=list)
    ethernet: Optional[EthernetLayer] = None
    ip: Optional[IPLayer] = None
    transport: Optional[TransportLayer] = None
    ipsec: Optional[IPsecAnalysis] = None
    raw: Optional[RawData] = None
    flags: SecurityFlags = field(default_factory=SecurityFlags)
    parse_status: ParseStatus = "OK"
    parse_error: Optional[str] = None
    parse_affected_protocol: Optional[str] = None


@dataclass
class CaptureMetadata:
    format: Literal["pcap", "pcapng"]
    link_type: int
    link_type_name: str
    packet_count: int
    truncated: bool = False


@dataclass
class IPsecStreamSummary:
    spi: str
    protocol: Literal["ESP", "AH"]
    source_ip: str
    destination_ip: str
    packet_count: int
    total_bytes: int
    min_sequence: int
    max_sequence: int
    sequence_gaps: int
    sequence_replays: int
    sequence_zero_count: int
    nat_traversal: bool = False
    encapsulation_mode: Literal["TUNNEL", "TRANSPORT", "UNKNOWN"] = "TUNNEL"


@dataclass
class TunnelEndpointSummary:
    local_endpoint: str
    remote_endpoint: str
    protocol: str  # ESP, AH, IKE, or MIXED
    ike_sa_count: int
    child_sa_spis: list[str] = field(default_factory=list)
    total_packets: int = 0
    total_bytes: int = 0
    encapsulation_mode: str = "TUNNEL"


@dataclass
class ProtocolAnomaly:
    id: str
    anomaly_type: str  # SEQ_REPLAY, SEQ_ZERO, SEQ_GAP_LARGE, WEAK_CRYPTO_PROPOSAL, CLEARTEXT_LEAK, etc.
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    packet_number: Optional[int]
    spi: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    description: str
    evidence: dict = field(default_factory=dict)


@dataclass
class ProtocolAnalysisReport:
    capture_id: Optional[str] = None
    total_packets_analyzed: int = 0
    ipsec_packets: int = 0
    ike_summary: dict = field(default_factory=dict)
    ipsec_streams: list[IPsecStreamSummary] = field(default_factory=list)
    tunnel_endpoints: list[TunnelEndpointSummary] = field(default_factory=list)
    anomalies: list[ProtocolAnomaly] = field(default_factory=list)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    analysis_timestamp: str = ""
    status: str = "READY"

