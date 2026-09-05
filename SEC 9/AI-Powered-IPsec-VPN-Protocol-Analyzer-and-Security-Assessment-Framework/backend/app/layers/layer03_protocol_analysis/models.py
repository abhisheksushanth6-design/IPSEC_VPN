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
class IKEPayload:
    type_number: int
    name: str
    length: int
    critical: bool


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
    flags: list[str]
    length: int
    payloads: list[IKEPayload]
    payload_count: int
    encrypted_payload: bool


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
    nat_traversal: bool
    nat_traversal_note: Optional[str] = None
    udp_port: Optional[int] = None
    ike: Optional[IKELayer] = None
    esp: Optional[ESPLayer] = None
    ah: Optional[AHLayer] = None


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
    captured_length: int
    original_length: int
    source: str
    destination: str
    protocol: DisplayProtocol
    length: int
    info: str
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
