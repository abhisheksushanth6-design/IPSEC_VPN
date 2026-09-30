"""Pydantic schemas for the packet-analysis API.

Mirror the Layer 03 dataclasses; built with `from_attributes` so the service
can hand dataclass instances straight to the response models.
"""

from __future__ import annotations

from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EthernetLayerSchema(_Model):
    source_mac: str
    destination_mac: str
    ethertype: str
    vlan_id: Optional[int] = None


class IPLayerSchema(_Model):
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
    extension_headers: list[str] = []


class TCPLayerSchema(_Model):
    kind: Literal["TCP"]
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    flags: list[str]
    window: int
    header_length: int


class UDPLayerSchema(_Model):
    kind: Literal["UDP"]
    source_port: int
    destination_port: int
    length: int
    checksum: int


class ICMPLayerSchema(_Model):
    kind: Literal["ICMP"]
    type: int
    code: int
    checksum: int
    type_name: str


TransportSchema = Union[TCPLayerSchema, UDPLayerSchema, ICMPLayerSchema]


class IKETransformSchema(_Model):
    type_id: int
    type_name: str
    transform_id: int
    transform_name: str
    key_length: Optional[int] = None


class IKEProposalSchema(_Model):
    proposal_number: int
    protocol_id: int
    protocol_name: str
    spi: Optional[str] = None
    transforms: list[IKETransformSchema] = []
    encryption_algorithms: list[str] = []
    integrity_algorithms: list[str] = []
    prf_algorithms: list[str] = []
    dh_groups: list[str] = []
    esn: Optional[str] = None
    transform_number: Optional[int] = None
    auth_method: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    lifetime_kilobytes: Optional[int] = None


class IKEPayloadSchema(_Model):
    type_number: int
    name: str
    length: int
    critical: bool
    notify_type: Optional[int] = None
    notify_name: Optional[str] = None
    proposals: list[IKEProposalSchema] = []
    ke_dh_group: Optional[int] = None
    ke_dh_group_name: Optional[str] = None
    ke_data_length: Optional[int] = None


class IKELayerSchema(_Model):
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
    payloads: list[IKEPayloadSchema]
    payload_count: int
    encrypted_payload: bool
    proposals: list[IKEProposalSchema] = []



class ESPLayerSchema(_Model):
    spi: str
    sequence_number: int
    payload_length: int
    encrypted: bool
    authentication_data: str


class AHLayerSchema(_Model):
    next_header: int
    next_header_name: str
    payload_length: int
    spi: str
    sequence_number: int
    authentication_data: str
    icv_length: int


class IPsecAnalysisSchema(_Model):
    type: Literal["IKE", "ESP", "AH"]
    nat_traversal: bool
    nat_traversal_note: Optional[str] = None
    udp_port: Optional[int] = None
    ike: Optional[IKELayerSchema] = None
    esp: Optional[ESPLayerSchema] = None
    ah: Optional[AHLayerSchema] = None
    encapsulation_mode: str = "TUNNEL"


class RawDataSchema(_Model):
    hex: str
    ascii: str
    length: int
    truncated: bool


class SecurityFlagsSchema(_Model):
    encrypted: bool
    authenticated: bool
    fragmented: bool
    nat_t: bool
    malformed: bool
    incomplete: bool


class PacketSummarySchema(_Model):
    id: str
    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    parse_status: str
    ipsec_type: Optional[str] = None
    nat_traversal: bool = False
    spi: Optional[str] = None


class PacketAnalysisResultSchema(_Model):
    id: str
    number: int
    timestamp: str
    captured_length: int
    original_length: int
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    layers: list[str]
    ethernet: Optional[EthernetLayerSchema] = None
    ip: Optional[IPLayerSchema] = None
    transport: Optional[TransportSchema] = Field(default=None, discriminator="kind")
    ipsec: Optional[IPsecAnalysisSchema] = None
    raw: Optional[RawDataSchema] = None
    flags: SecurityFlagsSchema
    parse_status: str
    parse_error: Optional[str] = None
    parse_affected_protocol: Optional[str] = None


class ProtocolCountsSchema(BaseModel):
    IKE: int = 0
    ESP: int = 0
    AH: int = 0
    TCP: int = 0
    UDP: int = 0
    ICMP: int = 0
    OTHER: int = 0


class PacketStatisticsSchema(BaseModel):
    total_packets: int
    ipsec_packets: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    malformed_packets: int


class CaptureMetadataSchema(_Model):
    format: str
    link_type: int
    link_type_name: str
    packet_count: int
    truncated: bool
    filename: Optional[str] = None
    loaded_at: Optional[str] = None


AnalysisState = Literal["NOT INITIALIZED", "READY", "ANALYZING", "COMPLETED", "ERROR"]


class AnalysisStatusSchema(BaseModel):
    state: AnalysisState
    analyzer_available: bool = True
    supported_formats: list[str]
    max_upload_bytes: int
    max_packets: int
    capture: Optional[CaptureMetadataSchema] = None
    statistics: Optional[PacketStatisticsSchema] = None
    protocol_counts: Optional[ProtocolCountsSchema] = None
    last_error: Optional[str] = None


class PacketPageSchema(BaseModel):
    items: list[PacketSummarySchema]
    page: int
    page_size: int
    total: int
    total_pages: int


class PacketErrorSchema(BaseModel):
    error: str
    message: str


class IPsecStreamSummarySchema(_Model):
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
    encapsulation_mode: str = "TUNNEL"


class TunnelEndpointSummarySchema(_Model):
    local_endpoint: str
    remote_endpoint: str
    protocol: str
    ike_sa_count: int
    child_sa_spis: list[str] = []
    total_packets: int = 0
    total_bytes: int = 0
    encapsulation_mode: str = "TUNNEL"


class ProtocolAnomalySchema(_Model):
    id: str
    anomaly_type: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    packet_number: Optional[int] = None
    spi: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    description: str
    evidence: dict = {}


class IKENegotiationAnalysisSchema(BaseModel):
    total_ike_messages: int = 0
    exchanges: list[dict] = []
    proposals: list[dict] = []
    initiator_spis: list[str] = []
    responder_spis: list[str] = []


class ProtocolAnalysisReportSchema(BaseModel):
    capture_id: Optional[str] = None
    total_packets_analyzed: int = 0
    ipsec_packets: int = 0
    ike_summary: IKENegotiationAnalysisSchema
    ipsec_streams: list[IPsecStreamSummarySchema] = []
    tunnel_endpoints: list[TunnelEndpointSummarySchema] = []
    anomalies: list[ProtocolAnomalySchema] = []
    protocol_counts: dict[str, int] = {}
    analysis_timestamp: str
    status: str = "READY"

