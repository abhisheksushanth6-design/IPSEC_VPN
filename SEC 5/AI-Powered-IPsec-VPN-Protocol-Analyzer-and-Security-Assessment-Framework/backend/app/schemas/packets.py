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


class IKEPayloadSchema(_Model):
    type_number: int
    name: str
    length: int
    critical: bool


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
