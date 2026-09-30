"""Pydantic schemas for Layer 02 — Packet Capture & Data Collection."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class CaptureSourceInterface(BaseModel):
    """An available capture source (VM and NIC) discovered from VirtualBox."""
    vm_name: str = Field(..., description="Virtual machine name")
    vm_uuid: str = Field(..., description="Virtual machine UUID")
    vm_state: str = Field(..., description="VM execution state (running, poweroff, etc.)")
    role: str = Field(..., description="Configured role (client, server, analyzer, other)")
    nic_number: int = Field(..., description="1-indexed NIC interface number on the VM")
    nic_type: str = Field(..., description="Attachment type (hostonly, nat, etc.)")
    adapter_name: Optional[str] = Field(default=None, description="Host adapter or network name")
    mac_address: Optional[str] = Field(default=None, description="MAC address for this NIC")
    is_recommended: bool = Field(default=False, description="Whether this is the recommended IPsec capture source")


class LiveCaptureInterfacesResponse(BaseModel):
    """Response for GET /api/live-capture/interfaces."""
    interfaces: list[CaptureSourceInterface] = Field(default_factory=list, description="Available capture interfaces")
    default_vm: Optional[str] = Field(default=None, description="Recommended default VM name")
    default_nic: Optional[int] = Field(default=None, description="Recommended default NIC number")


class StartCaptureRequest(BaseModel):
    """Request payload for POST /api/live-capture/start."""
    vm: str = Field(..., description="Target VM name or UUID")
    nic: Optional[int] = Field(default=None, description="Optional target NIC number (defaults to host-only NIC)")


class ScapyPacketSummary(BaseModel):
    """Telemetry for an individual packet parsed by Scapy in Layer 02."""
    packet_number: int = Field(..., description="1-indexed sequence number in the capture")
    timestamp: float = Field(..., description="Epoch timestamp of packet capture")
    source_ip: str = Field(..., description="Source IPv4 or IPv6 address")
    destination_ip: str = Field(..., description="Destination IPv4 or IPv6 address")
    protocol: str = Field(..., description="Detected protocol (IKE, ESP, AH, TCP, UDP, ICMP, ICMPv6, OTHER)")
    source_port: Optional[int] = Field(default=None, description="Transport layer source port")
    destination_port: Optional[int] = Field(default=None, description="Transport layer destination port")
    length: int = Field(..., description="Packet length in bytes")
    summary: str = Field(default="", description="Scapy summary description of the packet")
    is_ipsec: bool = Field(default=False, description="Whether this packet belongs to IPsec (IKE, ESP, AH)")


class LiveCaptureStatusResponse(BaseModel):
    """Status of the live packet capture engine (GET /api/live-capture/status)."""
    state: str = Field(..., description="Current capture state (IDLE, STARTING, CAPTURING, STOPPING, INGESTING, COMPLETED, ERROR)")
    capture_id: Optional[str] = Field(default=None, description="Current capture session identifier")
    source_vm: Optional[str] = Field(default=None, description="Source VM being captured")
    nic_number: Optional[int] = Field(default=None, description="Source NIC number")
    output_file: Optional[str] = Field(default=None, description="Destination PCAP file path")
    started_at: Optional[str] = Field(default=None, description="ISO timestamp when capture started")
    elapsed_seconds: float = Field(default=0.0, description="Elapsed duration in seconds")
    packet_count: int = Field(default=0, description="Real count of packets captured")
    file_size_bytes: int = Field(default=0, description="Real PCAP file size in bytes")
    recent_packets: list[ScapyPacketSummary] = Field(default_factory=list, description="Recent captured packets from live buffer")
    error: Optional[str] = Field(default=None, description="Error message if capture or ingestion failed")


class StopCaptureResponse(BaseModel):
    """Response for POST /api/live-capture/stop."""
    capture_id: str = Field(..., description="Unique capture identifier")
    pcap_path: str = Field(..., description="Path to the finalized PCAP file")
    packet_count: int = Field(..., description="Total packets captured and verified")
    file_size_bytes: int = Field(..., description="Final PCAP file size in bytes")
    ingestion_status: str = Field(..., description="Layer 03 ingestion status (COMPLETED, ERROR)")
    analysis_id: Optional[str] = Field(default=None, description="Layer 03 analysis / SHA-256 capture ID")
    sessions_discovered: int = Field(default=0, description="Number of IPsec sessions discovered from this capture")
    error: Optional[str] = Field(default=None, description="Error detail if stop or ingestion failed")


class CaptureConversationSummary(BaseModel):
    """Aggregated conversation pair between two IP endpoints."""
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    packet_count: int = Field(..., description="Total packets exchanged")
    total_bytes: int = Field(..., description="Total payload bytes")
    protocols: list[str] = Field(default_factory=list, description="Unique protocols observed in this conversation")


class ScapyPcapAnalysisResponse(BaseModel):
    """Response payload for Layer 02 PCAP upload and Scapy parsing."""
    status: str = Field(default="success", description="Processing status (success, error)")
    filename: str = Field(..., description="Name of the uploaded PCAP file")
    file_size_bytes: int = Field(..., description="File size in bytes")
    total_packets: int = Field(..., description="Total number of packets parsed")
    ike_packets: int = Field(..., description="Count of IKE packets detected")
    esp_packets: int = Field(..., description="Count of ESP packets detected")
    ah_packets: int = Field(..., description="Count of AH packets detected")
    other_packets: int = Field(..., description="Count of non-IPsec packets")
    protocol_counts: dict[str, int] = Field(default_factory=dict, description="Counts by protocol (IKE, ESP, AH, etc.)")
    source_ips: list[str] = Field(default_factory=list, description="Unique source IP addresses found")
    destination_ips: list[str] = Field(default_factory=list, description="Unique destination IP addresses found")
    all_ips: list[str] = Field(default_factory=list, description="All unique IP addresses involved")
    conversations: list[CaptureConversationSummary] = Field(default_factory=list, description="Aggregated IP conversation pairs")
    packets: list[ScapyPacketSummary] = Field(default_factory=list, description="Sample of parsed packet records")
    analysis_duration_seconds: float = Field(default=0.0, description="Processing duration in seconds")
    error: Optional[str] = Field(default=None, description="Error details if parsing failed")

