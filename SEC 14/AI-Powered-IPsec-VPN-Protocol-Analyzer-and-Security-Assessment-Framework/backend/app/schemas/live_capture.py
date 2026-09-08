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
