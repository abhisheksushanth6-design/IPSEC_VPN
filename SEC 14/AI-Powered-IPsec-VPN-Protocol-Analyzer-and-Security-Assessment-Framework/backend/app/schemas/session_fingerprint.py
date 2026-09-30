"""Pydantic schemas for Layer 04 Session Fingerprinting & Correlation API."""

from __future__ import annotations

from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SessionFingerprintComponentsSchema(_Model):
    endpoint_pair: List[str] = Field(..., description="Sorted IP address pair for the tunnel endpoints")
    protocols: List[str] = Field(..., description="Protocols participating in this session (IKE, ESP, AH)")
    ike_version: Optional[str] = Field(None, description="Negotiated or observed IKE version (e.g. IKEv2)")
    initiator_spi: Optional[str] = Field(None, description="IKE initiator SPI")
    responder_spi: Optional[str] = Field(None, description="IKE responder SPI")
    child_spis: List[str] = Field(default_factory=list, description="Sorted list of Child SA SPIs")
    encapsulation_mode: str = Field("TUNNEL", description="TUNNEL or TRANSPORT mode")
    nat_traversal: bool = Field(False, description="Whether NAT-T encapsulation was detected")
    encryption_algorithms: List[str] = Field(default_factory=list, description="Negotiated encryption algorithms")
    integrity_algorithms: List[str] = Field(default_factory=list, description="Negotiated integrity algorithms")
    dh_groups: List[str] = Field(default_factory=list, description="Diffie-Hellman groups")
    prf_algorithms: List[str] = Field(default_factory=list, description="Pseudo-random functions")


class VPNSessionFingerprintSchema(_Model):
    session_id: str = Field(..., description="Unique deterministic session identifier")
    capture_id: str = Field(..., description="Identifier of the capture file")
    fingerprint: str = Field(..., description="Full 64-character SHA-256 deterministic signature")
    short_signature: str = Field(..., description="16-character compact signature for display")
    initiator_ip: str = Field(..., description="Initiator / local IP address")
    responder_ip: str = Field(..., description="Responder / remote IP address")
    endpoint_pair: List[str] = Field(..., description="Canonical [ip1, ip2] endpoint pair")
    protocols: List[str] = Field(..., description="Active protocols in this session")
    state: str = Field(..., description="Session state (NEGOTIATING, ESTABLISHED, ACTIVE, TERMINATED, UNKNOWN)")
    start_time: Optional[str] = Field(None, description="First observed packet timestamp")
    end_time: Optional[str] = Field(None, description="Last observed packet timestamp")
    duration_seconds: float = Field(0.0, description="Session duration in seconds")
    total_packets: int = Field(0, description="Total packets in session")
    total_bytes: int = Field(0, description="Total bytes transferred in session")
    ike_packets: int = Field(0, description="IKE packet count")
    esp_packets: int = Field(0, description="ESP packet count")
    ah_packets: int = Field(0, description="AH packet count")
    ike_version: Optional[str] = Field(None, description="IKE version")
    initiator_spi: Optional[str] = Field(None, description="IKE Initiator SPI")
    responder_spi: Optional[str] = Field(None, description="IKE Responder SPI")
    child_sa_spis: List[str] = Field(default_factory=list, description="List of negotiated Child SA SPIs")
    encapsulation_mode: str = Field("TUNNEL", description="Encapsulation mode")
    nat_traversal: bool = Field(False, description="NAT-T encapsulation status")
    packet_numbers: List[int] = Field(default_factory=list, description="Packet sequence numbers belonging to session")
    crypto_summary: dict[str, Any] = Field(default_factory=dict, description="Cryptographic parameters summary")
    components: Optional[SessionFingerprintComponentsSchema] = Field(None, description="Normalized components used for hashing")


class SessionFingerprintReportSchema(BaseModel):
    capture_id: Optional[str] = None
    total_sessions: int = 0
    sessions: List[VPNSessionFingerprintSchema] = []
    status: str = "READY"
