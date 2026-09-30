"""Data models for Layer 04 Session Correlation and Fingerprinting.

Defines deterministic session structures, normalized fingerprint components,
and rich session metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


@dataclass
class SessionFingerprintComponents:
    """Normalized, canonical components used to generate a deterministic fingerprint.
    
    All lists and sets are sorted, strings normalized, floats rounded to ensure
    identical session characteristics produce the identical SHA-256 signature.
    """
    endpoint_pair: list[str]  # e.g. ["10.0.0.1", "10.0.0.2"] sorted
    protocols: list[str]      # e.g. ["ESP", "IKE"] sorted
    ike_version: Optional[str] = None  # "IKEv1", "IKEv2", or None
    initiator_spi: Optional[str] = None
    responder_spi: Optional[str] = None
    child_spis: list[str] = field(default_factory=list)  # sorted SPIs e.g. ["0x12345678"]
    encapsulation_mode: str = "TUNNEL"  # "TUNNEL" / "TRANSPORT"
    nat_traversal: bool = False
    encryption_algorithms: list[str] = field(default_factory=list)
    integrity_algorithms: list[str] = field(default_factory=list)
    dh_groups: list[str] = field(default_factory=list)
    prf_algorithms: list[str] = field(default_factory=list)

    def to_canonical_dict(self) -> dict[str, Any]:
        """Produce dictionary with sorted keys for deterministic serialization."""
        return {
            "child_spis": sorted(self.child_spis),
            "dh_groups": sorted(self.dh_groups),
            "encapsulation_mode": self.encapsulation_mode,
            "encryption_algorithms": sorted(self.encryption_algorithms),
            "endpoint_pair": sorted(self.endpoint_pair),
            "ike_version": self.ike_version,
            "initiator_spi": self.initiator_spi.lower() if self.initiator_spi else None,
            "integrity_algorithms": sorted(self.integrity_algorithms),
            "nat_traversal": self.nat_traversal,
            "prf_algorithms": sorted(self.prf_algorithms),
            "protocols": sorted(self.protocols),
            "responder_spi": self.responder_spi.lower() if self.responder_spi else None,
        }


@dataclass
class VPNSessionFingerprint:
    """Correlated IPsec VPN session with stable fingerprint and rich metadata."""
    session_id: str
    capture_id: str
    fingerprint: str               # 64-character SHA-256 signature
    short_signature: str         # First 16 characters for fast display
    initiator_ip: str
    responder_ip: str
    endpoint_pair: list[str]      # [ep1, ep2]
    protocols: list[str]          # ["IKE", "ESP", "AH"]
    state: Literal["NEGOTIATING", "ESTABLISHED", "ACTIVE", "TERMINATED", "UNKNOWN"]
    start_time: Optional[str]
    end_time: Optional[str]
    duration_seconds: float
    total_packets: int
    total_bytes: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    ike_version: Optional[str]
    initiator_spi: Optional[str]
    responder_spi: Optional[str]
    child_sa_spis: list[str]
    encapsulation_mode: str
    nat_traversal: bool
    packet_numbers: list[int] = field(default_factory=list)
    crypto_summary: dict[str, Any] = field(default_factory=dict)
    components: SessionFingerprintComponents = field(default_factory=lambda: SessionFingerprintComponents([], []))
