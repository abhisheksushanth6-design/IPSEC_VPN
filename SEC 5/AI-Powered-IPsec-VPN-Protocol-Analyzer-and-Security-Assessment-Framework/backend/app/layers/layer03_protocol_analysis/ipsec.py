"""ESP, AH and NAT-T decoding (RFC 4303, RFC 4302, RFC 3948)."""

from __future__ import annotations

import struct

from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.models import AHLayer, ESPLayer
from app.layers.layer03_protocol_analysis.network_layer import protocol_name

IKE_PORT = 500
NAT_T_PORT = 4500
NON_ESP_MARKER = b"\x00\x00\x00\x00"


def decode_esp(data: bytes) -> ESPLayer:
    """ESP: SPI (4) + sequence (4) + encrypted payload + ICV.

    The ICV length is a property of the negotiated SA, which the packet does
    not carry, so the trailer cannot be separated from the ciphertext.
    """
    if len(data) < 8:
        raise TruncatedError("ESP", 8, len(data))
    spi, seq = struct.unpack("!II", data[:8])
    return ESPLayer(spi=f"0x{spi:08x}", sequence_number=seq, payload_length=len(data) - 8)


def decode_ah(data: bytes) -> tuple[AHLayer, bytes]:
    """AH: next header, payload length (in 32-bit words minus 2), reserved, SPI, seq, ICV."""
    if len(data) < 12:
        raise TruncatedError("AH", 12, len(data))
    next_header, payload_len_words, _reserved, spi, seq = struct.unpack("!BBHII", data[:12])
    total_length = (payload_len_words + 2) * 4
    if total_length < 12:
        raise ValueError(f"AH payload length {payload_len_words} is invalid")
    if len(data) < total_length:
        raise TruncatedError("AH ICV", total_length, len(data))
    icv = data[12:total_length]
    layer = AHLayer(
        next_header=next_header,
        next_header_name=protocol_name(next_header),
        payload_length=payload_len_words,
        spi=f"0x{spi:08x}",
        sequence_number=seq,
        authentication_data=icv.hex(),
        icv_length=len(icv),
    )
    return layer, data[total_length:]


def classify_udp_encapsulation(dport: int, sport: int, payload: bytes) -> str | None:
    """Decide what a UDP payload on the IPsec ports actually carries.

    Returns 'IKE', 'IKE_NAT_T', 'ESP_NAT_T', 'NAT_KEEPALIVE' or None. Port
    numbers alone are never sufficient; the payload structure must agree.
    """
    on_500 = IKE_PORT in (dport, sport)
    on_4500 = NAT_T_PORT in (dport, sport)
    if not (on_500 or on_4500):
        return None

    if on_4500:
        if len(payload) == 1 and payload == b"\xff":
            return "NAT_KEEPALIVE"
        if payload.startswith(NON_ESP_MARKER):
            return "IKE_NAT_T" if _looks_like_ike(payload[4:]) else None
        # RFC 3948 §2.1: an ESP SPI is never zero, so a nonzero first word is ESP.
        if len(payload) >= 8 and payload[:4] != NON_ESP_MARKER:
            return "ESP_NAT_T"
        return None

    return "IKE" if _looks_like_ike(payload) else None


def _looks_like_ike(data: bytes) -> bool:
    """A structurally plausible ISAKMP header: 28 bytes, version 1.x or 2.0."""
    if len(data) < 28:
        return False
    major = data[17] >> 4
    return major in (1, 2)
