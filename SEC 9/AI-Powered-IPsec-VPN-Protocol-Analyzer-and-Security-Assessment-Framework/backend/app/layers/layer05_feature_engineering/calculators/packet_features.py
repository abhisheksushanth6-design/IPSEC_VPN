"""Packet-level feature calculation.

Everything here reads a single decoded packet from Layer 03. Nothing is
re-parsed: the analyzer already produced these fields, and a feature that the
decoder could not populate is reported as unavailable rather than guessed.
"""

from __future__ import annotations

from typing import Optional

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

from ..registry import SRC_PACKET_IKE, SRC_PACKET_IPSEC, SRC_SESSION
from ..validation import FeatureSet

NO_IP = "The packet has no decoded IP layer."
NO_TRANSPORT = "The packet has no decoded transport header; ESP and AH ride directly on IP."
NO_IPSEC = "The packet carries no decoded IPsec layer."
NO_IKE = "The packet carries no IKE message."
NO_SEQUENCE = "Only ESP and AH headers carry a sequence number."


def calculate_packet_features(
    packet: PacketAnalysisResult,
    *,
    session_source: Optional[str] = None,
    session_id: Optional[str] = None,
) -> FeatureSet:
    """Features for one packet.

    ``session_source`` is the source address of the session's first observed
    packet. It is the only thing that makes direction meaningful, so when the
    packet belongs to no discovered session, direction stays UNKNOWN rather
    than being inferred from address ordering.
    """
    fs = FeatureSet("PACKET")

    # ----- size and network ------------------------------------------------
    fs.add("packet_length", packet.original_length)
    fs.add(
        "captured_length",
        packet.captured_length,
        detail="Capture was snapped short of the wire length."
        if packet.captured_length < packet.original_length
        else None,
    )

    ip = packet.ip
    if ip is None:
        fs.missing("ip_version", NO_IP)
        fs.missing("fragmented", NO_IP)
    else:
        fs.add("ip_version", ip.version)
        fragmented = _fragmented(packet)
        fs.add_or_missing(
            "fragmented",
            fragmented,
            "The IP header exposes no fragmentation fields.",
        )

    transport = packet.transport
    kind = getattr(transport, "kind", None)
    if kind is None:
        fs.missing("transport_protocol", NO_TRANSPORT)
        fs.missing("source_port", NO_TRANSPORT)
        fs.missing("destination_port", NO_TRANSPORT)
    else:
        fs.add("transport_protocol", str(kind))
        source_port = getattr(transport, "source_port", None)
        destination_port = getattr(transport, "destination_port", None)
        fs.add_or_missing("source_port", source_port, "ICMP carries no ports.")
        fs.add_or_missing("destination_port", destination_port, "ICMP carries no ports.")

    # ----- direction -------------------------------------------------------
    if ip is None:
        fs.missing("direction", NO_IP, source=SRC_SESSION)
    elif session_source is None:
        fs.missing(
            "direction",
            "The packet belongs to no discovered session, so there is no reference direction. "
            "Direction is never inferred from address ordering.",
            source=SRC_SESSION,
        )
    else:
        fs.add(
            "direction",
            "OUTBOUND" if ip.source == session_source else "INBOUND",
            detail=f"Relative to the first packet of session {session_id}." if session_id else None,
            source=SRC_SESSION,
        )

    # ----- IPsec -----------------------------------------------------------
    ipsec = packet.ipsec
    fs.add("is_ike", bool(ipsec and ipsec.type == "IKE"))
    fs.add("is_esp", bool(ipsec and ipsec.type == "ESP"))
    fs.add("is_ah", bool(ipsec and ipsec.type == "AH"))
    fs.add("is_nat_t", bool(ipsec and ipsec.nat_traversal))

    if ipsec is None:
        for name in ("ipsec_protocol", "spi_value", "sequence_number", "encrypted_payload_present"):
            fs.missing(name, NO_IPSEC)
        fs.add("spi_present", False, detail="No IPsec layer, so no SPI is present.")
    else:
        fs.add("ipsec_protocol", ipsec.type)
        spi = _spi(packet)
        fs.add("spi_present", spi is not None)
        fs.add_or_missing("spi_value", spi, "No SPI was decoded from this packet.")

        sequence = None
        if ipsec.esp is not None:
            sequence = ipsec.esp.sequence_number
        elif ipsec.ah is not None:
            sequence = ipsec.ah.sequence_number
        fs.add_or_missing("sequence_number", sequence, NO_SEQUENCE, source=SRC_PACKET_IPSEC)

        ike = ipsec.ike
        if ike is None:
            fs.missing("encrypted_payload_present", NO_IKE, source=SRC_PACKET_IKE)
        else:
            fs.add("encrypted_payload_present", bool(ike.encrypted_payload), source=SRC_PACKET_IKE)

    # ----- IKE header ------------------------------------------------------
    ike = ipsec.ike if ipsec else None
    if ike is None:
        for name in (
            "ike_version",
            "ike_exchange_type",
            "ike_exchange_name",
            "ike_message_id",
            "ike_payload_count",
        ):
            fs.missing(name, NO_IKE)
    else:
        fs.add("ike_version", ike.version)
        fs.add("ike_exchange_type", ike.exchange_type)
        fs.add("ike_exchange_name", ike.exchange_name)
        fs.add("ike_message_id", ike.message_id)
        fs.add(
            "ike_payload_count",
            ike.payload_count,
            partial=bool(ike.encrypted_payload),
            partial_detail="Counts only the visible payload chain; payloads inside the encrypted SK payload are not decoded."
            if ike.encrypted_payload
            else None,
        )

    return fs


def _fragmented(packet: PacketAnalysisResult) -> Optional[bool]:
    """Fragmentation as the decoder saw it, from flags or the IP header."""
    ip = packet.ip
    if ip is not None and (ip.more_fragments is not None or ip.fragment_offset is not None):
        return bool(ip.more_fragments) or bool(ip.fragment_offset)
    if packet.flags is not None:
        return bool(packet.flags.fragmented)
    return None


def _spi(packet: PacketAnalysisResult) -> Optional[str]:
    """The SPI a packet carries. A public header field, never key material."""
    ipsec = packet.ipsec
    if ipsec is None:
        return None
    if ipsec.esp is not None:
        return ipsec.esp.spi
    if ipsec.ah is not None:
        return ipsec.ah.spi
    if ipsec.ike is not None:
        return ipsec.ike.initiator_spi
    return None
