"""IPv4 and IPv6 header decoding."""

from __future__ import annotations

import ipaddress
import struct

from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.models import IPLayer

IP_PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}

# IPv6 extension headers we step over to reach the transport/IPsec header.
IPV6_EXTENSION_HEADERS = {0, 43, 60}  # hop-by-hop, routing, destination options


def protocol_name(number: int) -> str:
    return IP_PROTOCOL_NAMES.get(number, f"IP proto {number}")


def decode_ipv4(data: bytes) -> tuple[IPLayer, bytes]:
    if len(data) < 20:
        raise TruncatedError("IPv4", 20, len(data))
    first, _tos, total_length, ident, flags_frag, ttl, proto, _csum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", data[:20]
    )
    version = first >> 4
    if version != 4:
        raise ValueError(f"IPv4 header claims version {version}")
    ihl = (first & 0x0F) * 4
    if ihl < 20:
        raise ValueError(f"IPv4 header length {ihl} is below the 20-byte minimum")
    if len(data) < ihl:
        raise TruncatedError("IPv4 options", ihl, len(data))

    layer = IPLayer(
        version=4,
        source=str(ipaddress.IPv4Address(src)),
        destination=str(ipaddress.IPv4Address(dst)),
        protocol_number=proto,
        protocol_name=protocol_name(proto),
        total_length=total_length,
        ttl=ttl,
        header_length=ihl,
        identification=ident,
        dont_fragment=bool(flags_frag & 0x4000),
        more_fragments=bool(flags_frag & 0x2000),
        fragment_offset=(flags_frag & 0x1FFF) * 8,
    )
    # Bound the payload by the declared total length when the frame carries padding.
    end = min(len(data), total_length) if total_length >= ihl else len(data)
    return layer, data[ihl:end]


IPV6_EXTENSION_HEADER_NAMES = {
    0: "Hop-by-Hop Options",
    43: "Routing",
    44: "Fragment",
    60: "Destination Options",
}


def decode_ipv6(data: bytes) -> tuple[IPLayer, bytes]:
    if len(data) < 40:
        raise TruncatedError("IPv6", 40, len(data))
    vtf, payload_length, next_header, hop_limit, src, dst = struct.unpack("!IHBB16s16s", data[:40])
    version = vtf >> 28
    if version != 6:
        raise ValueError(f"IPv6 header claims version {version}")

    payload = data[40 : 40 + payload_length] if payload_length else data[40:]
    fragmented = False
    extension_headers_seen: list[str] = []

    # Walk extension headers until a transport or IPsec header is reached.
    while next_header in IPV6_EXTENSION_HEADERS or next_header == 44:
        ext_name = IPV6_EXTENSION_HEADER_NAMES.get(next_header, f"Extension Header {next_header}")
        extension_headers_seen.append(ext_name)
        if len(payload) < 8:
            raise TruncatedError("IPv6 extension header", 8, len(payload))
        if next_header == 44:  # Fragment header: fixed 8 bytes
            fragmented = True
            next_header = payload[0]
            payload = payload[8:]
        else:
            ext_len = (payload[1] + 1) * 8
            if len(payload) < ext_len:
                raise TruncatedError("IPv6 extension header", ext_len, len(payload))
            next_header = payload[0]
            payload = payload[ext_len:]

    layer = IPLayer(
        version=6,
        source=str(ipaddress.IPv6Address(src)),
        destination=str(ipaddress.IPv6Address(dst)),
        protocol_number=next_header,
        protocol_name=protocol_name(next_header),
        total_length=40 + payload_length,
        ttl=hop_limit,
        header_length=40,
        traffic_class=(vtf >> 20) & 0xFF,
        flow_label=vtf & 0xFFFFF,
        more_fragments=fragmented if fragmented else None,
        extension_headers=extension_headers_seen,
    )
    return layer, payload
