"""TCP, UDP and ICMP header decoding."""

from __future__ import annotations

import struct

from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.models import ICMPLayer, TCPLayer, UDPLayer

TCP_FLAG_BITS = [
    (0x001, "FIN"), (0x002, "SYN"), (0x004, "RST"), (0x008, "PSH"),
    (0x010, "ACK"), (0x020, "URG"), (0x040, "ECE"), (0x080, "CWR"), (0x100, "NS"),
]

ICMP_TYPE_NAMES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp", 14: "Timestamp Reply",
}
ICMPV6_TYPE_NAMES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
    134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
}


def decode_tcp(data: bytes) -> tuple[TCPLayer, bytes]:
    if len(data) < 20:
        raise TruncatedError("TCP", 20, len(data))
    sport, dport, seq, ack, offset_flags, window, _csum, _urg = struct.unpack("!HHIIHHHH", data[:20])
    header_length = (offset_flags >> 12) * 4
    if header_length < 20:
        raise ValueError(f"TCP data offset {header_length} is below the 20-byte minimum")
    if len(data) < header_length:
        raise TruncatedError("TCP options", header_length, len(data))
    flags = [name for bit, name in TCP_FLAG_BITS if offset_flags & bit]
    layer = TCPLayer("TCP", sport, dport, seq, ack, flags, window, header_length)
    return layer, data[header_length:]


def decode_udp(data: bytes) -> tuple[UDPLayer, bytes]:
    if len(data) < 8:
        raise TruncatedError("UDP", 8, len(data))
    sport, dport, length, csum = struct.unpack("!HHHH", data[:8])
    layer = UDPLayer("UDP", sport, dport, length, csum)
    payload = data[8:length] if 8 <= length <= len(data) else data[8:]
    return layer, payload


def decode_icmp(data: bytes, ipv6: bool = False) -> tuple[ICMPLayer, bytes]:
    if len(data) < 4:
        raise TruncatedError("ICMPv6" if ipv6 else "ICMP", 4, len(data))
    icmp_type, code, csum = struct.unpack("!BBH", data[:4])
    names = ICMPV6_TYPE_NAMES if ipv6 else ICMP_TYPE_NAMES
    layer = ICMPLayer("ICMP", icmp_type, code, csum, names.get(icmp_type, f"Type {icmp_type}"))
    return layer, data[4:]
