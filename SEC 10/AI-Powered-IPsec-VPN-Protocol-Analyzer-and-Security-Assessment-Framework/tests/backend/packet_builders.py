"""Byte-level frame builders following the RFC header layouts.

These construct real, structurally valid packets for the parser to decode.
Addresses use documentation ranges (RFC 5737 / RFC 3849).
"""

from __future__ import annotations

import ipaddress
import struct

SRC4, DST4 = "192.0.2.10", "198.51.100.20"
SRC6, DST6 = "2001:db8::10", "2001:db8::20"
MAC_A, MAC_B = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def ethernet(payload: bytes, ethertype: int = 0x0800, vlan: int | None = None) -> bytes:
    hdr = MAC_B + MAC_A
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    return hdr + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, proto: int, src: str = SRC4, dst: str = DST4, ttl: int = 64,
         ident: int = 0x1234, flags_frag: int = 0x4000) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, flags_frag, ttl, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return hdr + payload


def ipv6(payload: bytes, next_header: int, src: str = SRC6, dst: str = DST6) -> bytes:
    hdr = struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
                      ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
    return hdr + payload


def tcp(payload: bytes = b"", sport: int = 51234, dport: int = 443, seq: int = 1000, ack: int = 0,
        flags: int = 0x002, window: int = 65535) -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, window, 0, 0) + payload


def udp(payload: bytes, sport: int, dport: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(icmp_type: int = 8, code: int = 0, payload: bytes = b"\x00" * 8) -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + payload


def esp(spi: int = 0xC0FFEE01, seq: int = 7, ciphertext: bytes = b"\xaa" * 32) -> bytes:
    return struct.pack("!II", spi, seq) + ciphertext


def ah(next_header: int = 17, spi: int = 0xABCD0001, seq: int = 3, icv: bytes = b"\x11" * 12) -> bytes:
    payload_len_words = (12 + len(icv)) // 4 - 2
    return struct.pack("!BBHII", next_header, payload_len_words, 0, spi, seq) + icv


def ike_payload(payload_type: int, next_type: int, body: bytes, critical: bool = False) -> bytes:
    return struct.pack("!BBH", next_type, 0x80 if critical else 0, 4 + len(body)) + body


def ikev2(exchange: int = 34, payloads: list[tuple[int, bytes]] | None = None, flags: int = 0x08,
          message_id: int = 0, i_spi: bytes = b"\x01" * 8, r_spi: bytes = b"\x00" * 8) -> bytes:
    payloads = payloads if payloads is not None else [(33, b"\x00" * 8), (34, b"\x00" * 16), (40, b"\x00" * 16)]
    chain = b""
    for index, (ptype, body) in enumerate(payloads):
        next_type = payloads[index + 1][0] if index + 1 < len(payloads) else 0
        chain += ike_payload(ptype, next_type, body)
    first = payloads[0][0] if payloads else 0
    length = 28 + len(chain)
    return struct.pack("!8s8sBBBBII", i_spi, r_spi, first, 0x20, exchange, flags, message_id, length) + chain


def ikev1(exchange: int = 2, payloads: list[tuple[int, bytes]] | None = None, flags: int = 0) -> bytes:
    payloads = payloads if payloads is not None else [(1, b"\x00" * 8), (13, b"\x00" * 16)]
    chain = b""
    for index, (ptype, body) in enumerate(payloads):
        next_type = payloads[index + 1][0] if index + 1 < len(payloads) else 0
        chain += ike_payload(ptype, next_type, body)
    first = payloads[0][0] if payloads else 0
    return struct.pack("!8s8sBBBBII", b"\x02" * 8, b"\x00" * 8, first, 0x10, exchange, flags, 0, 28 + len(chain)) + chain


def pcap(frames: list[bytes], link_type: int = 1, ts: float = 1_700_000_000.0) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    for i, frame in enumerate(frames):
        sec = int(ts) + i
        out += struct.pack("<IIII", sec, 0, len(frame), len(frame)) + frame
    return out


def pcapng(frames: list[bytes], link_type: int = 1) -> bytes:
    def block(btype: int, body: bytes) -> bytes:
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(0x00000001, struct.pack("<HHI", link_type, 0, 65535))
    out = shb + idb
    for i, frame in enumerate(frames):
        ts = (1_700_000_000 + i) * 1_000_000
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame
        out += block(0x00000006, body)
    return out
