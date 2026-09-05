"""Focused unit tests for Linux Cooked Capture v2 (SLL2, link type 276)."""

from __future__ import annotations

import pytest

from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer03_protocol_analysis.capture_reader import LINKTYPE_LINUX_SLL2

from packet_builders import (
    DST4,
    DST6,
    SRC4,
    SRC6,
    esp,
    ipv4,
    ipv6,
    pcap,
    sll2,
    tcp,
    udp,
)


def one_sll2(frame: bytes):
    meta, results = analyze_capture(pcap([frame], link_type=LINKTYPE_LINUX_SLL2), max_packets=10)
    assert len(results) == 1
    return meta, results[0]


def test_sll2_ipv4_tcp() -> None:
    """SLL2 frame with IPv4 payload must decode properly without being labeled as Ethernet."""
    frame = sll2(ipv4(tcp(flags=0x002), proto=6), ethertype=0x0800)
    meta, r = one_sll2(frame)

    assert meta.link_type == 276
    assert meta.link_type_name == "Linux cooked capture v2"
    assert r.parse_status == "OK"
    assert r.protocol == "TCP"
    assert r.ethernet is None
    assert r.layers == ["IPv4", "TCP"]
    assert (r.source, r.destination) == (SRC4, DST4)
    assert r.transport.kind == "TCP"
    assert r.transport.flags == ["SYN"]


def test_sll2_ipv4_esp() -> None:
    """SLL2 frame with IPv4 ESP payload must produce valid IPsec analysis."""
    frame = sll2(ipv4(esp(spi=0xC0FFEE01, seq=42), proto=50), ethertype=0x0800)
    _, r = one_sll2(frame)

    assert r.parse_status == "OK"
    assert r.protocol == "ESP"
    assert r.ethernet is None
    assert r.layers == ["IPv4", "ESP"]
    assert r.ipsec is not None
    assert r.ipsec.type == "ESP"
    assert r.ipsec.esp.spi == "0xc0ffee01"
    assert r.ipsec.esp.sequence_number == 42
    assert r.flags.encrypted is True


def test_sll2_ipv6_udp() -> None:
    """SLL2 frame with IPv6 UDP payload must decode properly without Ethernet."""
    frame = sll2(ipv6(udp(b"test-payload", 1234, 5678), next_header=17), ethertype=0x86DD)
    _, r = one_sll2(frame)

    assert r.parse_status == "OK"
    assert r.protocol == "UDP"
    assert r.ethernet is None
    assert r.ip.version == 6
    assert r.layers == ["IPv6", "UDP"]
    assert (r.source, r.destination) == (SRC6, DST6)
    assert r.transport.source_port == 1234
    assert r.transport.destination_port == 5678


def test_sll2_unknown_non_ip_ethertype() -> None:
    """SLL2 frame with non-IP ethertype (e.g. ARP 0x0806) must be classified as OTHER without error."""
    arp_payload = b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20
    frame = sll2(arp_payload, ethertype=0x0806)
    _, r = one_sll2(frame)

    assert r.parse_status == "OK"
    assert r.protocol == "OTHER"
    assert r.ethernet is None
    assert r.layers == []
    assert "Non-IP frame" in r.info


def test_sll2_truncated_frame() -> None:
    """SLL2 frame shorter than the 20-byte header must be marked MALFORMED with protocol 'Linux SLL2'."""
    short_frame = b"\x08\x00\x00\x00\x01\x02\x03\x04"  # Only 8 bytes
    _, r = one_sll2(short_frame)

    assert r.parse_status == "MALFORMED"
    assert r.parse_affected_protocol == "Linux SLL2"
    assert r.flags.malformed is True


def test_sll2_empty_frame() -> None:
    """Empty SLL2 frame must be marked MALFORMED with protocol 'Linux SLL2'."""
    _, r = one_sll2(b"")

    assert r.parse_status == "MALFORMED"
    assert r.parse_affected_protocol == "Linux SLL2"
    assert r.flags.malformed is True
