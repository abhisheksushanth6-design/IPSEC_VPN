"""Layer 03 decoder tests against byte-exact frames."""

from __future__ import annotations

import pytest

from app.layers.layer03_protocol_analysis import CaptureFormatError, analyze_capture
from app.layers.layer03_protocol_analysis.capture_reader import Record
from app.layers.layer03_protocol_analysis.analyzer import analyze_frame
from app.layers.layer03_protocol_analysis.ipsec import classify_udp_encapsulation

from packet_builders import (
    DST4, DST6, SRC4, SRC6, ah, esp, ethernet, icmp, ikev1, ikev2, ipv4, ipv6, pcap, pcapng, tcp, udp,
)


def one(frame: bytes, link_type: int = 1):
    _, results = analyze_capture(pcap([frame], link_type=link_type), max_packets=10)
    assert len(results) == 1
    return results[0]


def test_tcp_syn() -> None:
    r = one(ethernet(ipv4(tcp(flags=0x002), proto=6)))
    assert r.parse_status == "OK"
    assert r.protocol == "TCP"
    assert r.layers == ["Ethernet", "IPv4", "TCP"]
    assert (r.source, r.destination) == (SRC4, DST4)
    assert r.transport.kind == "TCP"
    assert r.transport.flags == ["SYN"]
    assert r.transport.destination_port == 443
    assert r.ip.ttl == 64 and r.ip.dont_fragment is True


def test_udp_plain_is_not_ipsec() -> None:
    r = one(ethernet(ipv4(udp(b"payload", 5353, 53), proto=17)))
    assert r.protocol == "UDP"
    assert r.ipsec is None
    assert r.transport.destination_port == 53


def test_icmp_echo_request() -> None:
    r = one(ethernet(ipv4(icmp(8), proto=1)))
    assert r.protocol == "ICMP"
    assert r.transport.type_name == "Echo Request"


def test_ipv6_udp() -> None:
    r = one(ethernet(ipv6(udp(b"x", 1111, 2222), next_header=17), ethertype=0x86DD))
    assert r.ip.version == 6
    assert (r.source, r.destination) == (SRC6, DST6)
    assert r.protocol == "UDP"
    assert r.layers == ["Ethernet", "IPv6", "UDP"]


def test_vlan_tagged_frame() -> None:
    r = one(ethernet(ipv4(tcp(), proto=6), vlan=42))
    assert r.ethernet.vlan_id == 42
    assert r.protocol == "TCP"


def test_esp_native() -> None:
    r = one(ethernet(ipv4(esp(spi=0xC0FFEE01, seq=7), proto=50)))
    assert r.protocol == "ESP"
    assert r.ipsec.type == "ESP" and r.ipsec.nat_traversal is False
    assert r.ipsec.esp.spi == "0xc0ffee01"
    assert r.ipsec.esp.sequence_number == 7
    assert r.ipsec.esp.encrypted is True
    assert r.flags.encrypted is True


def test_ah_native() -> None:
    r = one(ethernet(ipv4(ah(next_header=17, spi=0xABCD0001, seq=3) + udp(b"", 1, 2), proto=51)))
    assert r.protocol == "AH"
    assert r.ipsec.ah.spi == "0xabcd0001"
    assert r.ipsec.ah.sequence_number == 3
    assert r.ipsec.ah.next_header_name == "UDP"
    assert r.ipsec.ah.icv_length == 12
    assert r.flags.authenticated is True


def test_ikev2_sa_init_over_udp_500() -> None:
    r = one(ethernet(ipv4(udp(ikev2(), 500, 500), proto=17)))
    assert r.protocol == "IKE"
    assert r.layers == ["Ethernet", "IPv4", "UDP", "IKE"]
    ike = r.ipsec.ike
    assert ike.version == "2.0"
    assert ike.exchange_name == "IKE_SA_INIT"
    assert ike.initiator_spi == "01" * 8
    assert [p.name for p in ike.payloads] == ["SA", "KE", "Nonce"]
    assert ike.payload_count == 3
    assert "Initiator" in ike.flags
    assert r.ipsec.nat_traversal is False
    assert ike.encrypted_payload is False


def test_ikev2_auth_with_encrypted_payload() -> None:
    r = one(ethernet(ipv4(udp(ikev2(exchange=35, payloads=[(46, b"\x00" * 40)], message_id=1), 500, 500), proto=17)))
    ike = r.ipsec.ike
    assert ike.exchange_name == "IKE_AUTH"
    assert ike.payloads[0].name == "SK (Encrypted)"
    assert ike.encrypted_payload is True
    assert r.flags.encrypted is True


def test_ikev1_main_mode() -> None:
    r = one(ethernet(ipv4(udp(ikev1(), 500, 500), proto=17)))
    ike = r.ipsec.ike
    assert ike.version == "1.0"
    assert ike.exchange_name == "Identity Protection (Main Mode)"
    assert [p.name for p in ike.payloads] == ["SA", "VENDOR"]


def test_ike_nat_t_with_non_esp_marker() -> None:
    r = one(ethernet(ipv4(udp(b"\x00\x00\x00\x00" + ikev2(), 4500, 4500), proto=17)))
    assert r.protocol == "IKE"
    assert r.ipsec.nat_traversal is True
    assert r.ipsec.udp_port == 4500
    assert r.flags.nat_t is True


def test_esp_in_udp_nat_t() -> None:
    r = one(ethernet(ipv4(udp(esp(spi=0x0BADF00D, seq=9), 4500, 4500), proto=17)))
    assert r.protocol == "ESP"
    assert r.ipsec.nat_traversal is True
    assert r.ipsec.esp.spi == "0x0badf00d"


def test_nat_keepalive() -> None:
    r = one(ethernet(ipv4(udp(b"\xff", 4500, 4500), proto=17)))
    assert r.protocol == "UDP"
    assert r.flags.nat_t is True
    assert "keepalive" in r.info


def test_udp_500_with_non_ike_payload_stays_udp() -> None:
    """Port 500 alone must not be classified as IKE."""
    r = one(ethernet(ipv4(udp(b"hello world", 500, 500), proto=17)))
    assert r.protocol == "UDP"
    assert r.ipsec is None
    assert r.parse_status == "OK"


def test_udp_4500_random_short_payload_not_ipsec() -> None:
    r = one(ethernet(ipv4(udp(b"\x12\x34", 4500, 4500), proto=17)))
    assert r.protocol == "UDP"
    assert r.ipsec is None


def test_classifier_returns_none_off_ports() -> None:
    assert classify_udp_encapsulation(80, 12345, ikev2()) is None


def test_truncated_ipv4_marked_malformed_and_keeps_ethernet() -> None:
    r = one(ethernet(b"\x45\x00\x00"))
    assert r.parse_status == "MALFORMED"
    assert r.parse_affected_protocol == "IPv4"
    assert r.layers == ["Ethernet"]
    assert r.flags.malformed is True


def test_bad_ike_payload_length_marked_malformed() -> None:
    import struct
    broken = struct.pack("!8s8sBBBBII", b"\x01" * 8, b"\x00" * 8, 33, 0x20, 34, 0x08, 0, 32) + b"\x00\x00\x00\x02"
    r = one(ethernet(ipv4(udp(broken, 500, 500), proto=17)))
    assert r.parse_status == "MALFORMED"
    assert "IKE" in r.layers


def test_ipv4_fragment_has_no_transport() -> None:
    r = one(ethernet(ipv4(b"\x00" * 16, proto=17, flags_frag=0x0010)))
    assert r.flags.fragmented is True
    assert r.transport is None
    assert "fragment" in r.info


def test_one_malformed_packet_does_not_stop_capture() -> None:
    frames = [ethernet(ipv4(tcp(), proto=6)), ethernet(b"\x45"), ethernet(ipv4(esp(), proto=50))]
    _, results = analyze_capture(pcap(frames), max_packets=10)
    assert [r.parse_status for r in results] == ["OK", "MALFORMED", "OK"]
    assert [r.number for r in results] == [1, 2, 3]


def test_pcapng_reader() -> None:
    meta, results = analyze_capture(pcapng([ethernet(ipv4(udp(ikev2(), 500, 500), proto=17))]), max_packets=10)
    assert meta.format == "pcapng"
    assert meta.link_type_name == "Ethernet"
    assert results[0].protocol == "IKE"
    assert results[0].timestamp.startswith("2023-11-14T")


def test_pcap_raw_ip_link_type() -> None:
    r = one(ipv4(tcp(), proto=6), link_type=101)
    assert r.ethernet is None and r.protocol == "TCP"


def test_max_packets_truncates_capture() -> None:
    meta, results = analyze_capture(pcap([ethernet(ipv4(tcp(), proto=6))] * 5), max_packets=3)
    assert meta.packet_count == 3 and meta.truncated is True


def test_raw_view_present_and_bounded() -> None:
    r = one(ethernet(ipv4(tcp(payload=b"A" * 3000), proto=6)))
    assert r.raw.length > 2048 and r.raw.truncated is True
    assert len(bytes.fromhex(r.raw.hex)) == 2048


def test_invalid_file_rejected() -> None:
    with pytest.raises(CaptureFormatError):
        analyze_capture(b"this is not a capture", max_packets=10)


def test_analyze_frame_direct() -> None:
    r = analyze_frame(1, Record(0.0, 14, 14, ethernet(b"")), 1)
    assert r.timestamp == ""
    assert r.parse_status == "MALFORMED"
