"""Session correlation against byte-built captures."""

from __future__ import annotations

import struct

from app.layers.layer03_protocol_analysis import analyze_capture
from app.services.session_correlation import INACTIVITY_GAP_SECONDS, correlate

from packet_builders import DST4, SRC4, ah, esp, ethernet, icmp, ike_payload, ikev1, ikev2, ipv4, pcap, tcp, udp

CAPTURE_ID = "test-capture"
T0 = 1_700_000_000.0


def pcap_at(frames_with_ts: list[tuple[bytes, float]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for frame, ts in frames_with_ts:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def sessions_for(frames_with_ts):
    _, packets = analyze_capture(pcap_at(frames_with_ts), max_packets=10_000)
    return correlate(packets, CAPTURE_ID)


def ike(*, src=SRC4, dst=DST4, **kw):
    return ethernet(ipv4(udp(ikev2(**kw), 500, 500), proto=17, src=src, dst=dst))


def esp_frame(*, src=SRC4, dst=DST4, **kw):
    return ethernet(ipv4(esp(**kw), proto=50, src=src, dst=dst))


def test_one_session_with_ike_then_esp_both_directions() -> None:
    frames = [
        (ike(flags=0x08, message_id=0), T0),
        (ike(src=DST4, dst=SRC4, flags=0x20, message_id=0, r_spi=b"\x02" * 8), T0 + 0.1),
        (ike(exchange=35, payloads=[(46, b"\x00" * 40)], flags=0x08, message_id=1, r_spi=b"\x02" * 8), T0 + 0.2),
        (ike(src=DST4, dst=SRC4, exchange=35, payloads=[(46, b"\x00" * 40)], flags=0x20, message_id=1, r_spi=b"\x02" * 8), T0 + 0.3),
        (esp_frame(spi=0xAAAA0001, seq=1), T0 + 1.0),
        (esp_frame(src=DST4, dst=SRC4, spi=0xBBBB0001, seq=1), T0 + 1.1),
        (esp_frame(spi=0xAAAA0001, seq=2), T0 + 2.0),
    ]
    sessions = sessions_for(frames)
    assert len(sessions) == 1
    s = sessions[0]
    assert (s.source, s.destination) == (SRC4, DST4)
    assert s.direction == "BIDIRECTIONAL"
    assert s.state == "ACTIVE"
    assert s.packet_count == 7 and s.ike_packets == 4 and s.esp_packets == 3
    assert s.ike_version == "2.0"
    assert s.ike.exchange_types == ["IKE_SA_INIT", "IKE_AUTH"]
    assert s.ike.initiator_spis == ["01" * 8]
    assert s.ike.responder_spis == ["02" * 8]
    assert [x.spi for x in s.esp.spis] == ["0xaaaa0001", "0xbbbb0001"]
    assert s.esp.spis[0].sequence_min == 1 and s.esp.spis[0].sequence_max == 2
    assert s.correlation == "DIRECT"
    assert s.duration_seconds == 2.0
    assert [e.label for e in s.timeline] == ["First packet", "IKE detected", "IKE_AUTH observed", "IPsec traffic", "Last packet"]
    assert s.byte_count == sum(len(f) for f, _ in frames)


def test_session_id_is_stable_across_runs() -> None:
    frames = [(ike(), T0), (esp_frame(), T0 + 1)]
    a = sessions_for(frames)[0].id
    b = sessions_for(frames)[0].id
    assert a == b and a.startswith("IPSEC-") and len(a) == 18


def test_multiple_independent_sessions_by_endpoint_pair() -> None:
    frames = [
        (ike(), T0),
        (ike(src="192.0.2.30", dst="198.51.100.40"), T0 + 0.5),
        (esp_frame(), T0 + 1),
        (esp_frame(src="192.0.2.30", dst="198.51.100.40", spi=0x1234), T0 + 1.5),
    ]
    sessions = sessions_for(frames)
    assert len(sessions) == 2
    assert {(s.source, s.destination) for s in sessions} == {(SRC4, DST4), ("192.0.2.30", "198.51.100.40")}
    assert [s.ordinal for s in sessions] == [1, 2]


def test_inactivity_gap_splits_sessions() -> None:
    frames = [(esp_frame(seq=1), T0), (esp_frame(seq=2), T0 + INACTIVITY_GAP_SECONDS + 1)]
    sessions = sessions_for(frames)
    assert len(sessions) == 2
    assert all(s.packet_count == 1 for s in sessions)


def test_esp_only_is_active_with_no_ike_info() -> None:
    sessions = sessions_for([(esp_frame(seq=5), T0), (esp_frame(seq=6), T0 + 1)])
    s = sessions[0]
    assert s.state == "ACTIVE" and s.ike is None and s.ike_version is None
    assert s.direction == "OUTBOUND"
    assert "child SA carried traffic" in s.evidence[0]


def test_sa_init_only_is_negotiating() -> None:
    s = sessions_for([(ike(flags=0x08), T0)])[0]
    assert s.state == "NEGOTIATING"
    assert s.direction == "OUTBOUND"


def test_ike_auth_response_without_data_is_established() -> None:
    frames = [
        (ike(flags=0x08), T0),
        (ike(src=DST4, dst=SRC4, exchange=35, payloads=[(46, b"\x00" * 8)], flags=0x20, message_id=1), T0 + 1),
    ]
    s = sessions_for(frames)[0]
    assert s.state == "ESTABLISHED"
    assert "IKE_AUTH response observed." in s.evidence


def test_plaintext_delete_terminates() -> None:
    frames = [
        (ike(flags=0x08), T0),
        (ethernet(ipv4(udp(ikev2(exchange=37, payloads=[(42, b"\x00" * 8)], flags=0x08, message_id=2), 500, 500), proto=17)), T0 + 5),
    ]
    s = sessions_for(frames)[0]
    assert s.state == "TERMINATED"
    assert any(e.label == "Termination observed" for e in s.timeline)


def test_informational_only_is_discovered_not_established() -> None:
    frames = [(ethernet(ipv4(udp(ikev2(exchange=37, payloads=[(41, b"\x00" * 8)]), 500, 500), proto=17)), T0)]
    s = sessions_for(frames)[0]
    assert s.state == "DISCOVERED"


def test_ikev1_quick_mode_is_established() -> None:
    frames = [
        (ethernet(ipv4(udp(ikev1(exchange=2), 500, 500), proto=17)), T0),
        (ethernet(ipv4(udp(ikev1(exchange=32, payloads=[(8, b"\x00" * 16)]), 500, 500), proto=17)), T0 + 1),
    ]
    s = sessions_for(frames)[0]
    assert s.ike_version == "1.0" and s.state == "ESTABLISHED"


def test_non_ipsec_and_malformed_packets_are_excluded() -> None:
    frames = [
        (ethernet(ipv4(tcp(), proto=6)), T0),
        (ethernet(ipv4(icmp(), proto=1)), T0 + 1),
        (ethernet(b"\x45\x00"), T0 + 2),
        (esp_frame(), T0 + 3),
    ]
    sessions = sessions_for(frames)
    assert len(sessions) == 1 and sessions[0].packet_count == 1


def test_empty_input() -> None:
    assert correlate([], CAPTURE_ID) == []
    assert sessions_for([(ethernet(ipv4(tcp(), proto=6)), T0)]) == []


def test_nat_t_recorded_from_evidence() -> None:
    frames = [(ethernet(ipv4(udp(b"\x00\x00\x00\x00" + ikev2(), 4500, 4500), proto=17)), T0),
              (ethernet(ipv4(udp(esp(spi=0x5), 4500, 4500), proto=17)), T0 + 1)]
    s = sessions_for(frames)[0]
    assert s.nat_traversal is True
    assert any(e.label == "NAT-T observed" and e.detail == "UDP/4500" for e in s.timeline)


def test_ah_information() -> None:
    frames = [(ethernet(ipv4(ah(spi=0x77, seq=10), proto=51)), T0), (ethernet(ipv4(ah(spi=0x77, seq=11), proto=51)), T0 + 1)]
    s = sessions_for(frames)[0]
    assert s.ah.spis[0].spi == "0x00000077" and s.ah.spis[0].sequence_max == 11 and s.esp is None


def test_missing_timestamps_yield_partial_correlation_without_duration() -> None:
    from packet_builders import pcapng
    from app.layers.layer03_protocol_analysis.capture_reader import Record
    from app.layers.layer03_protocol_analysis.analyzer import analyze_frame
    packets = [analyze_frame(1, Record(0.0, 0, 0, esp_frame()), 1), analyze_frame(1, Record(0.0, 0, 0, esp_frame(seq=8)), 2)]
    s = correlate(packets, CAPTURE_ID)[0]
    assert s.start_time is None and s.duration_seconds is None
    assert s.correlation == "PARTIAL"
    assert s.activity == []


def test_activity_buckets_sum_to_packet_count() -> None:
    frames = [(esp_frame(seq=i), T0 + i * 0.5) for i in range(1, 21)]
    s = sessions_for(frames)[0]
    assert sum(p.packets for p in s.activity) == 20
