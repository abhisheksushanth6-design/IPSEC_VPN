"""Layer 05 calculation correctness and edge cases.

Fixtures are deterministic: the same bytes and the same feature version must
produce the same numbers. The edge-case block is the important half — an
empty packet set, a zero-duration session or a capture that is no longer
loaded must all produce an honest "unavailable" instead of a crash or a zero.
"""

from __future__ import annotations

import math

import packet_builders as B
import pytest

from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer05_feature_engineering import (
    SAEvent,
    SARecord,
    SessionRecord,
    extract_packet,
    extract_sa,
    extract_session,
)
from app.layers.layer05_feature_engineering.calculators import (
    calculate_sa_features,
    calculate_session_features,
)

CAPTURE = "test-capture"


def values(feature_set) -> dict:
    return {v.name: v for v in feature_set.values}


def vector_values(vector) -> dict:
    return {f.name: f for f in vector.features}


def decode(frames: list[bytes]):
    _, packets = analyze_capture(B.pcap(frames), 1000)
    return packets


# ----- fixtures -------------------------------------------------------------


@pytest.fixture()
def ike_esp_packets():
    """Two IKE messages each way plus ESP in both directions."""
    return decode(
        [
            B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0), 500, 500), 17)),
            B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0, flags=0x20), 500, 500), 17, src=B.DST4, dst=B.SRC4)),
            B.ethernet(B.ipv4(B.esp(spi=0xC0FFEE01, seq=1), 50)),
            B.ethernet(B.ipv4(B.esp(spi=0xDEADBE01, seq=1), 50, src=B.DST4, dst=B.SRC4)),
        ]
    )


def session_of(packets, **overrides) -> SessionRecord:
    ike = [p for p in packets if p.ipsec and p.ipsec.type == "IKE"]
    esp = [p for p in packets if p.ipsec and p.ipsec.type == "ESP"]
    ah = [p for p in packets if p.ipsec and p.ipsec.type == "AH"]
    timestamps = [p.timestamp for p in packets if p.timestamp]
    from app.layers.layer05_feature_engineering.calculators.timing_features import duration_between

    record = SessionRecord(
        id="SESSION-1",
        source=packets[0].ip.source if packets and packets[0].ip else "192.0.2.10",
        destination=packets[0].ip.destination if packets and packets[0].ip else "198.51.100.20",
        state="ACTIVE",
        direction="BIDIRECTIONAL",
        packet_count=len(packets),
        byte_count=sum(p.original_length for p in packets),
        ike_packets=len(ike),
        esp_packets=len(esp),
        ah_packets=len(ah),
        nat_traversal=False,
        start_time=min(timestamps) if timestamps else None,
        end_time=max(timestamps) if timestamps else None,
        duration_seconds=duration_between(min(timestamps), max(timestamps)) if timestamps else None,
        ike_version="2.0" if ike else None,
        ike_detail={
            "exchange_types": sorted({p.ipsec.ike.exchange_name for p in ike}),
            "payload_types": sorted({pl.name for p in ike for pl in p.ipsec.ike.payloads}),
        }
        if ike
        else None,
    )
    for key, value in overrides.items():
        setattr(record, key, value)
    return record


# ----- session calculations -------------------------------------------------


def test_counts_and_sizes_match_the_packets(ike_esp_packets) -> None:
    record = session_of(ike_esp_packets)
    v = values(calculate_session_features(record, ike_esp_packets))
    lengths = [p.original_length for p in ike_esp_packets]

    assert v["packet_count"].value == 4
    assert v["byte_count"].value == sum(lengths)
    assert v["ike_packet_count"].value == 2
    assert v["esp_packet_count"].value == 2
    assert v["ah_packet_count"].value == 0
    assert v["minimum_packet_size"].value == min(lengths)
    assert v["maximum_packet_size"].value == max(lengths)
    assert v["average_packet_size"].value == pytest.approx(sum(lengths) / len(lengths))


def test_duration_and_rates(ike_esp_packets) -> None:
    record = session_of(ike_esp_packets)
    v = values(calculate_session_features(record, ike_esp_packets))
    # The builder spaces frames one second apart, so four packets span three.
    assert v["session_duration_seconds"].value == pytest.approx(3.0)
    assert v["packets_per_second"].value == pytest.approx(4 / 3)
    assert v["bytes_per_second"].value == pytest.approx(record.byte_count / 3)


def test_interarrival_statistics(ike_esp_packets) -> None:
    v = values(calculate_session_features(session_of(ike_esp_packets), ike_esp_packets))
    assert v["mean_interarrival_time"].value == pytest.approx(1.0)
    assert v["min_interarrival_time"].value == pytest.approx(1.0)
    assert v["max_interarrival_time"].value == pytest.approx(1.0)
    assert v["interarrival_variance"].value == pytest.approx(0.0)


def test_protocol_ratios_sum_to_one(ike_esp_packets) -> None:
    v = values(calculate_session_features(session_of(ike_esp_packets), ike_esp_packets))
    assert v["ike_ratio"].value == pytest.approx(0.5)
    assert v["esp_ratio"].value == pytest.approx(0.5)
    assert v["ah_ratio"].value == pytest.approx(0.0)
    total = v["udp_ratio"].value + v["tcp_ratio"].value + v["other_ratio"].value
    assert total == pytest.approx(1.0)


def test_direction_is_relative_to_the_first_packet(ike_esp_packets) -> None:
    v = values(calculate_session_features(session_of(ike_esp_packets), ike_esp_packets))
    assert v["outbound_packets"].value == 2
    assert v["inbound_packets"].value == 2
    assert v["inbound_outbound_packet_ratio"].value == pytest.approx(1.0)
    assert v["outbound_bytes"].value + v["inbound_bytes"].value == sum(
        p.original_length for p in ike_esp_packets
    )


def test_ike_features_from_real_exchanges(ike_esp_packets) -> None:
    v = values(calculate_session_features(session_of(ike_esp_packets), ike_esp_packets))
    assert v["ike_message_count"].value == 2
    assert v["ike_exchange_count"].value == 1  # one exchange, request and response
    assert v["ike_sa_init_observed"].value is True
    assert v["ike_auth_observed"].value is False
    assert v["ike_payload_count"].value == 6
    assert v["unique_exchange_types"].value == 1


def test_packet_size_variance_and_deviation_agree(ike_esp_packets) -> None:
    v = values(calculate_session_features(session_of(ike_esp_packets), ike_esp_packets))
    variance = v["packet_size_variance"].value
    assert v["packet_size_standard_deviation"].value == pytest.approx(math.sqrt(variance), abs=1e-6)


def test_burst_window_counts_a_documented_window(ike_esp_packets) -> None:
    v = values(calculate_session_features(session_of(ike_esp_packets), ike_esp_packets))
    # Frames are one second apart and the window is one second, so no window
    # holds more than a single packet.
    assert v["maximum_packets_in_window"].value == 1
    assert v["maximum_bytes_in_window"].value == max(p.original_length for p in ike_esp_packets)


# ----- edge cases -----------------------------------------------------------


def test_empty_packet_set_does_not_crash() -> None:
    record = SessionRecord(
        id="S", source="192.0.2.10", destination="198.51.100.20", state="DISCOVERED",
        direction="UNKNOWN", packet_count=0, byte_count=0, ike_packets=0, esp_packets=0,
        ah_packets=0, nat_traversal=False,
    )
    v = values(calculate_session_features(record, []))
    assert v["packet_count"].value == 0
    assert v["average_packet_size"].availability == "UNAVAILABLE"
    assert v["ike_ratio"].availability == "UNAVAILABLE"
    assert v["minimum_packet_size"].availability == "UNAVAILABLE"


def test_single_packet_session_has_no_interarrival_gap(ike_esp_packets) -> None:
    one = ike_esp_packets[:1]
    v = values(calculate_session_features(session_of(one), one))
    assert v["packet_count"].value == 1
    assert v["mean_interarrival_time"].availability == "UNAVAILABLE"
    assert v["mean_interarrival_time"].value is None
    assert "two timestamped packets" in v["mean_interarrival_time"].detail


def test_zero_duration_session_reports_no_rate(ike_esp_packets) -> None:
    record = session_of(ike_esp_packets, duration_seconds=0.0)
    v = values(calculate_session_features(record, ike_esp_packets))
    for name in ("packets_per_second", "bytes_per_second", "ike_packets_per_second", "esp_packets_per_second"):
        assert v[name].availability == "UNAVAILABLE"
        assert v[name].value is None


def test_missing_timestamps_leave_timing_unavailable(ike_esp_packets) -> None:
    record = session_of(ike_esp_packets, start_time=None, end_time=None, duration_seconds=None)
    v = values(calculate_session_features(record, ike_esp_packets))
    assert v["first_seen"].availability == "UNAVAILABLE"
    assert v["session_duration_seconds"].availability == "UNAVAILABLE"
    # Counts are unaffected by missing time.
    assert v["packet_count"].value == 4


def test_packets_unavailable_marks_derived_features_not_zero(ike_esp_packets) -> None:
    """Aggregates survive without the capture; distributions do not."""
    v = values(calculate_session_features(session_of(ike_esp_packets), None))
    assert v["packet_count"].value == 4  # from the stored record
    for name in (
        "minimum_packet_size", "median_packet_size", "mean_interarrival_time",
        "inbound_packets", "udp_ratio", "ike_payload_count", "maximum_packets_in_window",
    ):
        assert v[name].availability == "UNAVAILABLE", name
        assert v[name].value is None, name
        assert "not loaded" in v[name].detail


def test_esp_only_session() -> None:
    packets = decode([B.ethernet(B.ipv4(B.esp(spi=0xC0FFEE01, seq=n), 50)) for n in (1, 2, 3)])
    v = values(calculate_session_features(session_of(packets), packets))
    assert v["esp_packet_count"].value == 3
    assert v["ike_packet_count"].value == 0
    assert v["esp_ratio"].value == pytest.approx(1.0)
    assert v["ike_version"].availability == "UNAVAILABLE"
    assert v["ike_sa_init_observed"].value is False
    assert v["retransmission_count"].availability == "UNAVAILABLE"


def test_ah_only_session() -> None:
    packets = decode([B.ethernet(B.ipv4(B.ah(spi=0xABCD0001, seq=n), 51)) for n in (1, 2)])
    v = values(calculate_session_features(session_of(packets), packets))
    assert v["ah_packet_count"].value == 2
    assert v["ah_ratio"].value == pytest.approx(1.0)
    assert v["other_ratio"].value == pytest.approx(1.0)  # native AH, no transport header


def test_ikev1_session_cannot_count_retransmissions() -> None:
    packets = decode(
        [
            B.ethernet(B.ipv4(B.udp(B.ikev1(exchange=2), 500, 500), 17)),
            B.ethernet(B.ipv4(B.udp(B.ikev1(exchange=2), 500, 500), 17, src=B.DST4, dst=B.SRC4)),
        ]
    )
    v = values(calculate_session_features(session_of(packets), packets))
    assert v["retransmission_count"].availability == "UNAVAILABLE"
    assert "IKEv2" in v["retransmission_count"].detail


def test_ikev2_retransmission_is_counted() -> None:
    frame = B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=34, message_id=0), 500, 500), 17))
    packets = decode([frame, frame])  # the same request twice
    v = values(calculate_session_features(session_of(packets), packets))
    assert v["retransmission_count"].value == 1


def test_encrypted_payloads_make_counts_partial() -> None:
    packets = decode(
        [B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=35, message_id=1, payloads=[(46, b"\x00" * 32)]), 500, 500), 17))]
    )
    v = values(calculate_session_features(session_of(packets), packets))
    assert v["ike_payload_count"].availability == "PARTIAL"
    assert v["delete_payload_count"].availability == "PARTIAL"
    assert "not decoded" in v["ike_payload_count"].detail


# ----- SA calculations ------------------------------------------------------


def ike_sa(**overrides) -> SARecord:
    record = SARecord(
        id="SA-1", type="IKE", state="ESTABLISHED", protocol="IKE",
        initiator="192.0.2.10", responder="198.51.100.20",
        packet_count=6, byte_count=600, nat_traversal=False, rekey_count=2,
        capture_ended_in_state=True, ike_version="2.0",
        start_time="2026-01-01T00:00:00+00:00", last_seen="2026-01-01T00:01:00+00:00",
        duration_seconds=60.0, child_sa_ids=["SA-2", "SA-3"],
        events=[
            SAEvent("SA DETECTED", "2026-01-01T00:00:00+00:00", None, "DETECTED"),
            SAEvent("NEGOTIATION START", "2026-01-01T00:00:01+00:00", "DETECTED", "NEGOTIATING"),
            SAEvent("SA ESTABLISHED", "2026-01-01T00:00:02+00:00", "NEGOTIATING", "ESTABLISHED"),
            SAEvent("REKEY START", "2026-01-01T00:00:20+00:00", "ESTABLISHED", "REKEYING"),
            SAEvent("REKEY START", "2026-01-01T00:00:50+00:00", "ESTABLISHED", "REKEYING"),
        ],
    )
    for key, value in overrides.items():
        setattr(record, key, value)
    return record


def test_sa_lifecycle_observations() -> None:
    v = values(calculate_sa_features(ike_sa()))
    assert v["sa_type"].value == "IKE"
    assert v["sa_duration_seconds"].value == pytest.approx(60.0)
    assert v["child_sa_count"].value == 2
    assert v["state_transition_count"].value == 5  # every fixture event changes state
    assert v["negotiation_observed"].value is True
    assert v["establishment_observed"].value is True
    assert v["rekey_observed"].value is True
    assert v["termination_observed"].value is False
    assert v["failed_negotiation_observed"].value is False
    assert v["average_packet_size"].value == pytest.approx(100.0)


def test_rekey_intervals_need_two_rekeys() -> None:
    v = values(calculate_sa_features(ike_sa()))
    assert v["rekey_count"].value == 2
    assert v["mean_rekey_interval"].value == pytest.approx(30.0)
    assert v["last_rekey_time"].value == "2026-01-01T00:00:50+00:00"

    single = ike_sa(rekey_count=1, events=ike_sa().events[:4])
    v = values(calculate_sa_features(single))
    assert v["rekey_count"].value == 1  # a real count
    assert v["mean_rekey_interval"].availability == "UNAVAILABLE"  # but no interval
    assert v["last_rekey_time"].value == "2026-01-01T00:00:20+00:00"


def test_child_sa_rekey_is_unavailable_not_zero() -> None:
    child = SARecord(
        id="SA-2", type="CHILD", state="ACTIVE", protocol="ESP",
        initiator="192.0.2.10", responder="198.51.100.20",
        packet_count=3, byte_count=300, nat_traversal=False, rekey_count=0,
        events=[SAEvent("SA DETECTED", "2026-01-01T00:00:03+00:00", None, "DETECTED")],
    )
    v = values(calculate_sa_features(child))
    assert v["rekey_count"].value is None
    assert v["rekey_count"].availability == "UNAVAILABLE"
    assert "new child SA" in v["rekey_count"].detail
    assert v["child_sa_count"].availability == "UNAVAILABLE"


def test_partial_sa_lifecycle_without_events() -> None:
    v = values(calculate_sa_features(ike_sa(events=[], rekey_count=0)))
    assert v["state_transition_count"].availability == "UNAVAILABLE"
    assert v["negotiation_observed"].availability == "UNAVAILABLE"
    assert v["rekey_count"].value == 0  # the record's own count is still a fact


def test_failed_negotiation_is_observed_not_judged() -> None:
    failed = ike_sa(
        state="FAILED",
        events=[SAEvent("NEGOTIATION FAILED", "2026-01-01T00:00:05+00:00", "NEGOTIATING", "FAILED")],
    )
    v = values(calculate_sa_features(failed))
    assert v["failed_negotiation_observed"].value is True
    assert v["sa_state"].value == "FAILED"


# ----- packet calculations --------------------------------------------------


def test_packet_features(ike_esp_packets) -> None:
    vector = extract_packet(ike_esp_packets[0], CAPTURE, session_source="192.0.2.10", session_id="S1")
    v = vector_values(vector)
    assert v["is_ike"].value is True
    assert v["is_esp"].value is False
    assert v["ip_version"].value == 4
    assert v["transport_protocol"].value == "UDP"
    assert v["source_port"].value == 500
    assert v["direction"].value == "OUTBOUND"
    assert v["ike_exchange_name"].value == "IKE_SA_INIT"
    assert v["sequence_number"].availability == "UNAVAILABLE"


def test_packet_direction_is_unknown_without_a_session(ike_esp_packets) -> None:
    v = vector_values(extract_packet(ike_esp_packets[0], CAPTURE))
    assert v["direction"].value is None
    assert v["direction"].availability == "UNAVAILABLE"
    assert "address ordering" in v["direction"].detail


def test_esp_packet_exposes_spi_and_sequence(ike_esp_packets) -> None:
    v = vector_values(extract_packet(ike_esp_packets[2], CAPTURE))
    assert v["is_esp"].value is True
    assert v["spi_present"].value is True
    assert v["sequence_number"].value == 1
    assert v["ike_version"].availability == "UNAVAILABLE"


def test_non_ipsec_packet_reports_no_ipsec() -> None:
    packets = decode([B.ethernet(B.ipv4(B.tcp(), 6))])
    v = vector_values(extract_packet(packets[0], CAPTURE))
    assert v["is_ike"].value is False
    assert v["spi_present"].value is False
    assert v["ipsec_protocol"].availability == "UNAVAILABLE"
    assert v["transport_protocol"].value == "TCP"


# ----- vector-level guarantees ---------------------------------------------


def test_vectors_are_complete_and_ordered(ike_esp_packets) -> None:
    from app.layers.layer05_feature_engineering import definitions_for

    vector = extract_session(session_of(ike_esp_packets), CAPTURE, ike_esp_packets)
    assert [f.name for f in vector.features] == [d.name for d in definitions_for("SESSION")]
    assert vector.feature_version == "1.0"
    assert (
        vector.available_count + vector.partial_count + vector.unavailable_count
        == len(vector.features)
    )


def test_extraction_is_reproducible(ike_esp_packets) -> None:
    record = session_of(ike_esp_packets)
    first = extract_session(record, CAPTURE, ike_esp_packets)
    second = extract_session(record, CAPTURE, ike_esp_packets)
    assert [(f.name, f.value) for f in first.features] == [
        (f.name, f.value) for f in second.features
    ]


def test_no_vector_ever_contains_nan_or_infinity(ike_esp_packets) -> None:
    vectors = [
        extract_session(session_of(ike_esp_packets), CAPTURE, ike_esp_packets),
        extract_session(session_of(ike_esp_packets, duration_seconds=0.0), CAPTURE, ike_esp_packets),
        extract_session(session_of(ike_esp_packets), CAPTURE, None),
        extract_sa(ike_sa(), CAPTURE),
        extract_packet(ike_esp_packets[0], CAPTURE),
    ]
    for vector in vectors:
        for feature in vector.features:
            if isinstance(feature.value, float):
                assert not math.isnan(feature.value)
                assert not math.isinf(feature.value)
            if feature.availability == "UNAVAILABLE":
                assert feature.value is None
                assert feature.detail, feature.name


def test_no_secrets_are_ever_emitted(ike_esp_packets) -> None:
    """SPIs are public header fields; key material must never appear."""
    vector = extract_session(session_of(ike_esp_packets), CAPTURE, ike_esp_packets)
    forbidden = ("psk", "secret", "private_key", "password", "token", "credential", "key_material")
    for feature in vector.features:
        assert not any(word in feature.name.lower() for word in forbidden)
