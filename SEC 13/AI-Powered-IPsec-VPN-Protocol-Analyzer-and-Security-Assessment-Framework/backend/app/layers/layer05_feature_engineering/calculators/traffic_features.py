"""Traffic feature calculation: sizes, rates, bursts, direction and ratios.

Every division here goes through ``safe_divide``, so a zero-duration session
or an empty packet set produces an unavailable feature rather than infinity.
"""

from __future__ import annotations

import math
from typing import Optional, Sequence

from ..registry import BURST_WINDOW_SECONDS
from ..validation import FeatureSet, round_float, safe_divide
from .timing_features import epoch

ZERO_DURATION = (
    "Session duration is zero, so a per-second rate is not defined. "
    "All packets carry the same timestamp or only one packet was observed."
)
NO_DURATION = "No usable duration could be derived from the packet timestamps."


def _median(values: Sequence[int | float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def _variance(values: Sequence[int | float]) -> Optional[float]:
    if not values:
        return None
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def add_packet_size_features(
    fs: FeatureSet,
    lengths: Sequence[int],
    *,
    source: Optional[str] = None,
    unavailable_detail: str,
) -> None:
    """Distribution of on-the-wire packet lengths."""
    names = (
        "median_packet_size",
        "minimum_packet_size",
        "maximum_packet_size",
        "packet_size_variance",
        "packet_size_standard_deviation",
    )
    if not lengths:
        for name in names:
            fs.missing(name, unavailable_detail, source=source)
        return

    variance = _variance(lengths)
    fs.add("median_packet_size", round_float(_median(lengths)), source=source)
    fs.add("minimum_packet_size", int(min(lengths)), source=source)
    fs.add("maximum_packet_size", int(max(lengths)), source=source)
    fs.add("packet_size_variance", round_float(variance), source=source)
    fs.add(
        "packet_size_standard_deviation",
        round_float(math.sqrt(variance) if variance is not None else None),
        source=source,
    )


def add_rate_features(
    fs: FeatureSet,
    *,
    packet_count: int,
    byte_count: int,
    ike_packet_count: int,
    esp_packet_count: int,
    duration_seconds: Optional[float],
    source: Optional[str] = None,
) -> None:
    """Per-second rates, guarded against a zero or missing duration."""
    pairs = (
        ("packets_per_second", packet_count),
        ("bytes_per_second", byte_count),
        ("ike_packets_per_second", ike_packet_count),
        ("esp_packets_per_second", esp_packet_count),
    )
    if duration_seconds is None:
        for name, _ in pairs:
            fs.missing(name, NO_DURATION, source=source)
        return
    if duration_seconds == 0:
        for name, _ in pairs:
            fs.missing(name, ZERO_DURATION, source=source)
        return
    for name, numerator in pairs:
        fs.add_or_missing(
            name,
            round_float(safe_divide(numerator, duration_seconds)),
            ZERO_DURATION,
            source=source,
        )


def add_burst_features(
    fs: FeatureSet,
    timestamps: Sequence[str],
    lengths: Sequence[int],
    *,
    source: Optional[str] = None,
    unavailable_detail: str,
) -> None:
    """Peak load in a fixed tumbling window aligned to the first packet.

    The window is a documented constant rather than a tuned one, and no
    "burst" threshold is applied: deciding which peak counts as unusual needs
    a baseline, which belongs to a later section.
    """
    points = [
        (epoch(ts), length)
        for ts, length in zip(timestamps, lengths)
        if epoch(ts) is not None
    ]
    if not points:
        fs.missing("maximum_packets_in_window", unavailable_detail, source=source)
        fs.missing("maximum_bytes_in_window", unavailable_detail, source=source)
        return

    start = min(t for t, _ in points)
    packets_per_window: dict[int, int] = {}
    bytes_per_window: dict[int, int] = {}
    for moment, length in points:
        index = int((moment - start) // BURST_WINDOW_SECONDS)
        packets_per_window[index] = packets_per_window.get(index, 0) + 1
        bytes_per_window[index] = bytes_per_window.get(index, 0) + int(length)

    detail = f"Peak within a {BURST_WINDOW_SECONDS:g}s tumbling window aligned to the first packet."
    fs.add("maximum_packets_in_window", max(packets_per_window.values()), detail=detail, source=source)
    fs.add("maximum_bytes_in_window", max(bytes_per_window.values()), detail=detail, source=source)


def add_directional_features(
    fs: FeatureSet,
    directions: Sequence[tuple[bool, int]],
    *,
    source: Optional[str] = None,
    unavailable_detail: str,
) -> None:
    """Directional counts and ratios.

    ``directions`` pairs each packet with ``True`` when it travels in the same
    direction as the session's first observed packet. Callers that cannot
    establish that reference pass an empty sequence, and everything here is
    reported unavailable rather than assumed.
    """
    names = (
        "inbound_packets",
        "outbound_packets",
        "inbound_bytes",
        "outbound_bytes",
        "inbound_outbound_packet_ratio",
        "inbound_outbound_byte_ratio",
    )
    if not directions:
        for name in names:
            fs.missing(name, unavailable_detail, source=source)
        return

    outbound_packets = sum(1 for outbound, _ in directions if outbound)
    inbound_packets = sum(1 for outbound, _ in directions if not outbound)
    outbound_bytes = sum(length for outbound, length in directions if outbound)
    inbound_bytes = sum(length for outbound, length in directions if not outbound)

    fs.add("inbound_packets", inbound_packets, source=source)
    fs.add("outbound_packets", outbound_packets, source=source)
    fs.add("inbound_bytes", inbound_bytes, source=source)
    fs.add("outbound_bytes", outbound_bytes, source=source)
    fs.add_or_missing(
        "inbound_outbound_packet_ratio",
        round_float(safe_divide(inbound_packets, outbound_packets)),
        "No outbound packet was observed, so the ratio has no denominator.",
        source=source,
    )
    fs.add_or_missing(
        "inbound_outbound_byte_ratio",
        round_float(safe_divide(inbound_bytes, outbound_bytes)),
        "No outbound bytes were observed, so the ratio has no denominator.",
        source=source,
    )


def add_ipsec_ratio_features(
    fs: FeatureSet,
    *,
    packet_count: int,
    ike_packet_count: int,
    esp_packet_count: int,
    ah_packet_count: int,
    source: Optional[str] = None,
) -> None:
    """IKE, ESP and AH shares of the session's packets."""
    empty = "The session has no packets, so protocol shares have no denominator."
    for name, count in (
        ("ike_ratio", ike_packet_count),
        ("esp_ratio", esp_packet_count),
        ("ah_ratio", ah_packet_count),
    ):
        fs.add_or_missing(name, round_float(safe_divide(count, packet_count)), empty, source=source)


def add_transport_ratio_features(
    fs: FeatureSet,
    transports: Sequence[Optional[str]],
    *,
    source: Optional[str] = None,
    unavailable_detail: str,
) -> None:
    """Shares of the session carried over UDP, over TCP, and directly over IP.

    The third share is the meaningful one for IPsec: it is native ESP or AH,
    as opposed to UDP-encapsulated traffic traversing a NAT.
    """
    names = ("udp_ratio", "tcp_ratio", "other_ratio")
    if not transports:
        for name in names:
            fs.missing(name, unavailable_detail, source=source)
        return

    total = len(transports)
    udp = sum(1 for t in transports if t == "UDP")
    tcp = sum(1 for t in transports if t == "TCP")
    other = total - udp - tcp
    for name, count in (("udp_ratio", udp), ("tcp_ratio", tcp), ("other_ratio", other)):
        fs.add(name, round_float(safe_divide(count, total)), source=source)
