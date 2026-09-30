"""Session-level feature calculation.

Two source tiers feed this calculator, and keeping them apart is the point:

- The stored session record from Section 6 always exists once discovery has
  run, so counts, duration and protocol shares are always calculable.
- The individual packets only exist while the capture that produced the
  session is loaded. Distribution, timing and directional features depend on
  them, so when the capture is gone those features are UNAVAILABLE. They are
  never approximated from the aggregate counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

from ..registry import SRC_SESSION, SRC_SESSION_IKE, SRC_SESSION_PACKETS
from ..validation import FeatureSet, round_float, safe_divide
from .timing_features import add_interarrival_features, duration_between
from .traffic_features import (
    add_burst_features,
    add_directional_features,
    add_ipsec_ratio_features,
    add_packet_size_features,
    add_rate_features,
    add_transport_ratio_features,
)

NO_PACKETS = (
    "The capture that produced this session is not loaded, so its individual "
    "packets are not available for calculation."
)
EMPTY_PACKETS = "No packets are associated with this session."

# Payload names the decoder emits for encrypted IKEv2 containers.
_ENCRYPTED_PAYLOADS = {"SK (Encrypted)", "SKF (Encrypted Fragment)"}
_ENCRYPTED_NOTE = (
    "IKEv2 encrypted (SK) payloads were observed; payloads carried inside them are not "
    "decoded, so this count is a floor rather than a total."
)


@dataclass
class SessionRecord:
    """The stored session, decoupled from the ORM row that carries it."""

    id: str
    source: str
    destination: str
    state: str
    direction: str
    packet_count: int
    byte_count: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    nat_traversal: bool
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    ike_version: Optional[str] = None
    #: `detail_json["ike"]` from Section 6, when the session carried IKE.
    ike_detail: Optional[dict] = field(default=None)
    ipsec_mode: str = "TUNNEL"
    ip_version: int = 4


def calculate_session_features(
    session: SessionRecord,
    packets: Optional[Sequence[PacketAnalysisResult]] = None,
) -> FeatureSet:
    """Features for one correlated IPsec session."""
    fs = FeatureSet("SESSION")
    have_packets = packets is not None
    members = list(packets or [])
    packet_detail = NO_PACKETS if not have_packets else EMPTY_PACKETS

    _add_counts(fs, session)
    _add_timing(fs, session, members, have_packets, packet_detail)
    _add_sizes(fs, session, members, have_packets, packet_detail)
    _add_rates(fs, session)
    _add_direction(fs, session, members, have_packets, packet_detail)
    _add_ratios(fs, session, members, have_packets, packet_detail)
    _add_ike(fs, session, members, have_packets, packet_detail)
    _add_profiling_features(fs, session, members, have_packets, packet_detail)
    return fs


# ----- counts and identity ------------------------------------------------- #


def _add_counts(fs: FeatureSet, session: SessionRecord) -> None:
    fs.add("packet_count", int(session.packet_count))
    fs.add("byte_count", int(session.byte_count))
    fs.add("ike_packet_count", int(session.ike_packets))
    fs.add("esp_packet_count", int(session.esp_packets))
    fs.add("ah_packet_count", int(session.ah_packets))
    fs.add("session_state", session.state)
    fs.add("session_direction", session.direction)
    fs.add("nat_traversal_observed", bool(session.nat_traversal))
    fs.add("ipsec_mode", getattr(session, "ipsec_mode", "TUNNEL"))
    fs.add("ip_version", int(getattr(session, "ip_version", 4)))


# ----- timing --------------------------------------------------------------- #


def _add_timing(
    fs: FeatureSet,
    session: SessionRecord,
    members: list[PacketAnalysisResult],
    have_packets: bool,
    packet_detail: str,
) -> None:
    no_time = "No packet in this session carried a usable timestamp."
    fs.add_or_missing("first_seen", session.start_time, no_time)
    fs.add_or_missing("last_seen", session.end_time, no_time)

    duration = session.duration_seconds
    if duration is None:
        duration = duration_between(session.start_time, session.end_time)
    fs.add_or_missing("session_duration_seconds", round_float(duration), no_time)

    if not have_packets:
        add_interarrival_features(fs, [], source=SRC_SESSION_PACKETS, unavailable_detail=packet_detail)
        return
    add_interarrival_features(
        fs,
        [p.timestamp for p in members if p.timestamp],
        source=SRC_SESSION_PACKETS,
    )


# ----- size distribution ---------------------------------------------------- #


def _add_sizes(
    fs: FeatureSet,
    session: SessionRecord,
    members: list[PacketAnalysisResult],
    have_packets: bool,
    packet_detail: str,
) -> None:
    fs.add_or_missing(
        "average_packet_size",
        round_float(safe_divide(session.byte_count, session.packet_count)),
        "The session has no packets, so a mean size has no denominator.",
        source=SRC_SESSION,
    )
    lengths = [p.original_length for p in members] if have_packets else []
    add_packet_size_features(
        fs,
        lengths,
        source=SRC_SESSION_PACKETS,
        unavailable_detail=packet_detail,
    )


# ----- rates and bursts ------------------------------------------------------ #


def _add_rates(fs: FeatureSet, session: SessionRecord) -> None:
    add_rate_features(
        fs,
        packet_count=int(session.packet_count),
        byte_count=int(session.byte_count),
        ike_packet_count=int(session.ike_packets),
        esp_packet_count=int(session.esp_packets),
        duration_seconds=session.duration_seconds,
        source=SRC_SESSION,
    )


# ----- direction ------------------------------------------------------------- #


def _add_direction(
    fs: FeatureSet,
    session: SessionRecord,
    members: list[PacketAnalysisResult],
    have_packets: bool,
    packet_detail: str,
) -> None:
    if not have_packets:
        add_directional_features(fs, [], source=SRC_SESSION_PACKETS, unavailable_detail=packet_detail)
        add_burst_features(fs, [], [], source=SRC_SESSION_PACKETS, unavailable_detail=packet_detail)
        return

    # Outbound means "same direction as the session's first observed packet".
    # Packets with no IP layer cannot be placed and are left out entirely
    # rather than defaulted into one side.
    directions = [
        (p.ip.source == session.source, p.original_length)
        for p in members
        if p.ip is not None
    ]
    add_directional_features(
        fs,
        directions,
        source=SRC_SESSION_PACKETS,
        unavailable_detail="No session packet carries a decoded IP layer, so direction cannot be established.",
    )
    add_burst_features(
        fs,
        [p.timestamp for p in members if p.timestamp],
        [p.original_length for p in members if p.timestamp],
        source=SRC_SESSION_PACKETS,
        unavailable_detail="No session packet carries a usable timestamp.",
    )


# ----- protocol ratios -------------------------------------------------------- #


def _add_ratios(
    fs: FeatureSet,
    session: SessionRecord,
    members: list[PacketAnalysisResult],
    have_packets: bool,
    packet_detail: str,
) -> None:
    add_ipsec_ratio_features(
        fs,
        packet_count=int(session.packet_count),
        ike_packet_count=int(session.ike_packets),
        esp_packet_count=int(session.esp_packets),
        ah_packet_count=int(session.ah_packets),
        source=SRC_SESSION,
    )
    transports = (
        [getattr(p.transport, "kind", None) for p in members] if have_packets else []
    )
    add_transport_ratio_features(
        fs,
        transports,
        source=SRC_SESSION_PACKETS,
        unavailable_detail=packet_detail,
    )


# ----- IKE -------------------------------------------------------------------- #


def _add_ike(
    fs: FeatureSet,
    session: SessionRecord,
    members: list[PacketAnalysisResult],
    have_packets: bool,
    packet_detail: str,
) -> None:
    detail = session.ike_detail or {}
    exchange_types: list[str] = list(detail.get("exchange_types") or [])
    payload_types: list[str] = list(detail.get("payload_types") or [])
    has_ike = int(session.ike_packets) > 0

    no_ike = "No IKE message was observed in this session."
    fs.add_or_missing("ike_version", session.ike_version, no_ike, source=SRC_SESSION)
    fs.add("ike_message_count", int(session.ike_packets), source=SRC_SESSION)
    fs.add("unique_exchange_types", len(exchange_types), source=SRC_SESSION_IKE)

    # Whether an exchange or a visible payload was seen is answerable from the
    # stored record: absence of IKE is itself a complete observation, so these
    # are False rather than unavailable.
    encrypted_seen = any(name in _ENCRYPTED_PAYLOADS for name in payload_types)
    no_ike_note = no_ike if not has_ike else None

    for name, needle in (
        ("ike_sa_init_observed", "IKE_SA_INIT"),
        ("ike_auth_observed", "IKE_AUTH"),
        ("create_child_sa_observed", "CREATE_CHILD_SA"),
    ):
        fs.add(
            name,
            any(needle == exchange.upper() for exchange in exchange_types),
            detail=no_ike_note,
            source=SRC_SESSION_IKE,
        )
    fs.add(
        "informational_exchange_observed",
        any("INFORMATIONAL" in exchange.upper() for exchange in exchange_types),
        detail=no_ike_note,
        source=SRC_SESSION_IKE,
    )
    for name, needle in (
        ("delete_payload_observed", "DELETE"),
        ("notify_payload_observed", "NOTIFY"),
    ):
        fs.add(
            name,
            any(needle == payload.upper() for payload in payload_types),
            detail=no_ike_note,
            source=SRC_SESSION_IKE,
            partial=encrypted_seen,
            partial_detail=_ENCRYPTED_NOTE if encrypted_seen else None,
        )

    if not have_packets:
        for name in (
            "ike_exchange_count",
            "ike_payload_count",
            "notify_payload_count",
            "delete_payload_count",
            "retransmission_count",
        ):
            fs.missing(name, packet_detail, source=SRC_SESSION_PACKETS)
        return

    ike_layers = [
        (p, p.ipsec.ike) for p in members if p.ipsec is not None and p.ipsec.ike is not None
    ]
    if not ike_layers:
        for name in ("ike_exchange_count", "ike_payload_count", "notify_payload_count", "delete_payload_count"):
            fs.add(name, 0, detail=no_ike, source=SRC_SESSION_PACKETS)
        fs.missing("retransmission_count", no_ike, source=SRC_SESSION_PACKETS)
        return

    encrypted_here = any(layer.encrypted_payload for _, layer in ike_layers)
    partial_note = _ENCRYPTED_NOTE if encrypted_here else None

    fs.add(
        "ike_exchange_count",
        len({(layer.exchange_name, layer.message_id) for _, layer in ike_layers}),
        source=SRC_SESSION_PACKETS,
    )
    fs.add(
        "ike_payload_count",
        sum(layer.payload_count for _, layer in ike_layers),
        source=SRC_SESSION_PACKETS,
        partial=encrypted_here,
        partial_detail=partial_note,
    )
    for name, needle in (("notify_payload_count", "NOTIFY"), ("delete_payload_count", "DELETE")):
        fs.add(
            name,
            sum(1 for _, layer in ike_layers for payload in layer.payloads if payload.name.upper() == needle),
            source=SRC_SESSION_PACKETS,
            partial=encrypted_here,
            partial_detail=partial_note,
        )

    fs.add_or_missing(
        "retransmission_count",
        _retransmissions(ike_layers),
        "Retransmissions are only counted for IKEv2, where a message ID is unique per exchange "
        "and direction. This session is not IKEv2, so repeats cannot be distinguished from "
        "distinct exchanges.",
        source=SRC_SESSION_PACKETS,
    )


def _retransmissions(ike_layers: list[tuple[PacketAnalysisResult, object]]) -> Optional[int]:
    """Repeat IKEv2 messages, or None when the evidence cannot support a count.

    An IKEv2 message ID identifies one exchange in one direction, so a second
    message carrying the same ID from the same address is a retransmission.
    IKEv1 reuses message ID 0 across all of Phase 1, which would turn ordinary
    exchanges into false retransmissions, so IKEv1 returns None instead.
    """
    if not all(getattr(layer, "major_version", None) == 2 for _, layer in ike_layers):
        return None
    seen: dict[tuple[str, int, str], int] = {}
    for packet, layer in ike_layers:
        if packet.ip is None:
            return None
        key = (packet.ip.source, getattr(layer, "message_id"), getattr(layer, "exchange_name"))
        seen[key] = seen.get(key, 0) + 1
    return sum(count - 1 for count in seen.values() if count > 1)


def _add_profiling_features(
    fs: FeatureSet,
    session: SessionRecord,
    members: list[PacketAnalysisResult],
    have_packets: bool,
    packet_detail: str,
) -> None:
    if not have_packets or not members:
        fs.missing("iat_coefficient_of_variation", packet_detail)
        fs.missing("small_packet_ratio", packet_detail)
        fs.missing("mtu_packet_ratio", packet_detail)
        fs.missing("chunk_burst_periodicity", packet_detail)
        fs.missing("mos_score_estimate", packet_detail)
        return

    # 1. Packet size ratios
    total = len(members)
    small_count = sum(1 for p in members if p.original_length <= 160)
    mtu_count = sum(1 for p in members if p.original_length >= 1200)
    fs.add("small_packet_ratio", round_float(safe_divide(small_count, total) or 0.0), source=SRC_SESSION_PACKETS)
    fs.add("mtu_packet_ratio", round_float(safe_divide(mtu_count, total) or 0.0), source=SRC_SESSION_PACKETS)

    # 2. IAT coefficient of variation & MOS score
    from .timing_features import interarrival_gaps, epoch
    timestamps = [p.timestamp for p in members if p.timestamp]
    gaps = interarrival_gaps(timestamps) if len(timestamps) >= 2 else []
    if len(gaps) >= 2:
        mean_iat = sum(gaps) / len(gaps)
        var_iat = sum((g - mean_iat) ** 2 for g in gaps) / len(gaps)
        std_iat = var_iat ** 0.5
        cv = safe_divide(std_iat, mean_iat)
        fs.add_or_missing("iat_coefficient_of_variation", round_float(cv), "Could not compute IAT coefficient of variation.", source=SRC_SESSION_PACKETS)

        # Estimate MOS score (ITU-T G.107 E-model approximation for VoIP)
        jitter_ms = std_iat * 1000.0
        delay_penalty = min(30.0, jitter_ms * 0.8)
        r_val = max(0.0, min(100.0, 93.2 - delay_penalty))
        if r_val <= 0:
            mos = 1.0
        elif r_val >= 100:
            mos = 4.5
        else:
            mos = 1.0 + 0.035 * r_val + r_val * (r_val - 60.0) * (100.0 - r_val) * 7e-6
            mos = max(1.0, min(4.5, mos))
        fs.add("mos_score_estimate", round_float(mos), source=SRC_SESSION_PACKETS)
    else:
        fs.missing("iat_coefficient_of_variation", "At least two timestamped packets are needed for IAT CV.")
        fs.missing("mos_score_estimate", "At least two timestamped packets are needed for MOS estimation.")

    # 3. Chunk burst periodicity (video streaming analysis)
    if len(timestamps) >= 10:
        times = sorted(t for t in (epoch(ts) for ts in timestamps) if t is not None)
        if len(times) >= 10:
            t0 = times[0]
            buckets: dict[int, int] = {}
            for t in times:
                sec = int(t - t0)
                buckets[sec] = buckets.get(sec, 0) + 1
            mean_b = sum(buckets.values()) / max(1, len(buckets))
            peaks = [sec for sec, cnt in sorted(buckets.items()) if cnt > mean_b * 1.5]
            if len(peaks) >= 2:
                peak_gaps = [peaks[i] - peaks[i-1] for i in range(1, len(peaks))]
                periodicity = sum(peak_gaps) / len(peak_gaps)
                fs.add("chunk_burst_periodicity", round_float(periodicity), source=SRC_SESSION_PACKETS)
            else:
                fs.missing("chunk_burst_periodicity", "Insufficient periodic chunk peaks observed in flow.")
        else:
            fs.missing("chunk_burst_periodicity", "Not enough timestamps for chunk periodicity.")
    else:
        fs.missing("chunk_burst_periodicity", "Flow packet count too small for burst periodicity.")
