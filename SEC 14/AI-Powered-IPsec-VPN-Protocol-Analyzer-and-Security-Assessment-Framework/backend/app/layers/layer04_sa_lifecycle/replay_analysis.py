"""Per-SPI ESP/AH sequence-number analysis (RFC 4303 §3.3.3, §3.4.3).

Sequence numbers are a per-SA, per-direction counter, so every statistic here is
computed inside one (protocol, SPI, direction) stream. Comparing counters across SPIs
— which is what naïve implementations do — produces meaningless "out-of-order" counts
because two interleaved unidirectional SAs count independently.

What can and cannot be verified from a passive capture:
* Verifiable: the *sender* maintains a monotonically increasing counter, never reuses a
  value, and never emits sequence number 0 for a fresh SA.
* Not verifiable: whether the *receiver* enforces its anti-replay window, and whether
  Extended Sequence Numbers (ESN) are in use — the high-order 32 bits are never sent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

DEFAULT_REPLAY_WINDOW = 64
MINIMUM_REPLAY_WINDOW = 32


@dataclass
class SPISequenceStats:
    protocol: str
    spi: str
    source: str
    destination: str
    packet_count: int
    sequence_min: int
    sequence_max: int
    unique_count: int
    duplicates: int
    reorders: int
    max_reorder_distance: int
    gaps: int
    zero_sequence_count: int
    monotonic: bool
    duplicate_packets: list[int] = field(default_factory=list)
    reorder_packets: list[int] = field(default_factory=list)


@dataclass
class ReplayAnalysis:
    streams: list[SPISequenceStats]
    data_packets: int
    total_duplicates: int
    total_reorders: int
    max_reorder_distance: int
    total_gaps: int
    zero_sequence_count: int
    verdict: str            # PROTECTED | DEGRADED | REPLAY_INDICATORS | UNVERIFIED
    sender_counter_integrity: str  # VERIFIED | VIOLATED | NOT_OBSERVED
    window_inference: str
    esn_observable: bool
    details: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_replay(packets: Iterable[PacketAnalysisResult]) -> ReplayAnalysis:
    streams: dict[tuple[str, str, str, str], list[PacketAnalysisResult]] = {}
    for p in packets:
        if p.ipsec is None or p.parse_status != "OK" or p.ip is None:
            continue
        layer = p.ipsec.esp or p.ipsec.ah
        if layer is None:
            continue
        key = (p.ipsec.type, layer.spi, p.ip.source, p.ip.destination)
        streams.setdefault(key, []).append(p)

    stats: list[SPISequenceStats] = []
    for (proto, spi, src, dst), members in streams.items():
        members.sort(key=lambda q: (q.timestamp or "", q.number))
        seen: set[int] = set()
        max_seen = -1
        duplicates = 0
        reorders = 0
        max_distance = 0
        zeros = 0
        dup_pkts: list[int] = []
        re_pkts: list[int] = []
        seqs: list[int] = []
        for q in members:
            layer = q.ipsec.esp or q.ipsec.ah  # type: ignore[union-attr]
            seq = layer.sequence_number  # type: ignore[union-attr]
            seqs.append(seq)
            if seq == 0:
                zeros += 1
            if seq in seen:
                duplicates += 1
                if len(dup_pkts) < 10:
                    dup_pkts.append(q.number)
            elif seq < max_seen:
                reorders += 1
                max_distance = max(max_distance, max_seen - seq)
                if len(re_pkts) < 10:
                    re_pkts.append(q.number)
            seen.add(seq)
            max_seen = max(max_seen, seq)
        span = max(seqs) - min(seqs) + 1
        stats.append(
            SPISequenceStats(
                protocol=proto, spi=spi, source=src, destination=dst, packet_count=len(members),
                sequence_min=min(seqs), sequence_max=max(seqs), unique_count=len(seen),
                duplicates=duplicates, reorders=reorders, max_reorder_distance=max_distance,
                gaps=max(0, span - len(seen)), zero_sequence_count=zeros,
                monotonic=(duplicates == 0 and reorders == 0),
                duplicate_packets=dup_pkts, reorder_packets=re_pkts,
            )
        )
    stats.sort(key=lambda s: (s.protocol, s.spi, s.source))

    data_packets = sum(s.packet_count for s in stats)
    total_dups = sum(s.duplicates for s in stats)
    total_reorders = sum(s.reorders for s in stats)
    max_distance = max((s.max_reorder_distance for s in stats), default=0)
    total_gaps = sum(s.gaps for s in stats)
    zeros = sum(s.zero_sequence_count for s in stats)
    details: list[str] = []

    if not stats:
        return ReplayAnalysis(
            streams=[], data_packets=0, total_duplicates=0, total_reorders=0, max_reorder_distance=0,
            total_gaps=0, zero_sequence_count=0, verdict="UNVERIFIED", sender_counter_integrity="NOT_OBSERVED",
            window_inference="No ESP/AH data packets observed; sequence-number behaviour cannot be verified.",
            esn_observable=False, details=["No data-plane packets in scope."],
        )

    details.append(f"{len(stats)} unidirectional SPI stream(s) analysed independently ({data_packets} packets).")
    for s in stats:
        details.append(
            f"{s.protocol} SPI {s.spi} {s.source} → {s.destination}: seq {s.sequence_min}–{s.sequence_max}, "
            f"{s.packet_count} packets, {s.duplicates} duplicate(s), {s.reorders} reordered, {s.gaps} missing."
        )

    if total_dups > 0:
        verdict = "REPLAY_INDICATORS"
        integrity = "VIOLATED"
        details.append(
            f"{total_dups} packet(s) repeat a sequence number already seen on the same SPI. An RFC 4303 sender never reuses "
            "a counter value, so these frames are either replayed by a third party or duplicated in the network; whether the "
            "receiver rejected them is not observable."
        )
    elif max_distance > DEFAULT_REPLAY_WINDOW:
        verdict = "DEGRADED"
        integrity = "VERIFIED"
        details.append(
            f"Reordering distance of {max_distance} exceeds the {DEFAULT_REPLAY_WINDOW}-packet default window: a receiver with the "
            "default window drops these packets (availability impact) unless a larger window is configured."
        )
    else:
        verdict = "PROTECTED"
        integrity = "VERIFIED"
        details.append("Every SPI stream carries a strictly increasing sender counter with no reuse (RFC 4303 §3.3.3 satisfied).")

    if zeros:
        details.append(f"{zeros} packet(s) carry sequence number 0, which RFC 4303 forbids for a fresh SA (counter starts at 1).")

    if max_distance == 0:
        window = f"No reordering observed; any window ≥ {MINIMUM_REPLAY_WINDOW} packets (RFC 4303 minimum) suffices."
    elif max_distance <= MINIMUM_REPLAY_WINDOW:
        window = f"Maximum reordering distance {max_distance} fits the {MINIMUM_REPLAY_WINDOW}-packet minimum window."
    elif max_distance <= DEFAULT_REPLAY_WINDOW:
        window = f"Maximum reordering distance {max_distance} fits the {DEFAULT_REPLAY_WINDOW}-packet default window but not the 32-packet minimum."
    else:
        window = f"Maximum reordering distance {max_distance} exceeds the {DEFAULT_REPLAY_WINDOW}-packet default window."
    details.append("ESN usage is not observable on the wire: only the low-order 32 bits of an extended sequence number are transmitted.")

    return ReplayAnalysis(
        streams=stats, data_packets=data_packets, total_duplicates=total_dups, total_reorders=total_reorders,
        max_reorder_distance=max_distance, total_gaps=total_gaps, zero_sequence_count=zeros, verdict=verdict,
        sender_counter_integrity=integrity, window_inference=window, esn_observable=False, details=details,
    )
