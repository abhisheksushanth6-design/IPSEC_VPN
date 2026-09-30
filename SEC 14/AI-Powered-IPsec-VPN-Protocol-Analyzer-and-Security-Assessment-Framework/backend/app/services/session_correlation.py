"""IPsec session correlation.

Groups decoded IPsec packets (IKE, ESP, AH) into logical sessions using only
what the packets themselves carry. This is a supporting analysis module; it
is not the SA lifecycle engine (Layer 04) and makes no security judgement.

Correlation rules, in order:

1. Only packets with a decoded IPsec layer and parse_status OK participate.
   Everything else — TCP, plain UDP, ICMP, malformed frames — is outside any
   session.
2. A session is bounded by an unordered endpoint pair {A, B}. An IKE SA and
   the child SAs it negotiates run between the same two hosts, so the pair
   is the one identifier every IPsec packet of a session shares. Binding a
   given ESP SPI to a specific IKE SA needs the negotiated SA parameters,
   which is Layer 04 work; here ESP/AH packets are attached to the pair.
3. Within a pair, an inactivity gap longer than INACTIVITY_GAP_SECONDS
   starts a new session. Packets without timestamps never split a session.
4. State comes from observed exchanges only (see `_determine_state`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Literal, Optional

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

INACTIVITY_GAP_SECONDS = 300.0
ACTIVITY_BUCKETS = 24
MAX_SESSION_PACKET_REFS = 50_000

SessionState = Literal["DISCOVERED", "NEGOTIATING", "ESTABLISHED", "ACTIVE", "IDLE", "TERMINATED", "UNKNOWN"]
SessionDirection = Literal["OUTBOUND", "INBOUND", "BIDIRECTIONAL", "UNKNOWN"]
Correlation = Literal["DIRECT", "CORRELATED", "PARTIAL", "UNKNOWN"]

IKEV2_DELETE = 42
IKEV1_DELETE = 12


@dataclass
class TimelineEvent:
    timestamp: Optional[str]
    packet_number: int
    label: str
    detail: str


@dataclass
class IKEInfo:
    version: Optional[str]
    initiator_spis: list[str]
    responder_spis: list[str]
    exchange_types: list[str]
    message_ids: list[int]
    payload_types: list[str]
    packet_count: int
    nat_traversal: bool


@dataclass
class SPIInfo:
    """Per-SPI observation for ESP or AH."""

    spi: str
    direction: str  # "A→B" style expressed as source→destination of that SPI
    packet_count: int
    sequence_min: int
    sequence_max: int
    nat_traversal: bool


@dataclass
class DataPlaneInfo:
    spis: list[SPIInfo]
    packet_count: int


@dataclass
class ActivityPoint:
    timestamp: str
    packets: int


@dataclass
class Session:
    id: str
    ordinal: int
    source: str
    destination: str
    direction: SessionDirection
    state: SessionState
    correlation: Correlation
    start_time: Optional[str]
    end_time: Optional[str]
    duration_seconds: Optional[float]
    packet_count: int
    byte_count: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    ike_version: Optional[str]
    nat_traversal: bool
    ike: Optional[IKEInfo]
    esp: Optional[DataPlaneInfo]
    ah: Optional[DataPlaneInfo]
    timeline: list[TimelineEvent]
    activity: list[ActivityPoint]
    packet_numbers: list[int] = field(default_factory=list)
    packet_roles: dict[int, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    ipsec_mode: str = "TUNNEL"
    ip_version: int = 4


def correlate(packets: Iterable[PacketAnalysisResult], capture_id: str) -> list[Session]:
    """Derive sessions from decoded packets. Deterministic for a given capture."""
    ipsec = [p for p in packets if p.ipsec is not None and p.parse_status == "OK" and p.ip is not None]
    ipsec.sort(key=lambda p: (p.timestamp or "", p.number))

    groups: dict[tuple[str, str], list[list[PacketAnalysisResult]]] = {}
    last_seen: dict[tuple[str, str], Optional[float]] = {}

    for packet in ipsec:
        pair = _pair(packet)
        ts = _epoch(packet.timestamp)
        buckets = groups.setdefault(pair, [])
        previous = last_seen.get(pair)
        if not buckets or (ts is not None and previous is not None and ts - previous > INACTIVITY_GAP_SECONDS):
            buckets.append([])
        buckets[-1].append(packet)
        if ts is not None:
            last_seen[pair] = ts

    sessions: list[Session] = []
    ordered = sorted(
        ((pair, members) for pair, buckets in groups.items() for members in buckets),
        key=lambda item: (item[1][0].timestamp or "", item[1][0].number),
    )
    for ordinal, (pair, members) in enumerate(ordered, start=1):
        session = _build_session(capture_id, ordinal, pair, members)
        sessions.append(session)
    return sessions


# --------------------------------------------------------------------------- #


def _pair(packet: PacketAnalysisResult) -> tuple[str, str]:
    a, b = packet.ip.source, packet.ip.destination  # type: ignore[union-attr]
    return (a, b) if a <= b else (b, a)


def _epoch(iso: str) -> Optional[float]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return None


def _build_session(
    capture_id: str,
    ordinal: int,
    pair: tuple[str, str],
    members: list[PacketAnalysisResult],
) -> Session:
    ike_pkts = [p for p in members if p.ipsec and p.ipsec.type == "IKE"]
    esp_pkts = [p for p in members if p.ipsec and p.ipsec.type == "ESP"]
    ah_pkts = [p for p in members if p.ipsec and p.ipsec.type == "AH"]

    source, destination = _orient(pair, ike_pkts, members)
    direction = _direction(members, source, destination)
    timestamps = [p.timestamp for p in members if p.timestamp]
    start = min(timestamps) if timestamps else None
    end = max(timestamps) if timestamps else None
    duration = None
    if start and end:
        s, e = _epoch(start), _epoch(end)
        duration = round(e - s, 6) if s is not None and e is not None else None

    ike_info = _ike_info(ike_pkts) if ike_pkts else None
    esp_info = _dataplane_info(esp_pkts) if esp_pkts else None
    ah_info = _dataplane_info(ah_pkts) if ah_pkts else None
    state, evidence = _determine_state(ike_pkts, esp_pkts, ah_pkts)
    correlation = _correlation(members, ike_info, esp_info, ah_info)

    has_transport = any(
        (p.ipsec and getattr(p.ipsec, "encapsulation_mode", "TUNNEL") == "TRANSPORT")
        or (p.ipsec and p.ipsec.ah and p.ipsec.ah.next_header in (1, 6, 17, 58))
        for p in members
    )
    ipsec_mode = "TRANSPORT" if has_transport else "TUNNEL"
    ip_version = 6 if any(p.ip and p.ip.version == 6 for p in members) else 4

    seed = f"{capture_id}|{pair[0]}|{pair[1]}|{start or ''}|{ordinal}"
    session_id = "IPSEC-" + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()

    return Session(
        id=session_id,
        ordinal=ordinal,
        source=source,
        destination=destination,
        direction=direction,
        state=state,
        correlation=correlation,
        start_time=start,
        end_time=end,
        duration_seconds=duration,
        packet_count=len(members),
        byte_count=sum(p.original_length for p in members),
        ike_packets=len(ike_pkts),
        esp_packets=len(esp_pkts),
        ah_packets=len(ah_pkts),
        ike_version=ike_info.version if ike_info else None,
        nat_traversal=any(p.ipsec.nat_traversal for p in members if p.ipsec),
        ipsec_mode=ipsec_mode,
        ip_version=ip_version,
        ike=ike_info,
        esp=esp_info,
        ah=ah_info,
        timeline=_timeline(members, ike_pkts, esp_pkts, ah_pkts),
        activity=_activity(members, start, end),
        packet_numbers=[p.number for p in members][:MAX_SESSION_PACKET_REFS],
        packet_roles={p.number: p.ipsec.type for p in members if p.ipsec},
        evidence=evidence,
    )


def _orient(pair: tuple[str, str], ike_pkts: list[PacketAnalysisResult], members: list[PacketAnalysisResult]) -> tuple[str, str]:
    """Source is the IKE initiator when an Initiator-flagged message exists; else the first packet's sender."""
    for p in ike_pkts:
        if p.ipsec and p.ipsec.ike and "Initiator" in p.ipsec.ike.flags and p.ip:
            return p.ip.source, p.ip.destination
    first = members[0]
    return (first.ip.source, first.ip.destination) if first.ip else pair


def _direction(members: list[PacketAnalysisResult], source: str, destination: str) -> SessionDirection:
    forward = any(p.ip and p.ip.source == source and p.ip.destination == destination for p in members)
    reverse = any(p.ip and p.ip.source == destination and p.ip.destination == source for p in members)
    if forward and reverse:
        return "BIDIRECTIONAL"
    if forward:
        return "OUTBOUND"
    if reverse:
        return "INBOUND"
    return "UNKNOWN"


def _ike_info(ike_pkts: list[PacketAnalysisResult]) -> IKEInfo:
    layers = [p.ipsec.ike for p in ike_pkts if p.ipsec and p.ipsec.ike]
    versions = sorted({l.version for l in layers})
    return IKEInfo(
        version=versions[0] if len(versions) == 1 else ("/".join(versions) if versions else None),
        initiator_spis=_unique(l.initiator_spi for l in layers),
        responder_spis=_unique(l.responder_spi for l in layers if l.responder_spi != "0" * 16),
        exchange_types=_unique(l.exchange_name for l in layers),
        message_ids=sorted({l.message_id for l in layers}),
        payload_types=_unique(pl.name for l in layers for pl in l.payloads),
        packet_count=len(ike_pkts),
        nat_traversal=any(p.ipsec.nat_traversal for p in ike_pkts if p.ipsec),
    )


def _dataplane_info(pkts: list[PacketAnalysisResult]) -> DataPlaneInfo:
    by_spi: dict[str, list[PacketAnalysisResult]] = {}
    for p in pkts:
        layer = p.ipsec.esp or p.ipsec.ah  # type: ignore[union-attr]
        if layer:
            by_spi.setdefault(layer.spi, []).append(p)
    spis = []
    for spi, group in by_spi.items():
        seqs = [(g.ipsec.esp or g.ipsec.ah).sequence_number for g in group]  # type: ignore[union-attr]
        first = group[0]
        spis.append(SPIInfo(
            spi=spi,
            direction=f"{first.ip.source} → {first.ip.destination}" if first.ip else "unknown",
            packet_count=len(group),
            sequence_min=min(seqs),
            sequence_max=max(seqs),
            nat_traversal=any(g.ipsec.nat_traversal for g in group if g.ipsec),
        ))
    spis.sort(key=lambda s: s.spi)
    return DataPlaneInfo(spis=spis, packet_count=len(pkts))


def _determine_state(ike_pkts, esp_pkts, ah_pkts) -> tuple[SessionState, list[str]]:
    """Every state cites the packet evidence that produced it."""
    evidence: list[str] = []
    exchanges = [(p.ipsec.ike, p) for p in ike_pkts if p.ipsec and p.ipsec.ike]

    # Explicit termination: a plaintext DELETE payload in the last IKE message.
    if exchanges:
        last_ike, last_pkt = exchanges[-1]
        delete_types = {IKEV2_DELETE} if last_ike.major_version == 2 else {IKEV1_DELETE}
        if any(pl.type_number in delete_types for pl in last_ike.payloads):
            evidence.append(f"Packet {last_pkt.number}: {last_ike.exchange_name} carries a DELETE payload.")
            return "TERMINATED", evidence

    if esp_pkts or ah_pkts:
        kinds = " and ".join(k for k, v in (("ESP", esp_pkts), ("AH", ah_pkts)) if v)
        evidence.append(f"{len(esp_pkts) + len(ah_pkts)} {kinds} data packets observed: a child SA carried traffic.")
        return "ACTIVE", evidence

    if not exchanges:
        return "UNKNOWN", ["No IKE, ESP or AH evidence could be classified."]

    names = [ike.exchange_name for ike, _ in exchanges]
    auth_response = any(
        ike.exchange_name == "IKE_AUTH" and "Response" in ike.flags for ike, _ in exchanges
    )
    v1_quick_mode = any(ike.exchange_name == "Quick Mode" for ike, _ in exchanges)
    if auth_response or v1_quick_mode:
        evidence.append("IKE_AUTH response observed." if auth_response else "IKEv1 Quick Mode observed.")
        return "ESTABLISHED", evidence

    if any(n in ("IKE_SA_INIT", "IKE_AUTH", "Identity Protection (Main Mode)", "Aggressive", "Base") for n in names):
        evidence.append(f"Negotiation exchanges observed ({', '.join(_unique(names))}) without an authenticated response or data traffic.")
        return "NEGOTIATING", evidence

    evidence.append(f"Only {', '.join(_unique(names))} exchanges observed; establishment cannot be inferred.")
    return "DISCOVERED", evidence


def _correlation(members, ike_info, esp_info, ah_info) -> Correlation:
    if any(not p.timestamp for p in members):
        return "PARTIAL"
    contexts = 0
    if ike_info:
        contexts += len(ike_info.initiator_spis)
    if esp_info:
        contexts += len(esp_info.spis)
    if ah_info:
        contexts += len(ah_info.spis)
    if contexts == 0:
        return "UNKNOWN"
    # A single IKE SA plus at most two data SPIs (one per direction) is directly attributable.
    ike_contexts = len(ike_info.initiator_spis) if ike_info else 0
    data_contexts = (len(esp_info.spis) if esp_info else 0) + (len(ah_info.spis) if ah_info else 0)
    if ike_contexts <= 1 and data_contexts <= 2:
        return "DIRECT"
    return "CORRELATED"


def _timeline(members, ike_pkts, esp_pkts, ah_pkts) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    first, last = members[0], members[-1]
    events.append(TimelineEvent(first.timestamp or None, first.number, "First packet", first.info))
    if ike_pkts:
        p = ike_pkts[0]
        events.append(TimelineEvent(p.timestamp or None, p.number, "IKE detected", p.info))
        for q in ike_pkts:
            ike = q.ipsec.ike  # type: ignore[union-attr]
            if ike and ike.exchange_name == "IKE_AUTH":
                events.append(TimelineEvent(q.timestamp or None, q.number, "IKE_AUTH observed", q.info))
                break
        for q in ike_pkts:
            ike = q.ipsec.ike  # type: ignore[union-attr]
            if ike and any(pl.type_number in (IKEV2_DELETE, IKEV1_DELETE) for pl in ike.payloads):
                events.append(TimelineEvent(q.timestamp or None, q.number, "Termination observed", q.info))
                break
    data = sorted(esp_pkts + ah_pkts, key=lambda p: (p.timestamp or "", p.number))
    if data:
        events.append(TimelineEvent(data[0].timestamp or None, data[0].number, "IPsec traffic", data[0].info))
    nat = next((p for p in members if p.ipsec and p.ipsec.nat_traversal), None)
    if nat:
        events.append(TimelineEvent(nat.timestamp or None, nat.number, "NAT-T observed", f"UDP/{nat.ipsec.udp_port}"))  # type: ignore[union-attr]
    if last is not first:
        events.append(TimelineEvent(last.timestamp or None, last.number, "Last packet", last.info))
    events.sort(key=lambda e: (e.timestamp or "", e.packet_number))
    return events


def _activity(members, start: Optional[str], end: Optional[str]) -> list[ActivityPoint]:
    """Packet counts in fixed time buckets. Empty when timestamps are absent."""
    s, e = _epoch(start or ""), _epoch(end or "")
    if s is None or e is None:
        return []
    span = max(e - s, 1e-6)
    width = span / ACTIVITY_BUCKETS
    counts = [0] * ACTIVITY_BUCKETS
    for p in members:
        t = _epoch(p.timestamp)
        if t is None:
            continue
        index = min(int((t - s) / width), ACTIVITY_BUCKETS - 1)
        counts[index] += 1
    return [
        ActivityPoint(datetime.fromtimestamp(s + i * width, tz=datetime.fromisoformat(start).tzinfo).isoformat(timespec="milliseconds"), c)  # type: ignore[arg-type]
        for i, c in enumerate(counts)
    ]


def _unique(values: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for v in values:
        if v not in seen:
            seen.append(v)
    return seen
