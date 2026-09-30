"""Layer 04 — Security State & SA Lifecycle Engine.

Derives Security Associations and their lifecycle from decoded packets. Every
state transition cites the packet that caused it, and the engine only moves
on evidence the decoder actually exposes: IKE headers, the IKE payload
*chain* (names, not contents), and ESP/AH SPIs with sequence numbers.

Things this engine deliberately does not do, because the evidence is absent:

- It never marks EXPIRED. Lifetimes are negotiated inside payloads the
  decoder does not read, and silence is not expiry.
- It never marks TERMINATED because a capture ended.
- It never reads IKEv2 content carried inside SK payloads, so a DELETE or a
  failure NOTIFY hidden there is not seen and not guessed at.
- It never calls a new SPI a rekey on its own; a rekey needs a rekey exchange.

Identity:
    IKE SA   = (capture, endpoint pair, initiator SPI)
    Child SA = (capture, endpoint pair, protocol, SPI)  — one direction each
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Literal, Optional

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

SAType = Literal["IKE", "CHILD", "UNKNOWN"]
SAState = Literal["UNKNOWN", "DETECTED", "NEGOTIATING", "ESTABLISHED", "ACTIVE", "REKEYING", "EXPIRED", "TERMINATED", "FAILED"]

IKEV2_DELETE, IKEV1_DELETE = 42, 12
IKEV2_NOTIFY, IKEV1_NOTIFY = 41, 11
IKEV2_SA, IKEV1_SA = 33, 1

NEGOTIATION_EXCHANGES = {"IKE_SA_INIT", "Identity Protection (Main Mode)", "Aggressive", "Base"}


@dataclass
class LifecycleEvent:
    timestamp: Optional[str]
    event_type: str
    previous_state: Optional[SAState]
    new_state: Optional[SAState]
    packet_number: Optional[int]
    message_id: Optional[int]
    spi: Optional[str]
    description: str


@dataclass
class ChildSA:
    id: str
    protocol: Literal["ESP", "AH"]
    spi: str
    source: str
    destination: str
    state: SAState
    packet_count: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    sequence_min: int
    sequence_max: int
    nat_traversal: bool
    parent_sa_id: Optional[str]
    association: Literal["CORRELATED", "UNKNOWN"]
    created_after_rekey: bool
    ipsec_mode: str = "TUNNEL"
    ip_version: int = 4
    packet_numbers: list[int] = field(default_factory=list)
    timeline: list[LifecycleEvent] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)


@dataclass
class SecurityAssociation:
    id: str
    type: SAType
    state: SAState
    start_time: Optional[str]
    last_seen: Optional[str]
    initiator: str
    responder: str
    protocol: str                      # "IKE" for IKE SAs; "ESP"/"AH" for child SAs
    ike_version: Optional[str]
    initiator_spi: Optional[str]
    responder_spi: Optional[str]
    spi: Optional[str]                 # data-plane SPI for child SAs
    packet_count: int
    byte_count: int
    duration_seconds: Optional[float]
    exchange_types: list[str]
    message_ids: list[int]
    payload_types: list[str]
    flags_seen: list[str]
    nat_traversal: bool
    child_sa_ids: list[str]
    parent_sa_id: Optional[str]
    association: Literal["DIRECT", "CORRELATED", "UNKNOWN"]
    rekey_count: int
    capture_ended_in_state: bool
    timeline: list[LifecycleEvent]
    state_history: list[tuple[Optional[str], SAState]]
    observations: list[str]
    failure: Optional[dict]
    ipsec_mode: str = "TUNNEL"
    ip_version: int = 4
    packet_numbers: list[int] = field(default_factory=list)
    security_parameters_available: bool = False
    traffic_selectors_available: bool = False


@dataclass
class DiscoveryResult:
    associations: list[SecurityAssociation]


# --------------------------------------------------------------------------- #


def discover(packets: Iterable[PacketAnalysisResult], capture_id: str) -> DiscoveryResult:
    ipsec = sorted(
        (p for p in packets if p.ipsec is not None and p.parse_status == "OK" and p.ip is not None),
        key=lambda p: (p.timestamp or "", p.number),
    )
    ike_groups: dict[tuple[tuple[str, str], str], list[PacketAnalysisResult]] = {}
    data_groups: dict[tuple[tuple[str, str], str, str], list[PacketAnalysisResult]] = {}

    for p in ipsec:
        pair = _pair(p)
        if p.ipsec.type == "IKE" and p.ipsec.ike:
            ike_groups.setdefault((pair, p.ipsec.ike.initiator_spi), []).append(p)
        else:
            layer = p.ipsec.esp or p.ipsec.ah
            if layer:
                data_groups.setdefault((pair, p.ipsec.type, layer.spi), []).append(p)

    # Attribute each data-plane SPI group to the IKE SA between the same endpoints whose
    # activity most recently precedes the group's first packet.
    ike_starts = {key: (members[0].timestamp or "") for key, members in ike_groups.items()}
    attributed: dict[tuple[tuple[str, str], str], list[PacketAnalysisResult]] = {key: [] for key in ike_groups}
    parent_key_of: dict[tuple[tuple[str, str], str, str], Optional[tuple[tuple[str, str], str]]] = {}
    for key, members in data_groups.items():
        pair = key[0]
        candidates = [k for k in ike_groups if k[0] == pair]
        if not candidates:
            parent_key_of[key] = None
            continue
        first_ts = members[0].timestamp or ""
        before = [k for k in candidates if ike_starts[k] <= first_ts] or candidates
        parent_key = max(before, key=lambda k: (ike_starts[k], k[1]))
        parent_key_of[key] = parent_key
        attributed[parent_key].extend(members)

    ike_sas: dict[tuple[tuple[str, str], str], SecurityAssociation] = {}
    for (pair, ispi), members in ike_groups.items():
        ike_sas[(pair, ispi)] = _build_ike_sa(pair, ispi, members, attributed[(pair, ispi)], capture_id)

    children: list[SecurityAssociation] = []
    for key, members in data_groups.items():
        pair, proto, spi = key
        parent = ike_sas[parent_key_of[key]] if parent_key_of[key] else None
        child = _build_child_sa(pair, proto, spi, members, capture_id, parent)
        children.append(child)
        if parent:
            parent.child_sa_ids.append(child.id)

    for parent in ike_sas.values():
        _finalize(parent)

    ike_sas_list = list(ike_sas.values())
    ike_sas = ike_sas_list  # type: ignore[assignment]

    associations = sorted(ike_sas_list + children, key=lambda s: (s.start_time or "", s.id))
    return DiscoveryResult(associations=associations)


# ----- IKE SA ---------------------------------------------------------------- #


def _build_ike_sa(pair, ispi: str, members: list[PacketAnalysisResult], data_members: list[PacketAnalysisResult], capture_id: str) -> SecurityAssociation:
    first = members[0]
    initiator, responder = _orient(members, pair)
    sa_id = _sa_id(capture_id, "IKE", pair, ispi)

    state: SAState = "UNKNOWN"
    history: list[tuple[Optional[str], SAState]] = []
    timeline: list[LifecycleEvent] = []
    observations: list[str] = []
    failure: Optional[dict] = None
    rekey_count = 0
    pending_rekey = False
    quick_modes = 0
    state_before_rekey: SAState = "ESTABLISHED"
    traffic_noted_early = False

    def transition(new: SAState, p: PacketAnalysisResult, event_type: str, description: str) -> None:
        nonlocal state
        ike = p.ipsec.ike  # type: ignore[union-attr]
        timeline.append(LifecycleEvent(p.timestamp or None, event_type, state, new, p.number, ike.message_id if ike else None, ispi, description))
        if new != state:
            history.append((p.timestamp or None, new))
            state = new

    def note(p: PacketAnalysisResult, event_type: str, description: str) -> None:
        ike = p.ipsec.ike  # type: ignore[union-attr]
        timeline.append(LifecycleEvent(p.timestamp or None, event_type, state, state, p.number, ike.message_id if ike else None, ispi, description))

    transition("DETECTED", first, "SA DETECTED", f"First IKE message for initiator SPI {ispi}: {first.info}")

    stream = sorted(members + data_members, key=lambda q: (q.timestamp or "", q.number))
    for p in stream:
        if p.ipsec.type != "IKE":  # type: ignore[union-attr]
            layer = p.ipsec.esp or p.ipsec.ah  # type: ignore[union-attr]
            spi = layer.spi if layer else None
            if state == "ESTABLISHED":
                timeline.append(LifecycleEvent(p.timestamp or None, "IPSEC TRAFFIC OBSERVED", state, "ACTIVE", p.number, None, spi, f"{p.ipsec.type} traffic observed under child SPI {spi}."))  # type: ignore[union-attr]
                history.append((p.timestamp or None, "ACTIVE"))
                state = "ACTIVE"
            elif state in ("NEGOTIATING", "DETECTED") and not traffic_noted_early:
                traffic_noted_early = True
                observations.append(f"{p.ipsec.type} traffic under SPI {spi} was observed between these endpoints, but this IKE SA was not seen to complete authentication in the capture; the traffic may belong to an earlier IKE SA.")  # type: ignore[union-attr]
            continue
        ike = p.ipsec.ike  # type: ignore[union-attr]
        if not ike:
            continue
        name = ike.exchange_name
        is_response = "Response" in ike.flags if ike.major_version == 2 else False
        payload_types = {pl.type_number for pl in ike.payloads}
        delete_type = IKEV2_DELETE if ike.major_version == 2 else IKEV1_DELETE
        notify_type = IKEV2_NOTIFY if ike.major_version == 2 else IKEV1_NOTIFY

        # Explicit termination — only a plaintext DELETE counts.
        if delete_type in payload_types:
            transition("TERMINATED", p, "DELETE OBSERVED", f"{name} carries a plaintext DELETE payload.")
            continue

        # IKEv2 negotiation failure: an IKE_SA_INIT response that contains only NOTIFY payload(s).
        if ike.major_version == 2 and name == "IKE_SA_INIT" and is_response and payload_types and payload_types <= {notify_type}:
            failure = {"exchange": name, "message_id": ike.message_id, "notification": "NOTIFY payload (type not decoded)", "timestamp": p.timestamp or None, "packet_number": p.number}
            transition("FAILED", p, "NEGOTIATION FAILED", "IKE_SA_INIT response carries only NOTIFY payload(s); no SA/KE/Nonce were offered.")
            continue

        if state in ("TERMINATED", "FAILED"):
            note(p, "MESSAGE AFTER FINAL STATE", f"{name} observed after {state}.")
            continue

        if name in NEGOTIATION_EXCHANGES:
            if state in ("UNKNOWN", "DETECTED"):
                transition("NEGOTIATING", p, "NEGOTIATION START", f"{name} {'response' if is_response else 'request'} observed.")
            else:
                note(p, "NEGOTIATION MESSAGE", f"{name} {'response' if is_response else 'request'} observed.")
            continue

        if ike.major_version == 2 and name == "IKE_AUTH":
            if is_response:
                if state in ("UNKNOWN", "DETECTED", "NEGOTIATING"):
                    transition("ESTABLISHED", p, "SA ESTABLISHED", "IKE_AUTH response observed; the IKE SA is authenticated.")
                else:
                    note(p, "IKE_AUTH RESPONSE", "IKE_AUTH response observed.")
            else:
                if state in ("UNKNOWN", "DETECTED"):
                    transition("NEGOTIATING", p, "NEGOTIATION START", "IKE_AUTH request observed without a preceding IKE_SA_INIT in this capture.")
                else:
                    note(p, "IKE_AUTH REQUEST", "IKE_AUTH request observed.")
            continue

        if ike.major_version == 2 and name == "CREATE_CHILD_SA":
            if not is_response:
                if state in ("ESTABLISHED", "ACTIVE"):
                    pending_rekey = True
                    state_before_rekey = state
                    transition("REKEYING", p, "REKEY START", "CREATE_CHILD_SA request observed on an established IKE SA.")
                else:
                    note(p, "CREATE_CHILD_SA REQUEST", "CREATE_CHILD_SA request observed before establishment was seen in this capture.")
            else:
                if state == "REKEYING":
                    rekey_count += 1
                    pending_rekey = False
                    transition(state_before_rekey, p, "REKEY COMPLETE", "CREATE_CHILD_SA response observed; new keying material negotiated.")
                elif state in ("UNKNOWN", "DETECTED", "NEGOTIATING"):
                    transition("ESTABLISHED", p, "CHILD SA CREATED", "CREATE_CHILD_SA response implies an authenticated IKE SA.")
                else:
                    note(p, "CREATE_CHILD_SA RESPONSE", "CREATE_CHILD_SA response observed.")
            continue

        if ike.major_version == 1 and name == "Quick Mode":
            quick_modes += 1
            if quick_modes == 1:
                if state in ("UNKNOWN", "DETECTED", "NEGOTIATING"):
                    transition("ESTABLISHED", p, "SA ESTABLISHED", "IKEv1 Quick Mode observed; Phase 1 must have completed.")
                else:
                    note(p, "QUICK MODE", "Quick Mode observed.")
            else:
                # A further Quick Mode on the same ISAKMP SA negotiates fresh IPsec SAs.
                rekey_count += 1
                transition("REKEYING", p, "REKEY START", "Additional Quick Mode exchange observed on the same ISAKMP SA.")
                transition("ESTABLISHED" if state == "REKEYING" else state, p, "REKEY COMPLETE", "Quick Mode exchange carries the new IPsec SA negotiation.")
            continue

        if name == "INFORMATIONAL" or name == "Informational":
            note(p, "INFORMATIONAL", f"{name} exchange observed ({', '.join(pl.name for pl in ike.payloads) or 'no visible payloads'}).")
            continue

        note(p, "UNRECOGNIZED EXCHANGE", f"{name} observed; no state rule applies.")

    if pending_rekey:
        observations.append("A CREATE_CHILD_SA request was observed without a response in this capture.")

    timestamps = [p.timestamp for p in members if p.timestamp]
    start, last = (min(timestamps), max(timestamps)) if timestamps else (None, None)
    duration = _duration(start, last)
    layers = [p.ipsec.ike for p in members if p.ipsec and p.ipsec.ike]
    versions = sorted({l.version for l in layers})

    observations = [
        f"{len(members)} IKE messages observed for initiator SPI {ispi}.",
        *_exchange_observations(layers),
        *(["Encrypted (SK) payloads observed; their contents are not visible to this engine."] if any(l.encrypted_payload for l in layers) else []),
        *observations,
    ]
    ike_mode = "TRANSPORT" if any(p.ipsec and getattr(p.ipsec, "encapsulation_mode", "TUNNEL") == "TRANSPORT" for p in members) else "TUNNEL"
    ike_ip_ver = 6 if any(p.ip and p.ip.version == 6 for p in members) else 4
    sa = SecurityAssociation(
        id=sa_id, type="IKE", state=state, start_time=start, last_seen=last, initiator=initiator, responder=responder,
        protocol="IKE", ike_version=versions[0] if len(versions) == 1 else "/".join(versions) or None,
        initiator_spi=ispi, responder_spi=next((l.responder_spi for l in layers if l.responder_spi != "0" * 16), None), spi=None,
        packet_count=len(members), byte_count=sum(p.original_length for p in members), duration_seconds=duration,
        exchange_types=_unique(l.exchange_name for l in layers), message_ids=sorted({l.message_id for l in layers}),
        payload_types=_unique(pl.name for l in layers for pl in l.payloads), flags_seen=_unique(f for l in layers for f in l.flags),
        nat_traversal=any(p.ipsec.nat_traversal for p in members if p.ipsec), child_sa_ids=[], parent_sa_id=None,
        association="DIRECT", rekey_count=rekey_count, capture_ended_in_state=state in ("ESTABLISHED", "ACTIVE", "REKEYING", "NEGOTIATING", "DETECTED"),
        ipsec_mode=ike_mode, ip_version=ike_ip_ver,
        timeline=timeline, state_history=history, observations=observations, failure=failure,
        packet_numbers=[p.number for p in members],
    )
    return sa


def _exchange_observations(layers) -> list[str]:
    out = []
    names = _unique(l.exchange_name for l in layers)
    if names:
        out.append(f"Exchanges observed: {', '.join(names)}.")
    return out


# ----- Child SA -------------------------------------------------------------- #


def _build_child_sa(pair, proto: str, spi: str, members, capture_id: str, parent: Optional[SecurityAssociation]) -> SecurityAssociation:
    first, last = members[0], members[-1]
    sa_id = _sa_id(capture_id, proto, pair, spi)
    timestamps = [p.timestamp for p in members if p.timestamp]
    start, end = (min(timestamps), max(timestamps)) if timestamps else (None, None)
    seqs = [(p.ipsec.esp or p.ipsec.ah).sequence_number for p in members]  # type: ignore[union-attr]

    timeline = [
        LifecycleEvent(first.timestamp or None, "SA DETECTED", None, "DETECTED", first.number, None, spi, f"First {proto} packet for SPI {spi}."),
        LifecycleEvent(first.timestamp or None, "IPSEC TRAFFIC OBSERVED", "DETECTED", "ACTIVE", first.number, None, spi, f"{proto} traffic carried under SPI {spi}: the child SA is in use."),
    ]
    if last is not first:
        timeline.append(LifecycleEvent(last.timestamp or None, "LAST TRAFFIC", "ACTIVE", "ACTIVE", last.number, None, spi, f"Last {proto} packet observed (seq {max(seqs)})."))

    created_after_rekey = False
    if parent and start:
        rekey_times = [e.timestamp for e in parent.timeline if e.event_type == "REKEY START" and e.timestamp]
        created_after_rekey = any(t <= start for t in rekey_times)
        if created_after_rekey:
            timeline.append(LifecycleEvent(first.timestamp or None, "CREATED AFTER REKEY", "ACTIVE", "ACTIVE", first.number, None, spi, "First traffic under this SPI follows a CREATE_CHILD_SA exchange on the parent IKE SA."))

    observations = [
        f"{len(members)} {proto} packets observed under SPI {spi} ({first.ip.source} → {first.ip.destination}).",  # type: ignore[union-attr]
        f"Sequence numbers {min(seqs)}–{max(seqs)}.",
        "Parent IKE SA correlated by endpoint pair and session; the binding SPI is negotiated inside payloads not decoded here."
        if parent else "No IKE SA observed between these endpoints in this capture; parent association unknown.",
    ]
    if proto == "ESP":
        observations.append("Payloads are encrypted; algorithms are not observable from ESP headers.")
    if parent and parent.state == "TERMINATED" and parent.last_seen and end and parent.last_seen > end:
        observations.append("The parent IKE SA carried a DELETE after this SA's last traffic; whether that DELETE named this SA is not decodable.")

    child_mode = "TRANSPORT" if any(
        (p.ipsec and getattr(p.ipsec, "encapsulation_mode", "TUNNEL") == "TRANSPORT")
        or (p.ipsec and p.ipsec.ah and p.ipsec.ah.next_header in (1, 6, 17, 58))
        for p in members
    ) else "TUNNEL"
    child_ip_ver = 6 if any(p.ip and p.ip.version == 6 for p in members) else 4
    return SecurityAssociation(
        id=sa_id, type="CHILD", state="ACTIVE", start_time=start, last_seen=end,
        initiator=first.ip.source, responder=first.ip.destination, protocol=proto,  # type: ignore[union-attr]
        ike_version=parent.ike_version if parent else None, initiator_spi=None, responder_spi=None, spi=spi,
        packet_count=len(members), byte_count=sum(p.original_length for p in members), duration_seconds=_duration(start, end),
        exchange_types=[], message_ids=[], payload_types=[], flags_seen=[],
        nat_traversal=any(p.ipsec.nat_traversal for p in members if p.ipsec), child_sa_ids=[], parent_sa_id=parent.id if parent else None,
        association="CORRELATED" if parent else "UNKNOWN", rekey_count=0, capture_ended_in_state=True,
        ipsec_mode=child_mode, ip_version=child_ip_ver,
        timeline=timeline, state_history=[(first.timestamp or None, "DETECTED"), (first.timestamp or None, "ACTIVE")],
        observations=observations, failure=None, packet_numbers=[p.number for p in members],
    )


def _finalize(sa: SecurityAssociation) -> None:
    if sa.state in ("ESTABLISHED", "ACTIVE", "REKEYING", "NEGOTIATING", "DETECTED"):
        sa.timeline.append(LifecycleEvent(sa.last_seen, "CAPTURE ENDED", sa.state, sa.state, None, None, sa.initiator_spi, f"Capture ends with the SA in state {sa.state}; no termination or expiry was observed."))
    sa.child_sa_ids.sort()


# ----- helpers --------------------------------------------------------------- #


def _pair(p: PacketAnalysisResult) -> tuple[str, str]:
    a, b = p.ip.source, p.ip.destination  # type: ignore[union-attr]
    return (a, b) if a <= b else (b, a)


def _orient(members, pair) -> tuple[str, str]:
    for p in members:
        ike = p.ipsec.ike if p.ipsec else None
        if ike and "Initiator" in ike.flags:
            return p.ip.source, p.ip.destination  # type: ignore[union-attr]
    first = members[0]
    return (first.ip.source, first.ip.destination) if first.ip else pair


def _sa_id(capture_id: str, kind: str, pair, key: str) -> str:
    seed = f"{capture_id}|{kind}|{pair[0]}|{pair[1]}|{key}"
    return "SA-" + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()


def _duration(start: Optional[str], end: Optional[str]) -> Optional[float]:
    if not start or not end:
        return None
    try:
        return round(datetime.fromisoformat(end).timestamp() - datetime.fromisoformat(start).timestamp(), 6)
    except ValueError:
        return None


def _unique(values: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for v in values:
        if v not in seen:
            seen.append(v)
    return seen
