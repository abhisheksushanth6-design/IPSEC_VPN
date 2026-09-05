"""SA-level feature calculation.

Layer 04 only moves an SA on evidence it can cite, and this calculator
inherits that discipline rather than adding inference on top. Where the
lifecycle engine cannot see something — a rekey on a child SA, a DELETE
hidden inside an encrypted payload — the feature is unavailable, not zero.

These are observations, not judgements. Nothing here says whether a rekey
interval or a failure is good, expected or concerning; that needs a baseline,
which belongs to a later section.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..registry import SRC_SA, SRC_SA_EVENTS
from ..validation import FeatureSet, round_float, safe_divide
from .timing_features import add_rekey_interval_features, duration_between

# Event types emitted by the Layer 04 engine.
EV_NEGOTIATION = {"NEGOTIATION START", "NEGOTIATION MESSAGE", "IKE_AUTH REQUEST"}
EV_ESTABLISHED = {"SA ESTABLISHED", "CHILD SA CREATED", "IKE_AUTH RESPONSE"}
EV_TRAFFIC = {"IPSEC TRAFFIC OBSERVED", "LAST TRAFFIC"}
EV_REKEY = {"REKEY START"}
EV_TERMINATION = {"DELETE OBSERVED"}
EV_FAILURE = {"NEGOTIATION FAILED"}

CHILD_SA_REKEY = (
    "A child SA is keyed by its SPI, so a rekey produces a new child SA rather than an event on "
    "this one. Rekey evidence lives on the parent IKE SA."
)
CHILD_SA_CHILDREN = "Only an IKE SA can have child SAs."


@dataclass
class SAEvent:
    """One lifecycle event as Layer 04 recorded it."""

    event_type: str
    timestamp: Optional[str] = None
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    packet_number: Optional[int] = None


@dataclass
class SARecord:
    """The stored Security Association, decoupled from its ORM row."""

    id: str
    type: str
    state: str
    protocol: str
    initiator: str
    responder: str
    packet_count: int
    byte_count: int
    nat_traversal: bool
    rekey_count: int
    capture_ended_in_state: bool = False
    ike_version: Optional[str] = None
    #: Human-readable SPI for labelling only; a public header field.
    spi_label: Optional[str] = None
    start_time: Optional[str] = None
    last_seen: Optional[str] = None
    duration_seconds: Optional[float] = None
    child_sa_ids: list[str] = field(default_factory=list)
    events: list[SAEvent] = field(default_factory=list)


def calculate_sa_features(sa: SARecord) -> FeatureSet:
    """Features for one Security Association."""
    fs = FeatureSet("SA")
    is_ike_sa = sa.type == "IKE"

    # ----- identity --------------------------------------------------------
    fs.add("sa_type", sa.type)
    fs.add("sa_state", sa.state)
    fs.add("sa_protocol", sa.protocol)
    fs.add_or_missing(
        "ike_version",
        sa.ike_version,
        "No IKE version is associated with this SA; for a child SA it is only known when a parent "
        "IKE SA was correlated.",
    )
    fs.add("nat_traversal_observed", bool(sa.nat_traversal))

    # ----- timing and traffic ----------------------------------------------
    no_time = "No packet attributed to this SA carried a usable timestamp."
    fs.add_or_missing("first_seen", sa.start_time, no_time)
    fs.add_or_missing("last_seen", sa.last_seen, no_time)

    duration = sa.duration_seconds
    if duration is None:
        duration = duration_between(sa.start_time, sa.last_seen)
    fs.add_or_missing(
        "sa_duration_seconds",
        round_float(duration),
        no_time,
        detail="Observation window between first and last packet, not a negotiated lifetime."
        if duration is not None
        else None,
    )

    fs.add("sa_packet_count", int(sa.packet_count))
    fs.add("sa_byte_count", int(sa.byte_count))
    fs.add_or_missing(
        "average_packet_size",
        round_float(safe_divide(sa.byte_count, sa.packet_count)),
        "No packets are attributed to this SA, so a mean size has no denominator.",
    )

    # ----- lifecycle -------------------------------------------------------
    types = [event.event_type for event in sa.events]
    has_events = bool(sa.events)
    no_events = "No lifecycle events are recorded for this SA."

    if is_ike_sa:
        fs.add("child_sa_count", len(sa.child_sa_ids))
    else:
        fs.missing("child_sa_count", CHILD_SA_CHILDREN)

    if has_events:
        fs.add(
            "state_transition_count",
            sum(1 for e in sa.events if e.new_state is not None and e.new_state != e.previous_state),
            source=SRC_SA_EVENTS,
        )
    else:
        fs.missing("state_transition_count", no_events, source=SRC_SA_EVENTS)

    fs.add("capture_ended_in_state", bool(sa.capture_ended_in_state), source=SRC_SA)

    for name, wanted in (
        ("negotiation_observed", EV_NEGOTIATION),
        ("establishment_observed", EV_ESTABLISHED),
        ("active_traffic_observed", EV_TRAFFIC),
        ("rekey_observed", EV_REKEY),
        ("termination_observed", EV_TERMINATION),
        ("failed_negotiation_observed", EV_FAILURE),
    ):
        if not has_events:
            fs.missing(name, no_events, source=SRC_SA_EVENTS)
            continue
        fs.add(name, any(t in wanted for t in types), source=SRC_SA_EVENTS)

    # ----- rekey -----------------------------------------------------------
    if is_ike_sa:
        fs.add("rekey_count", int(sa.rekey_count), source=SRC_SA)
        add_rekey_interval_features(
            fs,
            [e.timestamp for e in sa.events if e.event_type in EV_REKEY and e.timestamp],
            source=SRC_SA_EVENTS,
        )
    else:
        fs.missing("rekey_count", CHILD_SA_REKEY, source=SRC_SA)
        for name in ("last_rekey_time", "mean_rekey_interval", "min_rekey_interval", "max_rekey_interval"):
            fs.missing(name, CHILD_SA_REKEY, source=SRC_SA_EVENTS)

    return fs
