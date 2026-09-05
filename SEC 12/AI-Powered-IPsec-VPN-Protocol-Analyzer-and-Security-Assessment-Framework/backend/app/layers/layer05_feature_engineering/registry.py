"""The single authoritative feature registry.

Every feature the layer can emit is declared here exactly once: its type,
unit, category, lineage and formula. Calculators may not invent a name that
is absent from this table — ``build_vector`` rejects unknown names — so the
registry stays the one place a later baseline or AI module has to read to
know what a feature means.

Names are keyed by ``(level, name)``. The same name may legitimately appear
at two levels when it means the same thing about a different entity, for
example ``ike_version`` on a packet and on a session; it may never mean two
different things.

Sources are written so the lineage chain is readable end to end:
    feature -> source entity -> the observation the value came from.
"""

from __future__ import annotations

from .models import (
    FeatureCategory,
    FeatureDefinition,
    FeatureLevel,
    FeatureType,
    NormalizationMethod,
)

# Sources, named once so lineage strings cannot drift apart.
SRC_PACKET = "Layer 03 decoded packet"
SRC_PACKET_IP = "Layer 03 decoded packet — IP header"
SRC_PACKET_TRANSPORT = "Layer 03 decoded packet — transport header"
SRC_PACKET_IPSEC = "Layer 03 decoded packet — IPsec layer"
SRC_PACKET_IKE = "Layer 03 decoded packet — IKE header"
SRC_SESSION = "IPsec session record (Section 6)"
SRC_SESSION_IKE = "IPsec session record — IKE observations (Section 6)"
SRC_SESSION_PACKETS = "Packets associated with the IPsec session"
SRC_SA = "Security Association record (Layer 04)"
SRC_SA_EVENTS = "SA lifecycle events (Layer 04)"

#: Fixed tumbling window used by the burst features, aligned to the first
#: packet of the session. Documented rather than tuned: one second is the
#: coarsest window that still separates individual exchanges, and no
#: threshold is applied to it because "how bursty is unusual" needs a
#: baseline, which belongs to Section 9.
BURST_WINDOW_SECONDS = 1.0

_DEFINITIONS: list[FeatureDefinition] = []


def _d(
    name: str,
    display_name: str,
    description: str,
    level: FeatureLevel,
    category: FeatureCategory,
    data_type: FeatureType,
    unit: str | None,
    source: str,
    *,
    nullable: bool = True,
    formula: str | None = None,
    normalization_method: NormalizationMethod = "NONE",
    minimum_expected_value: float | None = None,
    maximum_expected_value: float | None = None,
) -> None:
    _DEFINITIONS.append(
        FeatureDefinition(
            name=name,
            display_name=display_name,
            description=description,
            level=level,
            category=category,
            data_type=data_type,
            unit=unit,
            source=source,
            nullable=nullable,
            formula=formula,
            normalization_method=normalization_method,
            minimum_expected_value=minimum_expected_value,
            maximum_expected_value=maximum_expected_value,
        )
    )


# --------------------------------------------------------------------------- #
# PACKET level
# --------------------------------------------------------------------------- #

_d("packet_length", "Packet Length", "Length of the frame on the wire.", "PACKET", "TRAFFIC", "INTEGER", "bytes", SRC_PACKET, minimum_expected_value=0)
_d("captured_length", "Captured Length", "Bytes actually stored in the capture file; lower than packet length when the capture was snapped short.", "PACKET", "TRAFFIC", "INTEGER", "bytes", SRC_PACKET, minimum_expected_value=0)
_d("ip_version", "IP Version", "IP version of the packet, 4 or 6.", "PACKET", "PROTOCOL", "INTEGER", None, SRC_PACKET_IP)
_d("transport_protocol", "Transport Protocol", "Decoded transport layer: TCP, UDP or ICMP. Null when the packet carries ESP or AH directly over IP.", "PACKET", "PROTOCOL", "CATEGORICAL", None, SRC_PACKET_TRANSPORT, normalization_method="CATEGORICAL_ENCODING")
_d("source_port", "Source Port", "Transport source port; present for TCP and UDP only.", "PACKET", "PROTOCOL", "INTEGER", None, SRC_PACKET_TRANSPORT, minimum_expected_value=0, maximum_expected_value=65535)
_d("destination_port", "Destination Port", "Transport destination port; present for TCP and UDP only.", "PACKET", "PROTOCOL", "INTEGER", None, SRC_PACKET_TRANSPORT, minimum_expected_value=0, maximum_expected_value=65535)
_d("fragmented", "Fragmented", "The IP header marks this packet as a fragment.", "PACKET", "PROTOCOL", "BOOLEAN", None, SRC_PACKET_IP)
_d("direction", "Direction", "Direction relative to the session's first observed packet: OUTBOUND matches it, INBOUND is the reverse. UNKNOWN when the packet belongs to no discovered session.", "PACKET", "DIRECTIONAL", "CATEGORICAL", None, SRC_SESSION, normalization_method="CATEGORICAL_ENCODING")

_d("is_ike", "Is IKE", "The packet carries a decoded IKE message.", "PACKET", "IPSEC", "BOOLEAN", None, SRC_PACKET_IPSEC, nullable=False)
_d("is_esp", "Is ESP", "The packet carries a decoded ESP header.", "PACKET", "IPSEC", "BOOLEAN", None, SRC_PACKET_IPSEC, nullable=False)
_d("is_ah", "Is AH", "The packet carries a decoded AH header.", "PACKET", "IPSEC", "BOOLEAN", None, SRC_PACKET_IPSEC, nullable=False)
_d("is_nat_t", "Is NAT-T", "The packet is UDP-encapsulated for NAT traversal.", "PACKET", "IPSEC", "BOOLEAN", None, SRC_PACKET_IPSEC, nullable=False)
_d("ipsec_protocol", "IPsec Protocol", "Which IPsec protocol the packet carries: IKE, ESP or AH.", "PACKET", "IPSEC", "CATEGORICAL", None, SRC_PACKET_IPSEC, normalization_method="CATEGORICAL_ENCODING")
_d("spi_present", "SPI Present", "A Security Parameter Index was decoded from the packet.", "PACKET", "IPSEC", "BOOLEAN", None, SRC_PACKET_IPSEC, nullable=False)
_d("spi_value", "SPI Value", "The decoded SPI, as it appears in the header. A public header field, not key material.", "PACKET", "IPSEC", "CATEGORICAL", None, SRC_PACKET_IPSEC)
_d("sequence_number", "Sequence Number", "ESP or AH anti-replay sequence number.", "PACKET", "IPSEC", "INTEGER", None, SRC_PACKET_IPSEC, minimum_expected_value=0)
_d("encrypted_payload_present", "Encrypted Payload Present", "The IKE message carries an encrypted (SK) payload whose contents are not decoded.", "PACKET", "IPSEC", "BOOLEAN", None, SRC_PACKET_IKE)

_d("ike_version", "IKE Version", "IKE version string from the message header.", "PACKET", "IKE", "CATEGORICAL", None, SRC_PACKET_IKE, normalization_method="CATEGORICAL_ENCODING")
_d("ike_exchange_type", "IKE Exchange Type", "Numeric exchange type from the IKE header.", "PACKET", "IKE", "INTEGER", None, SRC_PACKET_IKE, minimum_expected_value=0)
_d("ike_exchange_name", "IKE Exchange Name", "Decoded name of the IKE exchange type.", "PACKET", "IKE", "CATEGORICAL", None, SRC_PACKET_IKE, normalization_method="CATEGORICAL_ENCODING")
_d("ike_message_id", "IKE Message ID", "Message ID from the IKE header.", "PACKET", "IKE", "INTEGER", None, SRC_PACKET_IKE, minimum_expected_value=0)
_d("ike_payload_count", "IKE Payload Count", "Number of payloads visible in the message's payload chain. Payloads inside an encrypted SK payload are not counted.", "PACKET", "IKE", "INTEGER", "payloads", SRC_PACKET_IKE, minimum_expected_value=0)

# --------------------------------------------------------------------------- #
# SESSION level
# --------------------------------------------------------------------------- #

_d("packet_count", "Packet Count", "Packets correlated into the session.", "SESSION", "TRAFFIC", "INTEGER", "packets", SRC_SESSION, minimum_expected_value=0)
_d("byte_count", "Byte Count", "Sum of on-the-wire packet lengths in the session.", "SESSION", "TRAFFIC", "INTEGER", "bytes", SRC_SESSION, formula="sum(packet_length)", minimum_expected_value=0)
_d("ike_packet_count", "IKE Packet Count", "Session packets carrying IKE.", "SESSION", "TRAFFIC", "INTEGER", "packets", SRC_SESSION, minimum_expected_value=0)
_d("esp_packet_count", "ESP Packet Count", "Session packets carrying ESP.", "SESSION", "TRAFFIC", "INTEGER", "packets", SRC_SESSION, minimum_expected_value=0)
_d("ah_packet_count", "AH Packet Count", "Session packets carrying AH.", "SESSION", "TRAFFIC", "INTEGER", "packets", SRC_SESSION, minimum_expected_value=0)
_d("session_state", "Session State", "State the correlation engine derived from observed exchanges.", "SESSION", "PROTOCOL", "CATEGORICAL", None, SRC_SESSION, normalization_method="CATEGORICAL_ENCODING")
_d("session_direction", "Session Direction", "Whether traffic was seen in one or both directions.", "SESSION", "DIRECTIONAL", "CATEGORICAL", None, SRC_SESSION, normalization_method="CATEGORICAL_ENCODING")
_d("nat_traversal_observed", "NAT Traversal Observed", "At least one session packet was UDP-encapsulated for NAT traversal.", "SESSION", "IPSEC", "BOOLEAN", None, SRC_SESSION)

_d("first_seen", "First Seen", "Timestamp of the earliest session packet.", "SESSION", "TIMING", "TIMESTAMP", None, SRC_SESSION)
_d("last_seen", "Last Seen", "Timestamp of the latest session packet.", "SESSION", "TIMING", "TIMESTAMP", None, SRC_SESSION)
_d("session_duration_seconds", "Session Duration", "Elapsed time between the first and last session packet.", "SESSION", "TIMING", "FLOAT", "seconds", SRC_SESSION, formula="last_seen - first_seen", minimum_expected_value=0)
_d("mean_interarrival_time", "Mean Interarrival Time", "Mean gap between consecutive session packets. Needs at least two timestamped packets.", "SESSION", "TIMING", "FLOAT", "seconds", SRC_SESSION_PACKETS, formula="sum(t[i] - t[i-1]) / (n - 1)", minimum_expected_value=0)
_d("min_interarrival_time", "Minimum Interarrival Time", "Smallest gap between consecutive session packets.", "SESSION", "TIMING", "FLOAT", "seconds", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("max_interarrival_time", "Maximum Interarrival Time", "Largest gap between consecutive session packets.", "SESSION", "TIMING", "FLOAT", "seconds", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("interarrival_variance", "Interarrival Variance", "Population variance of the interarrival gaps.", "SESSION", "TIMING", "FLOAT", "seconds^2", SRC_SESSION_PACKETS, formula="sum((gap - mean_gap)^2) / n_gaps", minimum_expected_value=0)

_d("average_packet_size", "Average Packet Size", "Mean on-the-wire length of the session's packets.", "SESSION", "STATISTICAL", "FLOAT", "bytes", SRC_SESSION, formula="byte_count / packet_count", minimum_expected_value=0)
_d("median_packet_size", "Median Packet Size", "Median on-the-wire packet length.", "SESSION", "STATISTICAL", "FLOAT", "bytes", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("minimum_packet_size", "Minimum Packet Size", "Smallest on-the-wire packet length in the session.", "SESSION", "STATISTICAL", "INTEGER", "bytes", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("maximum_packet_size", "Maximum Packet Size", "Largest on-the-wire packet length in the session.", "SESSION", "STATISTICAL", "INTEGER", "bytes", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("packet_size_variance", "Packet Size Variance", "Population variance of packet lengths.", "SESSION", "STATISTICAL", "FLOAT", "bytes^2", SRC_SESSION_PACKETS, formula="sum((len - mean_len)^2) / n", minimum_expected_value=0)
_d("packet_size_standard_deviation", "Packet Size Std. Deviation", "Square root of the packet size variance.", "SESSION", "STATISTICAL", "FLOAT", "bytes", SRC_SESSION_PACKETS, formula="sqrt(packet_size_variance)", minimum_expected_value=0)

_d("packets_per_second", "Packets per Second", "Packet rate over the session duration. Not calculated for a zero-length session.", "SESSION", "TRAFFIC", "FLOAT", "packets/second", SRC_SESSION, formula="packet_count / session_duration_seconds", minimum_expected_value=0)
_d("bytes_per_second", "Bytes per Second", "Byte rate over the session duration.", "SESSION", "TRAFFIC", "FLOAT", "bytes/second", SRC_SESSION, formula="byte_count / session_duration_seconds", minimum_expected_value=0)
_d("ike_packets_per_second", "IKE Packets per Second", "IKE packet rate over the session duration.", "SESSION", "TRAFFIC", "FLOAT", "packets/second", SRC_SESSION, formula="ike_packet_count / session_duration_seconds", minimum_expected_value=0)
_d("esp_packets_per_second", "ESP Packets per Second", "ESP packet rate over the session duration.", "SESSION", "TRAFFIC", "FLOAT", "packets/second", SRC_SESSION, formula="esp_packet_count / session_duration_seconds", minimum_expected_value=0)
_d("maximum_packets_in_window", "Max Packets in Window", f"Most packets falling in any {BURST_WINDOW_SECONDS:g}-second tumbling window aligned to the session start.", "SESSION", "TRAFFIC", "INTEGER", "packets", SRC_SESSION_PACKETS, formula=f"max over {BURST_WINDOW_SECONDS:g}s windows of count(packets in window)", minimum_expected_value=0)
_d("maximum_bytes_in_window", "Max Bytes in Window", f"Most bytes falling in any {BURST_WINDOW_SECONDS:g}-second tumbling window aligned to the session start.", "SESSION", "TRAFFIC", "INTEGER", "bytes", SRC_SESSION_PACKETS, formula=f"max over {BURST_WINDOW_SECONDS:g}s windows of sum(packet_length in window)", minimum_expected_value=0)

_d("inbound_packets", "Inbound Packets", "Packets travelling opposite to the session's first observed packet.", "SESSION", "DIRECTIONAL", "INTEGER", "packets", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("outbound_packets", "Outbound Packets", "Packets travelling in the same direction as the session's first observed packet.", "SESSION", "DIRECTIONAL", "INTEGER", "packets", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("inbound_bytes", "Inbound Bytes", "On-the-wire bytes in the inbound direction.", "SESSION", "DIRECTIONAL", "INTEGER", "bytes", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("outbound_bytes", "Outbound Bytes", "On-the-wire bytes in the outbound direction.", "SESSION", "DIRECTIONAL", "INTEGER", "bytes", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("inbound_outbound_packet_ratio", "Inbound/Outbound Packet Ratio", "Inbound packets divided by outbound packets. Not calculated when no outbound packet was observed.", "SESSION", "DIRECTIONAL", "FLOAT", "ratio", SRC_SESSION_PACKETS, formula="inbound_packets / outbound_packets", minimum_expected_value=0)
_d("inbound_outbound_byte_ratio", "Inbound/Outbound Byte Ratio", "Inbound bytes divided by outbound bytes. Not calculated when no outbound byte was observed.", "SESSION", "DIRECTIONAL", "FLOAT", "ratio", SRC_SESSION_PACKETS, formula="inbound_bytes / outbound_bytes", minimum_expected_value=0)

_d("ike_ratio", "IKE Ratio", "Share of session packets carrying IKE.", "SESSION", "PROTOCOL", "FLOAT", "ratio", SRC_SESSION, formula="ike_packet_count / packet_count", minimum_expected_value=0, maximum_expected_value=1)
_d("esp_ratio", "ESP Ratio", "Share of session packets carrying ESP.", "SESSION", "PROTOCOL", "FLOAT", "ratio", SRC_SESSION, formula="esp_packet_count / packet_count", minimum_expected_value=0, maximum_expected_value=1)
_d("ah_ratio", "AH Ratio", "Share of session packets carrying AH.", "SESSION", "PROTOCOL", "FLOAT", "ratio", SRC_SESSION, formula="ah_packet_count / packet_count", minimum_expected_value=0, maximum_expected_value=1)
_d("udp_ratio", "UDP Ratio", "Share of session packets carried over UDP, which covers IKE and NAT-T encapsulated ESP.", "SESSION", "PROTOCOL", "FLOAT", "ratio", SRC_SESSION_PACKETS, formula="udp_packets / packet_count", minimum_expected_value=0, maximum_expected_value=1)
_d("tcp_ratio", "TCP Ratio", "Share of session packets carried over TCP.", "SESSION", "PROTOCOL", "FLOAT", "ratio", SRC_SESSION_PACKETS, formula="tcp_packets / packet_count", minimum_expected_value=0, maximum_expected_value=1)
_d("other_ratio", "Other Transport Ratio", "Share of session packets carried directly over IP with no transport header, that is native ESP or AH.", "SESSION", "PROTOCOL", "FLOAT", "ratio", SRC_SESSION_PACKETS, formula="1 - udp_ratio - tcp_ratio", minimum_expected_value=0, maximum_expected_value=1)

_d("ike_version", "IKE Version", "IKE version observed in the session.", "SESSION", "IKE", "CATEGORICAL", None, SRC_SESSION, normalization_method="CATEGORICAL_ENCODING")
_d("ike_message_count", "IKE Message Count", "Number of IKE messages observed in the session.", "SESSION", "IKE", "INTEGER", "messages", SRC_SESSION, minimum_expected_value=0)
_d("ike_exchange_count", "IKE Exchange Count", "Distinct IKE exchanges observed, counted as unique exchange type and message ID pairs.", "SESSION", "IKE", "INTEGER", "exchanges", SRC_SESSION_PACKETS, formula="count(distinct (exchange_name, message_id))", minimum_expected_value=0)
_d("unique_exchange_types", "Unique Exchange Types", "Number of distinct IKE exchange types observed.", "SESSION", "IKE", "INTEGER", "types", SRC_SESSION_IKE, minimum_expected_value=0)
_d("ike_payload_count", "IKE Payload Count", "Total payloads visible across the session's IKE messages. Payloads inside encrypted SK payloads are not counted.", "SESSION", "IKE", "INTEGER", "payloads", SRC_SESSION_PACKETS, formula="sum(ike_payload_count per message)", minimum_expected_value=0)
_d("notify_payload_count", "Notify Payload Count", "Visible NOTIFY payloads across the session's IKE messages.", "SESSION", "IKE", "INTEGER", "payloads", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("delete_payload_count", "Delete Payload Count", "Visible DELETE payloads across the session's IKE messages.", "SESSION", "IKE", "INTEGER", "payloads", SRC_SESSION_PACKETS, minimum_expected_value=0)
_d("retransmission_count", "Retransmission Count", "Repeat IKEv2 messages, counted as occurrences of a direction and message ID pair beyond the first. Only calculated for IKEv2, where message IDs are unique per exchange and direction.", "SESSION", "IKE", "INTEGER", "messages", SRC_SESSION_PACKETS, formula="sum over (direction, message_id) of max(0, occurrences - 1)", minimum_expected_value=0)
_d("ike_sa_init_observed", "IKE_SA_INIT Observed", "An IKE_SA_INIT exchange was observed.", "SESSION", "IKE", "BOOLEAN", None, SRC_SESSION_IKE)
_d("ike_auth_observed", "IKE_AUTH Observed", "An IKE_AUTH exchange was observed.", "SESSION", "IKE", "BOOLEAN", None, SRC_SESSION_IKE)
_d("create_child_sa_observed", "CREATE_CHILD_SA Observed", "A CREATE_CHILD_SA exchange was observed.", "SESSION", "IKE", "BOOLEAN", None, SRC_SESSION_IKE)
_d("informational_exchange_observed", "Informational Exchange Observed", "An INFORMATIONAL exchange was observed.", "SESSION", "IKE", "BOOLEAN", None, SRC_SESSION_IKE)
_d("delete_payload_observed", "Delete Payload Observed", "A DELETE payload was visible in the clear.", "SESSION", "IKE", "BOOLEAN", None, SRC_SESSION_IKE)
_d("notify_payload_observed", "Notify Payload Observed", "A NOTIFY payload was visible in the clear.", "SESSION", "IKE", "BOOLEAN", None, SRC_SESSION_IKE)

# --------------------------------------------------------------------------- #
# SA level
# --------------------------------------------------------------------------- #

_d("sa_type", "SA Type", "Whether the association is an IKE SA or a child SA.", "SA", "SA_LIFECYCLE", "CATEGORICAL", None, SRC_SA, normalization_method="CATEGORICAL_ENCODING")
_d("sa_state", "SA State", "Lifecycle state the engine derived from cited packet evidence.", "SA", "SA_LIFECYCLE", "CATEGORICAL", None, SRC_SA, normalization_method="CATEGORICAL_ENCODING")
_d("sa_protocol", "SA Protocol", "Protocol the association carries: IKE, ESP or AH.", "SA", "IPSEC", "CATEGORICAL", None, SRC_SA, normalization_method="CATEGORICAL_ENCODING")
_d("ike_version", "IKE Version", "IKE version associated with the SA.", "SA", "IKE", "CATEGORICAL", None, SRC_SA, normalization_method="CATEGORICAL_ENCODING")
_d("nat_traversal_observed", "NAT Traversal Observed", "At least one of the SA's packets was UDP-encapsulated for NAT traversal.", "SA", "IPSEC", "BOOLEAN", None, SRC_SA)

_d("first_seen", "First Seen", "Timestamp of the SA's earliest packet.", "SA", "TIMING", "TIMESTAMP", None, SRC_SA)
_d("last_seen", "Last Seen", "Timestamp of the SA's latest packet.", "SA", "TIMING", "TIMESTAMP", None, SRC_SA)
_d("sa_duration_seconds", "SA Duration", "Elapsed time between the SA's first and last observed packet. This is an observation window, not a negotiated lifetime.", "SA", "TIMING", "FLOAT", "seconds", SRC_SA, formula="last_seen - first_seen", minimum_expected_value=0)
_d("sa_packet_count", "SA Packet Count", "Packets attributed to the SA.", "SA", "TRAFFIC", "INTEGER", "packets", SRC_SA, minimum_expected_value=0)
_d("sa_byte_count", "SA Byte Count", "On-the-wire bytes attributed to the SA.", "SA", "TRAFFIC", "INTEGER", "bytes", SRC_SA, minimum_expected_value=0)
_d("average_packet_size", "Average Packet Size", "Mean on-the-wire length of the SA's packets.", "SA", "STATISTICAL", "FLOAT", "bytes", SRC_SA, formula="sa_byte_count / sa_packet_count", minimum_expected_value=0)

_d("child_sa_count", "Child SA Count", "Child SAs correlated to this IKE SA. Only meaningful for an IKE SA.", "SA", "SA_LIFECYCLE", "INTEGER", "SAs", SRC_SA, minimum_expected_value=0)
_d("state_transition_count", "State Transition Count", "Lifecycle events that changed the SA's state.", "SA", "SA_LIFECYCLE", "INTEGER", "transitions", SRC_SA_EVENTS, formula="count(events where new_state != previous_state)", minimum_expected_value=0)
_d("capture_ended_in_state", "Capture Ended in State", "The capture ended while the SA was still in a non-terminal state, so its lifecycle is truncated by the observation window.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA)
_d("negotiation_observed", "Negotiation Observed", "A negotiation exchange was observed for this SA.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA_EVENTS)
_d("establishment_observed", "Establishment Observed", "Evidence of establishment was observed, such as an IKE_AUTH response.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA_EVENTS)
_d("active_traffic_observed", "Active Traffic Observed", "Protected traffic was observed under this SA.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA_EVENTS)
_d("rekey_observed", "Rekey Observed", "A rekey exchange was observed.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA_EVENTS)
_d("termination_observed", "Termination Observed", "A plaintext DELETE payload terminated the SA. The end of a capture is never counted as termination.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA_EVENTS)
_d("failed_negotiation_observed", "Failed Negotiation Observed", "A negotiation failure was observed, that is an IKE_SA_INIT response carrying only NOTIFY payloads.", "SA", "SA_LIFECYCLE", "BOOLEAN", None, SRC_SA_EVENTS)

_d("rekey_count", "Rekey Count", "Rekey exchanges observed on this SA. Only calculated for IKE SAs, where rekeys are visible.", "SA", "SA_LIFECYCLE", "INTEGER", "rekeys", SRC_SA, minimum_expected_value=0)
_d("last_rekey_time", "Last Rekey Time", "Timestamp of the most recent observed rekey.", "SA", "TIMING", "TIMESTAMP", None, SRC_SA_EVENTS)
_d("mean_rekey_interval", "Mean Rekey Interval", "Mean gap between observed rekeys. Needs at least two rekey events.", "SA", "TIMING", "FLOAT", "seconds", SRC_SA_EVENTS, formula="sum(rekey[i] - rekey[i-1]) / (rekeys - 1)", minimum_expected_value=0)
_d("min_rekey_interval", "Minimum Rekey Interval", "Smallest gap between observed rekeys.", "SA", "TIMING", "FLOAT", "seconds", SRC_SA_EVENTS, minimum_expected_value=0)
_d("max_rekey_interval", "Maximum Rekey Interval", "Largest gap between observed rekeys.", "SA", "TIMING", "FLOAT", "seconds", SRC_SA_EVENTS, minimum_expected_value=0)


# --------------------------------------------------------------------------- #
# Lookup surface
# --------------------------------------------------------------------------- #

FEATURE_DEFINITIONS: tuple[FeatureDefinition, ...] = tuple(_DEFINITIONS)

_BY_KEY: dict[tuple[str, str], FeatureDefinition] = {}
for _definition in FEATURE_DEFINITIONS:
    _key = (_definition.level, _definition.name)
    if _key in _BY_KEY:  # pragma: no cover - guards against edits, not runtime
        raise RuntimeError(f"Duplicate feature definition {_definition.level}/{_definition.name}")
    _BY_KEY[_key] = _definition


def definition(level: str, name: str) -> FeatureDefinition:
    """Look up one definition, raising if a calculator invented a name."""
    try:
        return _BY_KEY[(level, name)]
    except KeyError as exc:
        raise KeyError(f"No feature definition registered for {level}/{name}") from exc


def definitions_for(level: str) -> tuple[FeatureDefinition, ...]:
    """Every definition for one entity level, in registry order."""
    return tuple(d for d in FEATURE_DEFINITIONS if d.level == level)


def has_definition(level: str, name: str) -> bool:
    return (level, name) in _BY_KEY
