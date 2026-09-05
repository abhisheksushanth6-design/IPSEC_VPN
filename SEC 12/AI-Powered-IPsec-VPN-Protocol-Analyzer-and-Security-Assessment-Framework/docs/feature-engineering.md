# Layer 05 — Feature Extraction & Engineering

Feature schema version: **1.0**
Registered features: **100** (22 packet, 53 session, 25 SA)

This document is generated from `backend/app/layers/layer05_feature_engineering/registry.py`,
which is the single source of truth. Regenerate it after changing the registry; do not
edit it by hand.

## What this layer does — and does not — do

Layer 05 turns the factual observations of Layer 03 (decoded packets) and Layer 04
(sessions and Security Associations) into a structured, validated, versioned feature
vector. Every value comes from real data; nothing is sampled, estimated or defaulted.

It performs no security judgement. There is no baseline, drift score, anomaly score,
vulnerability classification or risk score here. Those belong to Layers 06–10 and are
not started. Normalization is architecture only: each feature declares the method it
will eventually use, but no parameters are fitted and `normalized_value` is always null.

## Pipeline

    entity reference -> validate source data -> calculate -> validate output -> FeatureVector

The frontend sends only `entity_type` and `entity_id`. The backend already holds the
packets, sessions and SAs, so nothing is re-sent or re-parsed.

## Zero versus null

`0` and `null` are different facts and the layer never confuses them.

- `rekey_count = 0` on an IKE SA: the lifecycle was observed and no rekey happened.
- `rekey_count = null` on a child SA: Layer 04 cannot see child rekeys (a rekey creates a
  new SPI, hence a new child SA), so the question is unanswerable and the value is
  **UNAVAILABLE** with the reason attached.

There is no code path that turns a missing observation into a zero. Calculators must
call either `FeatureSet.add(value)` or `FeatureSet.missing(reason)`.

## Availability and quality

| availability | quality | meaning |
|---|---|---|
| AVAILABLE | COMPLETE | Calculated from complete source data |
| PARTIAL | PARTIAL | Calculated, but the source is known to be incomplete — e.g. payload counts when IKEv2 encrypted (SK) payloads hide part of the chain. The number is a floor, not a total |
| UNAVAILABLE | MISSING_SOURCE_DATA | Not calculated; `value` is null and `detail` says why |

Every vector carries every registered feature for its level, so "not calculated" is
never confused with "not in this schema".

## Output validation

Before a value is stored it is checked against its definition: no NaN, no infinity, no
negative count, no ratio outside [0, 1], correct type (a boolean is never accepted as an
integer). A value that fails validation is stored as UNAVAILABLE with the reason, never
as a number a later model would treat as real.

## Source tiers at session level

Two tiers feed session features, and they are kept apart:

- The **stored session record** always exists once discovery has run. Counts, duration,
  protocol shares and per-second rates are always calculable from it.
- The **individual packets** exist only while the originating capture is loaded.
  Distribution (median, variance), timing (interarrival), directional and burst
  features need them and are UNAVAILABLE when the capture is gone. They are never
  approximated from the aggregates.

## Direction

"Outbound" means *the same direction as the session's first observed packet*. That is
the one evidence-based reference the correlation engine provides. Direction is never
inferred from address ordering; a packet outside any session has direction UNAVAILABLE.

## Burst window

Burst features use a fixed **1-second tumbling window** aligned to the first packet.
The window is a documented constant, not a tuned one. No "burst count" is emitted: deciding
which peak counts as unusual needs a baseline, which is Layer 06 work.

## Retransmissions

Counted only for IKEv2, where a message ID identifies one exchange in one direction, so a
repeat from the same address is a retransmission. IKEv1 reuses message ID 0 across Phase 1,
which would manufacture false positives, so IKEv1 sessions report UNAVAILABLE.

## Formulas

| feature | formula |
|---|---|
| `byte_count` (SESSION) | `sum(packet_length)` |
| `session_duration_seconds` (SESSION) | `last_seen - first_seen` |
| `mean_interarrival_time` (SESSION) | `sum(t[i] - t[i-1]) / (n - 1)` |
| `interarrival_variance` (SESSION) | `sum((gap - mean_gap)^2) / n_gaps` |
| `average_packet_size` (SESSION) | `byte_count / packet_count` |
| `packet_size_variance` (SESSION) | `sum((len - mean_len)^2) / n` |
| `packet_size_standard_deviation` (SESSION) | `sqrt(packet_size_variance)` |
| `packets_per_second` (SESSION) | `packet_count / session_duration_seconds` |
| `bytes_per_second` (SESSION) | `byte_count / session_duration_seconds` |
| `ike_packets_per_second` (SESSION) | `ike_packet_count / session_duration_seconds` |
| `esp_packets_per_second` (SESSION) | `esp_packet_count / session_duration_seconds` |
| `maximum_packets_in_window` (SESSION) | `max over 1s windows of count(packets in window)` |
| `maximum_bytes_in_window` (SESSION) | `max over 1s windows of sum(packet_length in window)` |
| `inbound_outbound_packet_ratio` (SESSION) | `inbound_packets / outbound_packets` |
| `inbound_outbound_byte_ratio` (SESSION) | `inbound_bytes / outbound_bytes` |
| `ike_ratio` (SESSION) | `ike_packet_count / packet_count` |
| `esp_ratio` (SESSION) | `esp_packet_count / packet_count` |
| `ah_ratio` (SESSION) | `ah_packet_count / packet_count` |
| `udp_ratio` (SESSION) | `udp_packets / packet_count` |
| `tcp_ratio` (SESSION) | `tcp_packets / packet_count` |
| `other_ratio` (SESSION) | `1 - udp_ratio - tcp_ratio` |
| `ike_exchange_count` (SESSION) | `count(distinct (exchange_name, message_id))` |
| `ike_payload_count` (SESSION) | `sum(ike_payload_count per message)` |
| `retransmission_count` (SESSION) | `sum over (direction, message_id) of max(0, occurrences - 1)` |
| `sa_duration_seconds` (SA) | `last_seen - first_seen` |
| `average_packet_size` (SA) | `sa_byte_count / sa_packet_count` |
| `state_transition_count` (SA) | `count(events where new_state != previous_state)` |
| `mean_rekey_interval` (SA) | `sum(rekey[i] - rekey[i-1]) / (rekeys - 1)` |

## PACKET features

| name | display name | type | unit | category | source | description |
|---|---|---|---|---|---|---|
| `packet_length` | Packet Length | INTEGER | bytes | TRAFFIC | Layer 03 decoded packet | Length of the frame on the wire. |
| `captured_length` | Captured Length | INTEGER | bytes | TRAFFIC | Layer 03 decoded packet | Bytes actually stored in the capture file; lower than packet length when the capture was snapped short. |
| `ip_version` | IP Version | INTEGER | — | PROTOCOL | Layer 03 decoded packet — IP header | IP version of the packet, 4 or 6. |
| `transport_protocol` | Transport Protocol | CATEGORICAL | — | PROTOCOL | Layer 03 decoded packet — transport header | Decoded transport layer: TCP, UDP or ICMP. Null when the packet carries ESP or AH directly over IP. |
| `source_port` | Source Port | INTEGER | — | PROTOCOL | Layer 03 decoded packet — transport header | Transport source port; present for TCP and UDP only. |
| `destination_port` | Destination Port | INTEGER | — | PROTOCOL | Layer 03 decoded packet — transport header | Transport destination port; present for TCP and UDP only. |
| `fragmented` | Fragmented | BOOLEAN | — | PROTOCOL | Layer 03 decoded packet — IP header | The IP header marks this packet as a fragment. |
| `direction` | Direction | CATEGORICAL | — | DIRECTIONAL | IPsec session record (Section 6) | Direction relative to the session's first observed packet: OUTBOUND matches it, INBOUND is the reverse. UNKNOWN when the packet belongs to no discovered session. |
| `is_ike` | Is IKE | BOOLEAN | — | IPSEC | Layer 03 decoded packet — IPsec layer | The packet carries a decoded IKE message. |
| `is_esp` | Is ESP | BOOLEAN | — | IPSEC | Layer 03 decoded packet — IPsec layer | The packet carries a decoded ESP header. |
| `is_ah` | Is AH | BOOLEAN | — | IPSEC | Layer 03 decoded packet — IPsec layer | The packet carries a decoded AH header. |
| `is_nat_t` | Is NAT-T | BOOLEAN | — | IPSEC | Layer 03 decoded packet — IPsec layer | The packet is UDP-encapsulated for NAT traversal. |
| `ipsec_protocol` | IPsec Protocol | CATEGORICAL | — | IPSEC | Layer 03 decoded packet — IPsec layer | Which IPsec protocol the packet carries: IKE, ESP or AH. |
| `spi_present` | SPI Present | BOOLEAN | — | IPSEC | Layer 03 decoded packet — IPsec layer | A Security Parameter Index was decoded from the packet. |
| `spi_value` | SPI Value | CATEGORICAL | — | IPSEC | Layer 03 decoded packet — IPsec layer | The decoded SPI, as it appears in the header. A public header field, not key material. |
| `sequence_number` | Sequence Number | INTEGER | — | IPSEC | Layer 03 decoded packet — IPsec layer | ESP or AH anti-replay sequence number. |
| `encrypted_payload_present` | Encrypted Payload Present | BOOLEAN | — | IPSEC | Layer 03 decoded packet — IKE header | The IKE message carries an encrypted (SK) payload whose contents are not decoded. |
| `ike_version` | IKE Version | CATEGORICAL | — | IKE | Layer 03 decoded packet — IKE header | IKE version string from the message header. |
| `ike_exchange_type` | IKE Exchange Type | INTEGER | — | IKE | Layer 03 decoded packet — IKE header | Numeric exchange type from the IKE header. |
| `ike_exchange_name` | IKE Exchange Name | CATEGORICAL | — | IKE | Layer 03 decoded packet — IKE header | Decoded name of the IKE exchange type. |
| `ike_message_id` | IKE Message ID | INTEGER | — | IKE | Layer 03 decoded packet — IKE header | Message ID from the IKE header. |
| `ike_payload_count` | IKE Payload Count | INTEGER | payloads | IKE | Layer 03 decoded packet — IKE header | Number of payloads visible in the message's payload chain. Payloads inside an encrypted SK payload are not counted. |

## SESSION features

| name | display name | type | unit | category | source | description |
|---|---|---|---|---|---|---|
| `packet_count` | Packet Count | INTEGER | packets | TRAFFIC | IPsec session record (Section 6) | Packets correlated into the session. |
| `byte_count` | Byte Count | INTEGER | bytes | TRAFFIC | IPsec session record (Section 6) | Sum of on-the-wire packet lengths in the session. |
| `ike_packet_count` | IKE Packet Count | INTEGER | packets | TRAFFIC | IPsec session record (Section 6) | Session packets carrying IKE. |
| `esp_packet_count` | ESP Packet Count | INTEGER | packets | TRAFFIC | IPsec session record (Section 6) | Session packets carrying ESP. |
| `ah_packet_count` | AH Packet Count | INTEGER | packets | TRAFFIC | IPsec session record (Section 6) | Session packets carrying AH. |
| `session_state` | Session State | CATEGORICAL | — | PROTOCOL | IPsec session record (Section 6) | State the correlation engine derived from observed exchanges. |
| `session_direction` | Session Direction | CATEGORICAL | — | DIRECTIONAL | IPsec session record (Section 6) | Whether traffic was seen in one or both directions. |
| `nat_traversal_observed` | NAT Traversal Observed | BOOLEAN | — | IPSEC | IPsec session record (Section 6) | At least one session packet was UDP-encapsulated for NAT traversal. |
| `first_seen` | First Seen | TIMESTAMP | — | TIMING | IPsec session record (Section 6) | Timestamp of the earliest session packet. |
| `last_seen` | Last Seen | TIMESTAMP | — | TIMING | IPsec session record (Section 6) | Timestamp of the latest session packet. |
| `session_duration_seconds` | Session Duration | FLOAT | seconds | TIMING | IPsec session record (Section 6) | Elapsed time between the first and last session packet. |
| `mean_interarrival_time` | Mean Interarrival Time | FLOAT | seconds | TIMING | Packets associated with the IPsec session | Mean gap between consecutive session packets. Needs at least two timestamped packets. |
| `min_interarrival_time` | Minimum Interarrival Time | FLOAT | seconds | TIMING | Packets associated with the IPsec session | Smallest gap between consecutive session packets. |
| `max_interarrival_time` | Maximum Interarrival Time | FLOAT | seconds | TIMING | Packets associated with the IPsec session | Largest gap between consecutive session packets. |
| `interarrival_variance` | Interarrival Variance | FLOAT | seconds^2 | TIMING | Packets associated with the IPsec session | Population variance of the interarrival gaps. |
| `average_packet_size` | Average Packet Size | FLOAT | bytes | STATISTICAL | IPsec session record (Section 6) | Mean on-the-wire length of the session's packets. |
| `median_packet_size` | Median Packet Size | FLOAT | bytes | STATISTICAL | Packets associated with the IPsec session | Median on-the-wire packet length. |
| `minimum_packet_size` | Minimum Packet Size | INTEGER | bytes | STATISTICAL | Packets associated with the IPsec session | Smallest on-the-wire packet length in the session. |
| `maximum_packet_size` | Maximum Packet Size | INTEGER | bytes | STATISTICAL | Packets associated with the IPsec session | Largest on-the-wire packet length in the session. |
| `packet_size_variance` | Packet Size Variance | FLOAT | bytes^2 | STATISTICAL | Packets associated with the IPsec session | Population variance of packet lengths. |
| `packet_size_standard_deviation` | Packet Size Std. Deviation | FLOAT | bytes | STATISTICAL | Packets associated with the IPsec session | Square root of the packet size variance. |
| `packets_per_second` | Packets per Second | FLOAT | packets/second | TRAFFIC | IPsec session record (Section 6) | Packet rate over the session duration. Not calculated for a zero-length session. |
| `bytes_per_second` | Bytes per Second | FLOAT | bytes/second | TRAFFIC | IPsec session record (Section 6) | Byte rate over the session duration. |
| `ike_packets_per_second` | IKE Packets per Second | FLOAT | packets/second | TRAFFIC | IPsec session record (Section 6) | IKE packet rate over the session duration. |
| `esp_packets_per_second` | ESP Packets per Second | FLOAT | packets/second | TRAFFIC | IPsec session record (Section 6) | ESP packet rate over the session duration. |
| `maximum_packets_in_window` | Max Packets in Window | INTEGER | packets | TRAFFIC | Packets associated with the IPsec session | Most packets falling in any 1-second tumbling window aligned to the session start. |
| `maximum_bytes_in_window` | Max Bytes in Window | INTEGER | bytes | TRAFFIC | Packets associated with the IPsec session | Most bytes falling in any 1-second tumbling window aligned to the session start. |
| `inbound_packets` | Inbound Packets | INTEGER | packets | DIRECTIONAL | Packets associated with the IPsec session | Packets travelling opposite to the session's first observed packet. |
| `outbound_packets` | Outbound Packets | INTEGER | packets | DIRECTIONAL | Packets associated with the IPsec session | Packets travelling in the same direction as the session's first observed packet. |
| `inbound_bytes` | Inbound Bytes | INTEGER | bytes | DIRECTIONAL | Packets associated with the IPsec session | On-the-wire bytes in the inbound direction. |
| `outbound_bytes` | Outbound Bytes | INTEGER | bytes | DIRECTIONAL | Packets associated with the IPsec session | On-the-wire bytes in the outbound direction. |
| `inbound_outbound_packet_ratio` | Inbound/Outbound Packet Ratio | FLOAT | ratio | DIRECTIONAL | Packets associated with the IPsec session | Inbound packets divided by outbound packets. Not calculated when no outbound packet was observed. |
| `inbound_outbound_byte_ratio` | Inbound/Outbound Byte Ratio | FLOAT | ratio | DIRECTIONAL | Packets associated with the IPsec session | Inbound bytes divided by outbound bytes. Not calculated when no outbound byte was observed. |
| `ike_ratio` | IKE Ratio | FLOAT | ratio | PROTOCOL | IPsec session record (Section 6) | Share of session packets carrying IKE. |
| `esp_ratio` | ESP Ratio | FLOAT | ratio | PROTOCOL | IPsec session record (Section 6) | Share of session packets carrying ESP. |
| `ah_ratio` | AH Ratio | FLOAT | ratio | PROTOCOL | IPsec session record (Section 6) | Share of session packets carrying AH. |
| `udp_ratio` | UDP Ratio | FLOAT | ratio | PROTOCOL | Packets associated with the IPsec session | Share of session packets carried over UDP, which covers IKE and NAT-T encapsulated ESP. |
| `tcp_ratio` | TCP Ratio | FLOAT | ratio | PROTOCOL | Packets associated with the IPsec session | Share of session packets carried over TCP. |
| `other_ratio` | Other Transport Ratio | FLOAT | ratio | PROTOCOL | Packets associated with the IPsec session | Share of session packets carried directly over IP with no transport header, that is native ESP or AH. |
| `ike_version` | IKE Version | CATEGORICAL | — | IKE | IPsec session record (Section 6) | IKE version observed in the session. |
| `ike_message_count` | IKE Message Count | INTEGER | messages | IKE | IPsec session record (Section 6) | Number of IKE messages observed in the session. |
| `ike_exchange_count` | IKE Exchange Count | INTEGER | exchanges | IKE | Packets associated with the IPsec session | Distinct IKE exchanges observed, counted as unique exchange type and message ID pairs. |
| `unique_exchange_types` | Unique Exchange Types | INTEGER | types | IKE | IPsec session record — IKE observations (Section 6) | Number of distinct IKE exchange types observed. |
| `ike_payload_count` | IKE Payload Count | INTEGER | payloads | IKE | Packets associated with the IPsec session | Total payloads visible across the session's IKE messages. Payloads inside encrypted SK payloads are not counted. |
| `notify_payload_count` | Notify Payload Count | INTEGER | payloads | IKE | Packets associated with the IPsec session | Visible NOTIFY payloads across the session's IKE messages. |
| `delete_payload_count` | Delete Payload Count | INTEGER | payloads | IKE | Packets associated with the IPsec session | Visible DELETE payloads across the session's IKE messages. |
| `retransmission_count` | Retransmission Count | INTEGER | messages | IKE | Packets associated with the IPsec session | Repeat IKEv2 messages, counted as occurrences of a direction and message ID pair beyond the first. Only calculated for IKEv2, where message IDs are unique per exchange and direction. |
| `ike_sa_init_observed` | IKE_SA_INIT Observed | BOOLEAN | — | IKE | IPsec session record — IKE observations (Section 6) | An IKE_SA_INIT exchange was observed. |
| `ike_auth_observed` | IKE_AUTH Observed | BOOLEAN | — | IKE | IPsec session record — IKE observations (Section 6) | An IKE_AUTH exchange was observed. |
| `create_child_sa_observed` | CREATE_CHILD_SA Observed | BOOLEAN | — | IKE | IPsec session record — IKE observations (Section 6) | A CREATE_CHILD_SA exchange was observed. |
| `informational_exchange_observed` | Informational Exchange Observed | BOOLEAN | — | IKE | IPsec session record — IKE observations (Section 6) | An INFORMATIONAL exchange was observed. |
| `delete_payload_observed` | Delete Payload Observed | BOOLEAN | — | IKE | IPsec session record — IKE observations (Section 6) | A DELETE payload was visible in the clear. |
| `notify_payload_observed` | Notify Payload Observed | BOOLEAN | — | IKE | IPsec session record — IKE observations (Section 6) | A NOTIFY payload was visible in the clear. |

## SA features

| name | display name | type | unit | category | source | description |
|---|---|---|---|---|---|---|
| `sa_type` | SA Type | CATEGORICAL | — | SA_LIFECYCLE | Security Association record (Layer 04) | Whether the association is an IKE SA or a child SA. |
| `sa_state` | SA State | CATEGORICAL | — | SA_LIFECYCLE | Security Association record (Layer 04) | Lifecycle state the engine derived from cited packet evidence. |
| `sa_protocol` | SA Protocol | CATEGORICAL | — | IPSEC | Security Association record (Layer 04) | Protocol the association carries: IKE, ESP or AH. |
| `ike_version` | IKE Version | CATEGORICAL | — | IKE | Security Association record (Layer 04) | IKE version associated with the SA. |
| `nat_traversal_observed` | NAT Traversal Observed | BOOLEAN | — | IPSEC | Security Association record (Layer 04) | At least one of the SA's packets was UDP-encapsulated for NAT traversal. |
| `first_seen` | First Seen | TIMESTAMP | — | TIMING | Security Association record (Layer 04) | Timestamp of the SA's earliest packet. |
| `last_seen` | Last Seen | TIMESTAMP | — | TIMING | Security Association record (Layer 04) | Timestamp of the SA's latest packet. |
| `sa_duration_seconds` | SA Duration | FLOAT | seconds | TIMING | Security Association record (Layer 04) | Elapsed time between the SA's first and last observed packet. This is an observation window, not a negotiated lifetime. |
| `sa_packet_count` | SA Packet Count | INTEGER | packets | TRAFFIC | Security Association record (Layer 04) | Packets attributed to the SA. |
| `sa_byte_count` | SA Byte Count | INTEGER | bytes | TRAFFIC | Security Association record (Layer 04) | On-the-wire bytes attributed to the SA. |
| `average_packet_size` | Average Packet Size | FLOAT | bytes | STATISTICAL | Security Association record (Layer 04) | Mean on-the-wire length of the SA's packets. |
| `child_sa_count` | Child SA Count | INTEGER | SAs | SA_LIFECYCLE | Security Association record (Layer 04) | Child SAs correlated to this IKE SA. Only meaningful for an IKE SA. |
| `state_transition_count` | State Transition Count | INTEGER | transitions | SA_LIFECYCLE | SA lifecycle events (Layer 04) | Lifecycle events that changed the SA's state. |
| `capture_ended_in_state` | Capture Ended in State | BOOLEAN | — | SA_LIFECYCLE | Security Association record (Layer 04) | The capture ended while the SA was still in a non-terminal state, so its lifecycle is truncated by the observation window. |
| `negotiation_observed` | Negotiation Observed | BOOLEAN | — | SA_LIFECYCLE | SA lifecycle events (Layer 04) | A negotiation exchange was observed for this SA. |
| `establishment_observed` | Establishment Observed | BOOLEAN | — | SA_LIFECYCLE | SA lifecycle events (Layer 04) | Evidence of establishment was observed, such as an IKE_AUTH response. |
| `active_traffic_observed` | Active Traffic Observed | BOOLEAN | — | SA_LIFECYCLE | SA lifecycle events (Layer 04) | Protected traffic was observed under this SA. |
| `rekey_observed` | Rekey Observed | BOOLEAN | — | SA_LIFECYCLE | SA lifecycle events (Layer 04) | A rekey exchange was observed. |
| `termination_observed` | Termination Observed | BOOLEAN | — | SA_LIFECYCLE | SA lifecycle events (Layer 04) | A plaintext DELETE payload terminated the SA. The end of a capture is never counted as termination. |
| `failed_negotiation_observed` | Failed Negotiation Observed | BOOLEAN | — | SA_LIFECYCLE | SA lifecycle events (Layer 04) | A negotiation failure was observed, that is an IKE_SA_INIT response carrying only NOTIFY payloads. |
| `rekey_count` | Rekey Count | INTEGER | rekeys | SA_LIFECYCLE | Security Association record (Layer 04) | Rekey exchanges observed on this SA. Only calculated for IKE SAs, where rekeys are visible. |
| `last_rekey_time` | Last Rekey Time | TIMESTAMP | — | TIMING | SA lifecycle events (Layer 04) | Timestamp of the most recent observed rekey. |
| `mean_rekey_interval` | Mean Rekey Interval | FLOAT | seconds | TIMING | SA lifecycle events (Layer 04) | Mean gap between observed rekeys. Needs at least two rekey events. |
| `min_rekey_interval` | Minimum Rekey Interval | FLOAT | seconds | TIMING | SA lifecycle events (Layer 04) | Smallest gap between observed rekeys. |
| `max_rekey_interval` | Maximum Rekey Interval | FLOAT | seconds | TIMING | SA lifecycle events (Layer 04) | Largest gap between observed rekeys. |

## Persistence

Tables `feature_vectors` and `feature_values` in the existing SQLite database. Values are
stored in typed columns (`value_integer`, `value_float`, `value_boolean`, `value_text`), not
as strings. Definitions are **not** stored: the registry is code-owned so it cannot drift.
A vector's id is deterministic for `(capture, entity_type, entity_id)`, so re-extraction
replaces rather than duplicates.

## API

    GET    /api/features/status
    GET    /api/features/definitions
    GET    /api/features/entities?entity_type=PACKET|SESSION|SA
    GET    /api/features?entity_type=&page=&page_size=
    POST   /api/features/extract            {entity_type, entity_id}
    GET    /api/features/{vector_id}
    GET    /api/features/entity/{entity_type}/{entity_id}
    GET    /api/features/export?format=json|csv
    DELETE /api/features

## Versioning

Bump `FEATURE_VERSION` whenever a feature's *meaning* changes. Never reuse a name for a
different calculation. Later baseline and AI modules record the version they were built
against.

