# Architecture notes

## Source of truth for the 14 layers

`backend/app/core/architecture.py` holds the only authoritative list of layer
numbers, names, package paths, statuses and descriptions. The
`GET /api/system/status` endpoint serves that list, and the frontend consumes
it through `frontend/src/services/api.ts`. No other file restates the layer
names.

To change a layer's status, edit the `status` field of its entry in
`ARCHITECTURE_LAYERS`. The API, the tests and the frontend all follow.

## Backend layout

| Path | Responsibility |
| --- | --- |
| `app/core/` | Configuration, logging, architecture metadata, error types |
| `app/db/` | SQLAlchemy engine, session factory, schema creation and seeding |
| `app/models/` | ORM models |
| `app/schemas/` | Pydantic request and response models |
| `app/api/` | Route modules and the aggregate router |
| `app/services/` | Logic shared between routes and future layers |
| `app/websocket/` | Connection manager and the `/ws/events` route |
| `app/layers/` | One placeholder package per architecture layer |

Routes stay thin: they resolve dependencies and delegate to a service. Future
layers add their own models, schemas and routers in the same directories and
register the router in `app/api/router.py`.

## Frontend layout

`services/` owns every network call and converts failures into `ApiError` or
`NetworkError`. `hooks/` wraps those calls in loading and error state. `pages/`
and `components/` render; they never call `fetch` directly. Types in `types/`
mirror the backend schemas.

## Not implemented

Nothing in this repository captures packets, parses IPsec, evaluates security
rules, computes risk or generates reports. The `app/layers/` packages are empty
placeholders.

## Frontend shell (Section 1)

The shell is composed from four single-responsibility sources:

- `src/index.css` declares the design tokens as CSS custom properties, and
  `tailwind.config.js` maps them onto Tailwind colour names. Components use
  token names (`bg-surface`, `text-muted`, `border-border`) and never raw hex
  values, so the whole palette can be changed in one file.
- `src/config/navigation.ts` is the only definition of the sidebar. The routes
  in `App.tsx` and the sidebar items are both derived from it, so navigation
  and routing cannot disagree.
- `src/config/branding.ts` holds the official project name. The compact
  three-line sidebar wordmark is shorthand for display only.
- `src/context/SystemStateContext.tsx` fetches `/api/health` and
  `/api/system/status` once and shares the result, so the header and pages make
  one pair of requests between them rather than one each.

Status handling is centralised in `components/status/StatusBadge.tsx`. Each
status maps to a tone and a distinct icon, so state is never communicated by
colour alone.

When the backend is unreachable the shell reports `BACKEND OFFLINE`, renders an
error state with a retry action, and leaves navigation fully usable. It never
asserts a status it has not received.

## Overview dashboard (Section 2)

`src/hooks/useDashboardData.ts` assembles the dashboard model. It is the single
place that decides what each figure is. Because only `/api/health` and
`/api/system/status` exist, every security collection is `null`, and every
metric carries `source: 'unavailable'`.

The dashboard draws a hard line between two states that look similar on
screen but mean opposite things:

- `null` — the producing engine is not initialised. Rendered as
  NOT INITIALIZED or NO DATA AVAILABLE.
- `[]` — the engine ran and observed nothing. Rendered as, for example,
  NO TRAFFIC RECORDED.

A later section replaces the `null`s with real API calls; the components need
no change. Charts (`components/dashboard/charts/`) render Recharts only when
given a non-empty array, so nothing is drawn from invented data.

Risk classification bands live in `src/config/risk.ts` and are applied only to
a real score. The gauge draws the band track without a needle until then.

## Architecture page (Section 3)

`/architecture` renders the pipeline from `/api/system/status`. The backend
remains the only place layer names, statuses and descriptions are defined.
The frontend adds presentation-only metadata in `src/config/architecture.ts`
— icons, category grouping, purpose text, future inputs and outputs, and the
existing dashboard route — keyed by layer number, never by name.

`buildArchitectureLayers` validates the payload before rendering: fourteen
contiguous layers, recognised statuses, non-empty names. Anything else renders
ARCHITECTURE DATA UNAVAILABLE rather than a partial diagram. Progress figures
are computed from the merged list by `summarizeProgress`.

Section 3 changed Layer 13 (Web Dashboard) from FOUNDATION READY to
FOUNDATION CREATED in the backend source of truth, per that section's brief.
`tests/backend/test_architecture.py` now pins the full sequence.

## Live Monitor (Section 4)

`src/services/realtimeService.ts` is the only owner of the `/ws/events`
socket. It exposes state (`IDLE`, `CONNECTING`, `CONNECTED`, `DISCONNECTED`,
`RECONNECTING`, `ERROR`) and typed frames; reconnect backs off from 1 s
doubling to 30 s and stops after five attempts, after which the user can
retry explicitly. `useRealtime` subscribes a page for its lifetime and keeps
bounded buffers (`src/config/monitor.ts`) so the DOM cannot grow unbounded.

The service never synthesises frames. The only entries in System Activity are
the socket's own connect/disconnect transitions, stamped when they occur.

`useLiveMonitorData` reports every capture, session, SA and analysis
collection as `null`, following the same convention as the dashboard. Tables,
charts and detail panels accept the future shapes today; a later section swaps
the nulls for real service calls without touching the components.

Detail panels for packets, sessions and SAs display algorithm names,
identifiers and lifetimes only. Key material and credentials have no fields
and cannot be rendered.

## Packet analysis (Section 5, Layer 03)

`backend/app/layers/layer03_protocol_analysis/` is a dependency-free decoder
built on `struct` and the RFC header layouts:

| Module | Responsibility |
| --- | --- |
| `capture_reader.py` | pcap (both endiannesses, µs and ns) and pcapng (SHB/IDB/EPB/SPB) |
| `link_layer.py` | Ethernet II, 802.1Q, Linux SLL, raw IP link types |
| `network_layer.py` | IPv4 (options, fragmentation) and IPv6 (extension headers) |
| `transport_layer.py` | TCP flags/offset, UDP, ICMP / ICMPv6 |
| `ipsec.py` | ESP (RFC 4303), AH (RFC 4302), NAT-T discrimination (RFC 3948) |
| `ike.py` | ISAKMP header, IKEv1/IKEv2 exchange names, payload chain, SK detection |
| `analyzer.py` | Composes the above into `PacketAnalysisResult`; isolates failures per packet |

Scapy was deliberately not used here. Fixed-layout headers decode
deterministically with `struct`, the parser stays under a few hundred lines
that the test suite covers byte for byte, and Scapy remains reserved for
Layer 02's live capture where its interface handling earns its weight.

Protocol identification is structural. UDP/500 or UDP/4500 is treated as IKE
only when a 28-byte ISAKMP header with major version 1 or 2 follows (after
the non-ESP marker on 4500); a nonzero first word on 4500 is ESP-in-UDP; a
single 0xFF byte is a NAT-T keepalive. Anything else stays UDP.

A decoding failure marks that packet MALFORMED with the affected protocol and
keeps every layer decoded before the failure. It is a parser observation,
not a security finding — Layer 09 owns those.

`app/services/packet_service.py` holds one capture in memory (bounded by
size and packet count), serves filtered/sorted/paginated queries and computes
statistics from the decoded packets. The frontend controller
`usePacketAnalysis` is the only caller; components render what it returns.
Frontend tests run against `tests/fixtures/packets.json`, which is the real
decoder's JSON for a byte-built capture, regenerated from the backend.

## IPsec sessions (Section 6 — supporting module, not a layer)

The official architecture is unchanged: Layer 06 remains *Session
Fingerprinting & Baseline Profiling* and stays NOT INITIALIZED. The sessions
page is an application module that reads Layer 03 output.

`app/services/session_correlation.py` groups decoded IKE/ESP/AH packets into
sessions using only what the packets carry:

1. An unordered endpoint pair {A, B} bounds a session — it is the one
   identifier every packet of an IKE SA and its child SAs shares. Binding a
   specific ESP SPI to a specific IKE SA needs negotiated SA parameters,
   which is Layer 04 work, so ESP/AH packets attach to the pair.
2. An inactivity gap over 300 s inside a pair starts a new session.
3. State is derived from observed exchanges and each session lists its
   evidence: a plaintext DELETE payload → TERMINATED; ESP/AH traffic →
   ACTIVE; an IKE_AUTH response or IKEv1 Quick Mode → ESTABLISHED;
   negotiation exchanges without either → NEGOTIATING; only INFORMATIONAL /
   CREATE_CHILD_SA → DISCOVERED. Encrypted IKEv2 DELETEs inside SK cannot be
   seen and are not guessed at.
4. Direction is relative to the IKE initiator when one is identifiable.
5. Correlation quality is categorical (DIRECT / CORRELATED / PARTIAL /
   UNKNOWN), never a percentage.

Session IDs are `IPSEC-` plus twelve hex characters of a SHA-256 over the
capture ID, endpoint pair, start time and ordinal, so re-running discovery on
the same capture yields the same IDs.

`app/services/session_service.py` persists sessions and packet associations
to SQLite (`ipsec_sessions`, `session_packets`) keyed by capture ID.
Association is by packet number, which is stable within a capture; packet
UUIDs are not. Clearing a capture clears its sessions.
