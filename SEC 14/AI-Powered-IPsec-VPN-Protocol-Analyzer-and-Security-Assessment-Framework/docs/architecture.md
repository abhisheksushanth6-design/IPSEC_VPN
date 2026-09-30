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

## Operational Status & Layer Architecture

Every one of the fourteen architectural layers is fully implemented, integrated, and verified at runtime:

- **Layer 01 — IPsec VPN Test Environment**: StrongSwan 3-VM virtual testbed (`192.168.56.20` Client, `192.168.56.104` Analyzer / Sniffer, `192.168.56.30` Server), host-only virtual networking, automated SSH control, and realistic traffic generators (Tunnel/Transport mode, VoIP SIP/RTP, Video streaming).
- **Layer 02 — Packet Capture & Data Collection**: Live network interface packet sniffer and PCAP reader (pcap/pcapng) using Scapy and raw sockets with bounded ring buffers.
- **Layer 03 — Packet & Protocol Analysis**: High-speed, dependency-free binary protocol decoder parsing Ethernet II, Linux SLL, 802.1Q, IPv4/IPv6, UDP/TCP/ICMP, ESP (RFC 4303), AH (RFC 4302), NAT-T (RFC 3948), and IKEv1/IKEv2 exchange headers and payload chains.
- **Layer 04 — Security State & SA Lifecycle Engine**: Chronological state engine tracking IKE and Child Security Associations across state transitions (DETECTED, NEGOTIATING, ESTABLISHED, ACTIVE, REKEYING, TERMINATED, FAILED).
- **Layer 05 — Feature Extraction & Engineering**: Versioned 35-dimensional feature vectors capturing protocol mechanics, packet sizes, entropy, timing distributions, and directional asymmetry.
- **Layer 06 — Session Fingerprinting & Baseline Profiling**: Deterministic SHA-256 session fingerprints and behavioral statistical baselines for anomaly detection.
- **Layer 07 — Security Drift Detection**: Statistical deviation analysis evaluating active sessions against established baselines to detect behavioral and configuration drift.
- **Layer 08 — AI / ML Anomaly Detection Engine**: Unsupervised Isolation Forest and pre-trained CIC-IDS benchmark models detecting non-linear protocol anomalies without relying on rigid signatures.
- **Layer 09 — Security Rule & Vulnerability Engine**: Rule-based vulnerability evaluator auditing cryptographic proposals (DES/3DES, MD5/SHA1, weak DH groups 1/2/5), replay attacks, missing PFS, and cleartext leakage.
- **Layer 10 — Risk Assessment & Decision Engine**: Multi-factor quantitative risk scoring engine (0-100 score, CRITICAL/HIGH/MEDIUM/LOW/INFO severity classifications) and context-aware remediation roadmaps.
- **Layer 11 — Security Databases (SQLite)**: Relational SQLite schema with 13 core tables, connection pooling, and table integrity tracking.
- **Layer 12 — Backend & API (FastAPI)**: 22 modular API routers, OpenAPI documentation, WebSocket event bus, and runtime health verification.
- **Layer 13 — Web Dashboard**: Real-time Security Operations Center (SOC) dashboard presenting system posture, protocol distributions, risk gauges, and session timelines.
- **Layer 14 — Report Generation (PDF)**: Automated generation of professional executive and technical PDF security assessment reports using ReportLab.

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

## Security State & SA Lifecycle Engine (Section 7, Layer 04)

`backend/app/layers/layer04_sa_lifecycle/engine.py` derives Security
Associations from Layer 03 output in a single chronological pass per endpoint
pair. Identity: an IKE SA is (capture, endpoint pair, initiator SPI); a child
SA is (capture, endpoint pair, protocol, SPI), one per direction. Child SAs
are attributed to the IKE SA between the same endpoints whose activity most
recently precedes the child's first packet, and the association is labelled
CORRELATED because the binding SPI is negotiated inside payloads the decoder
does not read.

State transitions and the evidence that produces them:

| Transition | Evidence |
| --- | --- |
| → DETECTED | first IKE message for the initiator SPI |
| → NEGOTIATING | IKE_SA_INIT, Main Mode, Aggressive or Base exchange |
| → ESTABLISHED | IKE_AUTH *response*, or IKEv1 Quick Mode |
| ESTABLISHED → ACTIVE | ESP/AH traffic attributed to the SA |
| → REKEYING | CREATE_CHILD_SA request on an established SA; a second Quick Mode |
| REKEYING → previous state | CREATE_CHILD_SA response |
| → TERMINATED | a plaintext DELETE payload |
| → FAILED | IKE_SA_INIT response whose visible payloads are only NOTIFY |

The engine never marks EXPIRED (lifetimes are not decoded), never treats the
end of a capture as termination (a CAPTURE ENDED event records the state
instead), never reads inside SK payloads, and never calls a new SPI a rekey
without a rekey exchange. Every transition cites its packet number. Algorithms
and traffic selectors are reported as NOT AVAILABLE rather than guessed.

Persistence is in `security_associations`, `sa_lifecycle_events`
(append-only) and `sa_packet_links`, keyed by capture ID. Sessions are linked
by looking up Section 6's `session_packets`; without session discovery the
link is simply absent.

## 3-VM IPsec Testbed Configuration & Network Topology (Layer 01)

The testbed reproduces real enterprise site-to-site and host-to-host IPsec VPN architectures within an isolated VirtualBox environment:

```
+--------------------------+       +----------------------------+       +--------------------------+
|       IPsec Client       |       |       Analyzer / GW        |       |       IPsec Server       |
|      192.168.56.20       |<----->|       192.168.56.104       |<----->|      192.168.56.30       |
| StrongSwan (Initiator)   |       | Inline Sniffer / Framework |       | StrongSwan (Responder)   |
+--------------------------+       +----------------------------+       +--------------------------+
             \                                  |                                  /
              \_________________ Host-Only Network (vboxnet0) ____________________/
```

- **IPsec-Client (`192.168.56.20`)**: StrongSwan 5.9 initiator generating IKEv1/IKEv2 negotiations, ESP/AH tunnels, SIP VoIP audio traffic (SIP/5060, RTP/10000+), and HTTP/RTSP video streaming.
- **IPsec-Server (`192.168.56.30`)**: StrongSwan 5.9 responder terminating IPsec tunnels, handling rekeying events, and echoing bidirectional application traffic.
- **Analyzer / Gateway (`192.168.56.104`)**: Inline packet capture host executing Scapy capture engines on `eth1`/`vboxnet0`, hosting the FastAPI backend, and running real-time protocol decoders.
- **Automation**: Managed via `Layer01TestEnvironmentService` using `sshpass` and non-interactive sudoers scripts to orchestrate scenario execution (tunnel mode, transport mode, AH authentication, VoIP, video streaming).

## Intelligence, Detection & Platform Layers (Layers 05–14)

- **Layer 05 (Feature Engineering)**: Generates deterministic 35-dimensional vectors from decoded packets and session states (byte counts, packet size mean/std, IKE exchange counts, ESP sequence gaps, retransmissions, entropy).
- **Layer 06 (Session Fingerprinting & Baseline Profiling)**: Generates SHA-256 session fingerprints and creates statistical baseline profiles with mean and standard deviation matrices per feature dimension.
- **Layer 07 (Security Drift Detection)**: Calculates Mahalanobis and Z-score distances between active sessions and established baselines. Classifies drift into DRIFT_NONE, MINOR_DRIFT, and SIGNIFICANT_DRIFT.
- **Layer 08 (AI / ML Anomaly Detection Engine)**: Houses an Isolation Forest model and CIC-IDS pre-trained benchmarks. Computes normalized anomaly scores (-1.0 to 1.0) and top contributing features per session.
- **Layer 09 (Security Rule & Vulnerability Engine)**: Deterministic rule engine evaluating 15+ IPsec CVE/CWE patterns: weak encryption (DES, 3DES), weak integrity (MD5, SHA1), weak DH groups (DH 1, 2, 5), replay attacks, missing Perfect Forward Secrecy (PFS), and plaintext leaking.
- **Layer 10 (Risk Assessment & Decision Engine)**: Computes a unified quantitative risk score (0–100), maps severity levels, evaluates attack implications, and generates structured mitigation steps.
- **Layer 11 (Security Databases - SQLite)**: Manages 13 core relational tables (`system_settings`, `ipsec_sessions`, `session_packets`, `security_associations`, `sa_lifecycle_events`, `sa_packet_links`, `session_features`, `baseline_profiles`, `baseline_dimensions`, `drift_events`, `ml_models`, `vulnerability_findings`, `reports`) with foreign keys and WAL mode.
- **Layer 12 (Backend & API - FastAPI)**: Exposes 22 modular routers covering all system operations, WebSocket event fan-out, and Section 10 runtime verification endpoints.
- **Layer 13 (Web Dashboard)**: React/Vite dashboard presenting live system posture, protocol distributions, risk gauges, and interactive drill-down tables.
- **Layer 14 (Report Generation - PDF)**: Generates professional multi-page security assessment PDF reports using ReportLab with executive summaries, findings breakdown, and remediation roadmaps.

## Section 10 Runtime Verification Contract

Every architectural layer reports structured verification metrics to ensure complete architectural transparency:

```json
{
  "number": 1,
  "name": "IPsec VPN Test Environment",
  "package": "app.layers.layer01_test_environment",
  "status": "READY",
  "description": "VirtualBox-based 3-VM testbed and automated network topology.",
  "foundation_available": true,
  "implementation_available": true,
  "runtime_verified": true,
  "unit_tests_passed": true,
  "integration_tests_passed": true,
  "end_to_end_verified": true,
  "last_verified": "2026-09-12T14:30:00Z",
  "verification_errors": [],
  "limitations": []
}
```

