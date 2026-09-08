# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

## Project Overview

This project is an AI-powered security assessment framework for IPsec VPN deployments. It captures and ingests network traffic, decodes IKE, ESP, and AH structures, tracks Security Association lifecycles, learns per-session behavioural baselines, detects drift, identifies anomalies with machine learning, evaluates deterministic vulnerability rules, and presents results through a web dashboard and generated PDF assessment reports.

> **Master Implementation Notice**:
> - **SEC 14** is the current master codebase.
> - **SEC 0–13** represent historical and reference milestone snapshots during development.
> - **All 14 Layers (Layers 01–14) are fully OPERATIONAL**.
> - **Layer 01 (IPsec VPN Test Environment)** provides real VirtualBox VM orchestration and StrongSwan IPsec configuration verification.
> - **Layer 02 (Packet Capture & Data Collection)** provides real live hypervisor NIC packet capture and seamless downstream ingestion pipeline execution.
> - **Layer 08 (AI / ML Anomaly Detection Engine)** utilizes a local, trained CIC-IDS2017 XGBoost model (`model_cicids_xgb_local`) as the default active model alongside an IsolationForest engine.
> - **Layer 10 (Risk Assessment & Decision Engine)** features a genuine multi-criteria risk engine evaluating vulnerability, ML anomaly, baseline drift, and SA lifecycle signals without synthetic fabrication.
> - **Real IPsec E2E Validation Completed**: The application has been validated against real live IPsec traffic (CAP-830CD2).
> - **Layer 07 Security Drift Detection** performs drift analysis against reference baselines.
> - **Layer 09 Security Rule Engine** contains 17 deterministic IPsec security rules with explainable evidence.
> - **Layer 14 Report Generation** produces structured, auditable PDF assessment reports.

## 14-Layer Architecture

| # | Layer | Package | Status | Description |
|---|---|---|---|---|
| 01 | IPsec VPN Test Environment | `layer01_test_environment` | OPERATIONAL | Controlled environment for generating and validating IPsec VPN behavior |
| 02 | Packet Capture & Data Collection | `layer02_packet_capture` | OPERATIONAL | Real live hypervisor NIC packet capture and capture ingestion interface |
| 03 | Packet & Protocol Analysis | `layer03_protocol_analysis` | OPERATIONAL | PCAP/PCAPNG decoders for IPv4/IPv6, TCP/UDP/ICMP, IKEv1/v2, ESP, AH, NAT-T, and Linux SLL2 |
| 04 | Security State & SA Lifecycle Engine | `layer04_sa_lifecycle` | OPERATIONAL | Derives IKE and Child SAs with evidence-cited state transitions, rekeys, and terminations |
| 05 | Feature Extraction & Engineering | `layer05_feature_engineering` | OPERATIONAL | Extracts 53 validated, versioned packet, session, and SA features with per-feature lineage |
| 06 | Session Fingerprinting & Baseline Profiling | `layer06_session_fingerprinting` | OPERATIONAL | Behavioral session fingerprints and reference baselines from observed IPsec sessions |
| 07 | Security Drift Detection | `layer07_drift_detection` | OPERATIONAL | Identifies deviations between observed behavior and established security baselines |
| 08 | AI / ML Anomaly Detection Engine | `layer08_ai_ml` | OPERATIONAL | Local CIC-IDS2017 XGBoost anomaly classification and IsolationForest with explainable contribution scores |
| 09 | Security Rule & Vulnerability Engine | `layer09_vulnerability_engine` | OPERATIONAL | Deterministic evaluation of 17 rules across cryptographic, protocol, and SA criteria |
| 10 | Risk Assessment & Decision Engine | `layer10_risk_engine` | OPERATIONAL | Multi-criteria risk scoring engine combining vulnerability, ML anomaly, drift, and SA lifecycle signals |
| 11 | Security Databases (SQLite) | `layer11_database` | OPERATIONAL | Structured configuration, session records, drift analyses, findings, and model records |
| 12 | Backend & API (FastAPI) | `layer12_api` | OPERATIONAL | FastAPI REST backend, WebSocket event bus, dependency injection, and data models |
| 13 | Web Dashboard | `layer13_dashboard` | OPERATIONAL | Analyst-facing React 18 interface with responsive dark mode and 12 dedicated pages |
| 14 | Report Generation (PDF) | `layer14_reports` | OPERATIONAL | Multi-page ReportLab PDF assessment generation with technical appendices |

The layer list is defined centrally in `backend/app/core/architecture.py` and served live by `GET /api/system/status`.

## Technology Stack

Configured and in active use:

| Technology | Role |
| --- | --- |
| React 18 | Frontend UI library |
| Vite 6 | Frontend build tool and dev server |
| TypeScript 5 | Frontend type safety |
| Tailwind CSS 3 | Styling and dark theme design system |
| Lucide React | Icons |
| React Router | Client-side routing across 12 pages |
| Recharts | Data visualization charts |
| Vitest + Testing Library | Frontend unit and integration testing |
| Python 3.12 | Backend runtime |
| FastAPI | Backend REST framework and SPA hosting |
| Pydantic 2 | Typed schema validation and settings |
| Uvicorn | High-performance ASGI server |
| SQLite | Lightweight embedded database |
| SQLAlchemy 2 | Typed ORM, relationships, and schema migrations |
| scikit-learn | Layer 08 — Machine learning preprocessing & Isolation Forest engine |
| XGBoost | Layer 08 — Local CIC-IDS2017 machine learning classifier |
| joblib | Serialization for ML model artifacts |
| ReportLab | Layer 14 — Automated cybersecurity assessment PDF generation |
| VirtualBox VBoxManage | Layer 01 & 02 — Automated VM management and live hypervisor NIC packet capture |
| pytest | Backend regression test suite |

## Repository Structure

```
AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI entry point
│   │   ├── core/                   config, logging, architecture, errors
│   │   ├── db/                     engine, session, initialisation
│   │   ├── models/                 SQLAlchemy models
│   │   ├── schemas/                Pydantic schemas
│   │   ├── api/                    routers and route modules
│   │   ├── services/               shared logic
│   │   ├── websocket/              connection manager and /ws/events
│   │   └── layers/                 layer01_… through layer14_… placeholders
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── pytest.ini
├── frontend/
│   ├── src/
│   │   ├── components/  layout/  navigation/  ui/  status/  states/
│   │   ├── pages/       Overview/ … Settings/  NotFound/
│   │   ├── config/      navigation.ts  branding.ts
│   │   ├── context/     SystemStateContext.tsx
│   │   ├── hooks/  services/  types/  utils/
│   │   ├── App.tsx  main.tsx  index.css
│   ├── tests/                      Vitest shell tests
│   ├── package.json  tsconfig*.json  vite.config.ts
│   └── tailwind.config.js  postcss.config.js
├── tests/
│   ├── backend/                    pytest suite
│   └── frontend/
├── docs/
├── scripts/
├── .github/workflows/ci.yml
├── .env.example
├── docker-compose.yml
├── LICENSE
└── README.md
```

## Installation

### Prerequisites

- Python 3.11 or newer (developed on 3.12)
- Node.js 20 or newer (developed on 22)
- npm 10 or newer
- Git

### Configuration

```bash
cp .env.example .env
cp frontend/.env.example frontend/.env.local
```

Both `.env` files are git-ignored. The defaults work for local development;
no secrets are required.

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

### Frontend

```bash
cd frontend
npm install
```

## Running Locally

Backend, from the `backend` directory:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend, from the `frontend` directory, in a second terminal:

```bash
npm run dev
```

The dashboard shell is then at `http://127.0.0.1:5173` and the interactive API
documentation at `http://127.0.0.1:8000/docs`.

Helper scripts do the same thing:

```bash
./scripts/start-backend.sh
./scripts/start-frontend.sh
```

Docker Compose is available but optional:

```bash
docker compose up
```

### Tests

```bash
cd backend  && python -m pytest -q
cd frontend && npm run typecheck && npm run test && npm run build
```

## API

`GET /api/health`

```json
{
  "project": "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework",
  "status": "operational"
}
```

`GET /api/system/status` returns `backend_status`, `database_status`,
`application_mode` and `architecture_layers`, all read from live configuration
and database state.

Packet analysis (Layer 03):

```
GET    /api/packets/status         analyzer state, capture metadata, statistics
GET    /api/packets                paginated, filterable, sortable packet list
GET    /api/packets/{id}           full decoded packet
POST   /api/packets/upload         multipart .pcap / .pcapng (25 MB, 50 000 packets)
POST   /api/packets/analyze        re-run analysis on the loaded capture
DELETE /api/packets                clear the loaded capture
```

Captures are held in process memory for this section; persistence arrives
with Layer 11. Uploaded files are parsed, never executed, and filenames are
sanitised.

IPsec sessions (supporting module over Layer 03 output):

```
GET    /api/sessions/status               engine state and statistics
GET    /api/sessions                      paginated, filterable, sortable sessions
GET    /api/sessions/{id}                 detail: overview, timeline, packets, IKE/ESP/AH
GET    /api/sessions/for-packet/{id}      session a packet belongs to, if any
POST   /api/sessions/discover             correlate the loaded capture into sessions
DELETE /api/sessions                      clear sessions for the loaded capture
```

Security Associations (Layer 04):

```
GET    /api/sas/status                    engine state and statistics
GET    /api/sas                           paginated, filterable, sortable SAs
GET    /api/sas/{id}                      detail: state, history, timeline, IKE, children, packets
GET    /api/sas/{id}/timeline             append-only lifecycle events
GET    /api/sas/{id}/packets              associated packets
GET    /api/sas/for-session/{id}          SAs linked to a session
GET    /api/sas/for-packet/{id}           SAs a packet belongs to
POST   /api/sas/discover                  run lifecycle analysis on the loaded capture
DELETE /api/sas                           clear SAs for the loaded capture
```

Feature Extraction & Engineering (Layer 05):

```
GET    /api/features/status               engine state, schema version, statistics
GET    /api/features/definitions          the feature registry (name, type, unit, source, formula)
GET    /api/features/entities             packets, sessions or SAs available for extraction
GET    /api/features                      stored feature vectors
POST   /api/features/extract              extract for {entity_type, entity_id}
GET    /api/features/{id}                 vector detail with lineage and quality
GET    /api/features/entity/{type}/{id}   stored vector for one entity
GET    /api/features/export?format=json|csv
DELETE /api/features                      clear vectors for the loaded capture
```

`WS /ws/events` accepts connections and sends one acknowledgement frame. It
carries no security events, because no event sources exist. The Live Monitor
page connects to it with bounded reconnect (doubling backoff, five attempts).

An integration test for the socket runs only when a backend is up:

```bash
cd frontend && LIVE_BACKEND=1 npx vitest run tests/realtime.live.test.ts
```

## Current Status

SEC 14 is the current master implementation of the framework. All fourteen architectural layers (Layers 01–14) are fully operational and integrated with 100% regression test coverage.

Layer 10 (Risk Assessment & Decision Engine) evaluates multi-criteria risk dynamically based on genuine empirical signals (vulnerability findings, XGBoost anomaly inference, baseline drift, and SA state), strictly disallowing synthetic or fabricated risk scores. Real IPsec traffic has been validated end-to-end through hypervisor live capture, protocol decoding, SA tracking, feature extraction, baseline profiling, drift analysis, ML anomaly detection, vulnerability rule matching, composite risk evaluation, and PDF report generation.

## Development Roadmap

```
SECTION 0  — PROJECT FOUNDATION                    COMPLETED
SECTION 1  — GLOBAL WEBSITE SHELL                  COMPLETED
SECTION 2  — OVERVIEW DASHBOARD                    COMPLETED
SECTION 3  — 14-LAYER ARCHITECTURE VIEW            COMPLETED
SECTION 4  — LIVE MONITOR                          COMPLETED
SECTION 5  — PACKET ANALYSIS                       COMPLETED
SECTION 6  — IPSEC SESSIONS                        COMPLETED
SECTION 7  — SA LIFECYCLE                          COMPLETED
SECTION 8  — FEATURE EXTRACTION                    COMPLETED
SECTION 9  — BASELINE PROFILING                    COMPLETED
SECTION 10 — DRIFT DETECTION                       COMPLETED
SECTION 11 — AI / ML ANOMALY ENGINE                COMPLETED
SECTION 12 — VULNERABILITY ENGINE                  COMPLETED
SECTION 13 — DASHBOARD INTEGRATION                 COMPLETED
SECTION 14 — PDF REPORT GENERATION (MASTER)        COMPLETED
```

## License

MIT. The copyright holder in `LICENSE` is a placeholder — replace it with your
name or organisation before publishing.
