# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

## Project Overview

This project is intended to become a security assessment framework for IPsec
VPN deployments. Once complete, it will capture traffic from a controlled IPsec
test environment, decode IKE, ESP and AH structures, track Security Association
lifecycles, learn per-session behavioural baselines, detect drift and anomalies
with machine learning, evaluate deterministic vulnerability rules, produce
prioritised risk assessments, and present the results through a web dashboard
and generated PDF reports.

None of that analysis exists yet. This repository currently contains the
software foundation those capabilities will be built on.

## Current Development Stage

```
SECTION 2 — OVERVIEW DASHBOARD
```

What exists: a configured FastAPI backend, a SQLite database foundation, a
WebSocket channel, the full web shell, and the Overview dashboard — eight KPI
cards, a risk gauge, a system status panel, six chart components, an event
stream and a security summary. Every security figure on the dashboard reads
NOT INITIALIZED or NO DATA AVAILABLE, because no engine exists to produce one.
What does not exist: every security analysis capability described above.

## 14-Layer Architecture

| # | Layer | Status |
| --- | --- | --- |
| 01 | IPsec VPN Test Environment | NOT INITIALIZED |
| 02 | Packet Capture & Data Collection | NOT INITIALIZED |
| 03 | Packet & Protocol Analysis | NOT INITIALIZED |
| 04 | Security State & SA Lifecycle Engine | NOT INITIALIZED |
| 05 | Feature Extraction & Engineering | NOT INITIALIZED |
| 06 | Session Fingerprinting & Baseline Profiling | NOT INITIALIZED |
| 07 | Security Drift Detection | NOT INITIALIZED |
| 08 | AI / ML Anomaly Detection Engine | NOT INITIALIZED |
| 09 | Security Rule & Vulnerability Engine | NOT INITIALIZED |
| 10 | Risk Assessment & Decision Engine | NOT INITIALIZED |
| 11 | Security Databases (SQLite) | FOUNDATION CREATED |
| 12 | Backend & API (FastAPI) | FOUNDATION CREATED |
| 13 | Web Dashboard | FOUNDATION READY |
| 14 | Report Generation (PDF) | FOUNDATION READY |

"FOUNDATION CREATED" and "FOUNDATION READY" mean the scaffolding is in place,
not that the layer's functionality works.

The layer list is defined once, in `backend/app/core/architecture.py`, and
served by `GET /api/system/status`.

## Technology Stack

Configured and in use now:

| Technology | Role |
| --- | --- |
| React 18 | Frontend UI library |
| Vite 6 | Frontend build tool and dev server |
| TypeScript 5 | Frontend type safety |
| Tailwind CSS 3 | Styling |
| Lucide React | Icons |
| React Router | Client-side routing |
| Vitest + Testing Library | Frontend testing |
| Python 3.12 | Backend runtime |
| FastAPI | Backend web framework |
| Pydantic | Validation and settings |
| Uvicorn | ASGI server |
| SQLite | Database engine |
| SQLAlchemy 2 | ORM and database access |
| FastAPI WebSockets | Real-time channel foundation |
| pytest | Backend testing |

Declared as a frontend dependency, reserved for later layers:

| Technology | Planned for |
| --- | --- |
| Recharts | Dashboard charts (in use; render only when passed real data) |

Planned but deliberately **not installed yet**, because no code uses them:

| Technology | Planned for |
| --- | --- |
| Scapy | Layers 02–03 — packet capture and protocol analysis |
| scikit-learn | Layer 08 — anomaly detection |
| ReportLab | Layer 14 — PDF report generation |

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

`WS /ws/events` accepts connections and sends one acknowledgement frame. It
carries no security events, because no event sources exist.

## Current Status

The security analysis modules are not implemented. This repository performs no
packet capture, no protocol decoding, no anomaly detection, no vulnerability
evaluation, no risk scoring and no report generation. It stores no security
data of any kind — the only database row it creates is the application mode.

Any figure this application displays comes from its own configuration. It
reports no security findings, because it has produced none.

## Development Roadmap

```
SECTION 0 — PROJECT FOUNDATION         COMPLETED
SECTION 1 — GLOBAL WEBSITE SHELL       COMPLETED
SECTION 2 — OVERVIEW DASHBOARD         COMPLETED
SECTION 3 — 14-LAYER ARCHITECTURE VIEW NEXT
SECTION 4 — LIVE MONITOR
```

Then, layer by layer:

```
LAYER 1  — IPsec VPN Test Environment
LAYER 2  — Packet Capture & Data Collection
LAYER 3  — Packet & Protocol Analysis
LAYER 4  — Security State & SA Lifecycle Engine
LAYER 5  — Feature Extraction & Engineering
LAYER 6  — Session Fingerprinting & Baseline Profiling
LAYER 7  — Security Drift Detection
LAYER 8  — AI / ML Anomaly Detection Engine
LAYER 9  — Security Rule & Vulnerability Engine
LAYER 10 — Risk Assessment & Decision Engine
LAYER 11 — Security Databases (SQLite)
LAYER 12 — Backend & API (FastAPI)
LAYER 13 — Web Dashboard
LAYER 14 — Report Generation (PDF)
```

## License

MIT. The copyright holder in `LICENSE` is a placeholder — replace it with your
name or organisation before publishing.
