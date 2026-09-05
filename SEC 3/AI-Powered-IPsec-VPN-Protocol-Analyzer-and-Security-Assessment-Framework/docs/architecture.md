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
