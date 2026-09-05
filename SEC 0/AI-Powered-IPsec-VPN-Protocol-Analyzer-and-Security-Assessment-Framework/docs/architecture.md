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
