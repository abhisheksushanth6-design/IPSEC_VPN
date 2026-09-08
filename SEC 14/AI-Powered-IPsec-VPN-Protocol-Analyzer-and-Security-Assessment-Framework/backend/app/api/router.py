"""Aggregate API router.

Future layers attach their routers here rather than to the app directly.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    baselines,
    drift,
    features,
    fingerprints,
    health,
    ml,
    packets,
    security_associations,
    sessions,
    system,
    vulnerabilities,
    dashboard,
    environment,
    live_capture,
    reports,
    risk,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(system.router)
api_router.include_router(environment.router)
api_router.include_router(live_capture.router)
api_router.include_router(packets.router)
api_router.include_router(sessions.router)
api_router.include_router(security_associations.router)
api_router.include_router(features.router)
api_router.include_router(baselines.router)
api_router.include_router(fingerprints.router)
api_router.include_router(drift.router)
api_router.include_router(ml.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(risk.router)
api_router.include_router(dashboard.router)
api_router.include_router(reports.router)
