"""Aggregate API router.

Future layers attach their routers here rather than to the app directly.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import health, packets, security_associations, sessions, system

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(system.router)
api_router.include_router(packets.router)
api_router.include_router(sessions.router)
api_router.include_router(security_associations.router)
