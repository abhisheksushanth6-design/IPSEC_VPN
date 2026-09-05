"""Dashboard API endpoints (Layer 13).

Provides aggregated SOC operations data across analytical layers 01-09.
Maintains strict scope: Layer 10 risk scores remain NOT INITIALIZED.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer13_dashboard.schemas import (
    DashboardMetrics,
    DashboardSummaryResponse,
    ProtocolPosture,
    SecurityTimelineEvent,
    SessionActivityItem,
)
from app.layers.layer13_dashboard.service import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse, summary="Unified dashboard summary")
def read_dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummaryResponse:
    """Retrieve full dashboard summary including posture, metrics, timeline, and protocol posture."""
    return dashboard_service.get_summary(db)


@router.get("/metrics", response_model=DashboardMetrics, summary="Core security metrics")
def read_dashboard_metrics(db: Session = Depends(get_db)) -> DashboardMetrics:
    """Retrieve core KPI indicators aggregated from backend states."""
    return dashboard_service.get_metrics(db)


@router.get("/timeline", response_model=List[SecurityTimelineEvent], summary="Chronological security events")
def read_dashboard_timeline(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> List[SecurityTimelineEvent]:
    """Retrieve synthesized chronological security events across layers without fabrication."""
    return dashboard_service.get_timeline(db, limit=limit)


@router.get("/protocols", response_model=ProtocolPosture, summary="Protocol posture & cryptographic transforms")
def read_protocol_posture(db: Session = Depends(get_db)) -> ProtocolPosture:
    """Retrieve observed IKE versions, encryption algorithms, DH groups, and protocol distributions."""
    return dashboard_service.get_protocol_posture(db)


@router.get("/sessions", response_model=List[SessionActivityItem], summary="Recent session activity")
def read_recent_sessions(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
) -> List[SessionActivityItem]:
    """Retrieve recent IPsec sessions with correlated security and anomaly indicators."""
    return dashboard_service.get_recent_sessions(db, limit=limit)
