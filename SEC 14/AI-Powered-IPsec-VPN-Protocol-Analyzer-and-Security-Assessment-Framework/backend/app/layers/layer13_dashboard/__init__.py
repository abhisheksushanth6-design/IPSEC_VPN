"""Layer 13 — Web Dashboard package.

Provides unified SOC dashboard aggregation across all analytical layers.
"""

from app.layers.layer13_dashboard.schemas import (
    DashboardMetrics,
    DashboardSummaryResponse,
    ProtocolPosture,
    SecurityTimelineEvent,
    SessionActivityItem,
    SystemPosture,
)
from app.layers.layer13_dashboard.service import DashboardService, dashboard_service

__all__ = [
    "DashboardMetrics",
    "DashboardSummaryResponse",
    "ProtocolPosture",
    "SecurityTimelineEvent",
    "SessionActivityItem",
    "SystemPosture",
    "DashboardService",
    "dashboard_service",
]
