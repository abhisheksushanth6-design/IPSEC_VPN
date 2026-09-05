"""Pydantic schemas for Layer 13 — Web Dashboard.

Defines the contracts for dashboard aggregation, system posture,
security metrics, timeline events, protocol posture, and session activity.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class DashboardMetrics(BaseModel):
    """Core security and operational metrics aggregated across layers 01-09."""

    model_config = ConfigDict(extra="forbid")

    overall_risk_score: float | None = Field(
        None,
        description="Overall risk score from Layer 10 (None while Layer 10 is NOT INITIALIZED).",
    )
    overall_risk_status: str = Field(
        "NOT INITIALIZED",
        description="Current status of Layer 10 Risk Assessment & Decision Engine.",
    )
    active_vpn_sessions: int = Field(
        0, description="Total correlated IPsec VPN sessions observed."
    )
    active_sas: int = Field(
        0, description="Total active Security Associations (IKE + Child)."
    )
    packets_analyzed: int = Field(
        0, description="Total packets processed by the protocol analyzer."
    )
    ai_anomalies: int = Field(
        0, description="Total anomalous sessions flagged by Layer 08 AI/ML engine."
    )
    drift_events: int = Field(
        0, description="Total security drift events identified by Layer 07."
    )
    vulnerabilities_total: int = Field(
        0, description="Total security findings discovered by Layer 09."
    )
    vulnerabilities_critical: int = Field(
        0, description="Critical severity vulnerability findings."
    )
    vulnerabilities_high: int = Field(
        0, description="High severity vulnerability findings."
    )
    vulnerabilities_medium: int = Field(
        0, description="Medium severity vulnerability findings."
    )
    vulnerabilities_low: int = Field(
        0, description="Low severity vulnerability findings."
    )
    vulnerabilities_active: int = Field(
        0, description="Open or confirmed findings currently unresolved."
    )
    capture_status: str = Field(
        "READY", description="Packet capture engine status (READY/IDLE)."
    )


class SystemPosture(BaseModel):
    """Application and architecture operational health summary."""

    model_config = ConfigDict(extra="forbid")

    backend_status: str = Field("OPERATIONAL", description="FastAPI status.")
    database_status: str = Field("CONNECTED", description="SQLite connectivity status.")
    application_mode: str = Field("DEMO", description="Configured operating mode.")
    layers_total: int = Field(14, description="Total architecture layers.")
    layers_initialized: int = Field(11, description="Initialized architecture layers.")
    last_refresh: str = Field(..., description="ISO 8601 timestamp of summary.")


class SessionActivityItem(BaseModel):
    """Session summary with correlated analytical flags."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    start_time: str | None = None
    duration_seconds: float = 0.0
    peer_a: str
    peer_b: str
    ike_version: str | None = None
    sa_count: int = 0
    packet_count: int = 0
    has_anomaly: bool = False
    anomaly_score: float | None = None
    has_drift: bool = False
    drift_status: str | None = None
    vulnerabilities_count: int = 0
    status: str = "ACTIVE"


class SecurityTimelineEvent(BaseModel):
    """Chronological security event record derived from backend states."""

    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: str
    layer: str
    layer_number: int
    event_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    source_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ProtocolPosture(BaseModel):
    """Observed cryptographic suites, IKE transforms, and protocol distributions."""

    model_config = ConfigDict(extra="forbid")

    ike_versions: list[str] = Field(default_factory=list)
    observed_encryption_algorithms: list[str] = Field(default_factory=list)
    observed_integrity_algorithms: list[str] = Field(default_factory=list)
    observed_dh_groups: list[str] = Field(default_factory=list)
    observed_prf_algorithms: list[str] = Field(default_factory=list)
    pfs_enabled: bool | None = None
    protocol_counts: dict[str, int] = Field(default_factory=dict)


class DashboardSummaryResponse(BaseModel):
    """Unified operational dashboard summary response."""

    model_config = ConfigDict(extra="forbid")

    posture: SystemPosture
    metrics: DashboardMetrics
    recent_sessions: list[SessionActivityItem] = Field(default_factory=list)
    recent_events: list[SecurityTimelineEvent] = Field(default_factory=list)
    protocol_posture: ProtocolPosture
    vulnerability_breakdown: dict[str, int] = Field(default_factory=dict)
    sa_state_breakdown: dict[str, int] = Field(default_factory=dict)
    ml_engine_status: dict[str, Any] = Field(default_factory=dict)
    drift_engine_status: dict[str, Any] = Field(default_factory=dict)
