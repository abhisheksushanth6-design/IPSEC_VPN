"""Service layer for Layer 13 — Web Dashboard.

Aggregates operational state, security metrics, correlated sessions,
factual timeline events, and protocol posture across layers 01-09.
Maintains strict scope: Layer 10 risk scores are NEVER fabricated or computed here.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.architecture import ARCHITECTURE_LAYERS, LayerStatus, TOTAL_LAYERS
from app.layers.layer13_dashboard.schemas import (
    DashboardMetrics,
    DashboardSummaryResponse,
    ProtocolPosture,
    SecurityTimelineEvent,
    SessionActivityItem,
    SystemPosture,
)
from app.models.baseline import BaselineProfileRow
from app.models.drift import DriftAnalysisRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import AnomalyAnalysisRow, MLModelRow
from app.models.security_association import SALifecycleEventRow, SecurityAssociationRow
from app.models.vulnerability import VulnerabilityFindingRow
from app.services.packet_service import packet_service
from app.services.system_service import read_application_mode

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DashboardService:
    """Core aggregation service powering the Security Operations Dashboard."""

    def get_system_posture(self, db: Session) -> SystemPosture:
        """Assemble overall application and architecture operational health."""
        application_mode, database_status = read_application_mode(db)
        initialized = sum(
            1 for layer in ARCHITECTURE_LAYERS if layer.status is not LayerStatus.NOT_INITIALIZED
        )

        return SystemPosture(
            backend_status="OPERATIONAL",
            database_status=database_status,
            application_mode=application_mode,
            layers_total=TOTAL_LAYERS,
            layers_initialized=initialized,
            last_refresh=_utc_now().isoformat(),
        )

    def get_metrics(self, db: Session) -> DashboardMetrics:
        """Aggregate security and operational metrics from database and active services."""
        pkt_status = packet_service.status()
        in_memory_pkts = (
            pkt_status.capture.packet_count
            if pkt_status.capture
            else len(packet_service.all_packets())
        )
        db_pkts = db.scalar(select(func.sum(IPsecSession.packet_count))) or 0
        total_packets = max(in_memory_pkts, int(db_pkts))

        active_sessions = db.scalar(select(func.count(IPsecSession.id))) or 0
        active_sas = db.scalar(select(func.count(SecurityAssociationRow.id))) or 0

        anomalies_count = (
            db.scalar(
                select(func.count(AnomalyAnalysisRow.id)).where(
                    AnomalyAnalysisRow.classification == "ANOMALOUS"
                )
            )
            or 0
        )

        drift_count = (
            db.scalar(
                select(func.count(DriftAnalysisRow.id)).where(
                    DriftAnalysisRow.features_drifting > 0
                )
            )
            or 0
        )

        vuln_total = db.scalar(select(func.count(VulnerabilityFindingRow.id))) or 0
        vuln_crit = (
            db.scalar(
                select(func.count(VulnerabilityFindingRow.id)).where(
                    VulnerabilityFindingRow.severity == "CRITICAL"
                )
            )
            or 0
        )
        vuln_high = (
            db.scalar(
                select(func.count(VulnerabilityFindingRow.id)).where(
                    VulnerabilityFindingRow.severity == "HIGH"
                )
            )
            or 0
        )
        vuln_med = (
            db.scalar(
                select(func.count(VulnerabilityFindingRow.id)).where(
                    VulnerabilityFindingRow.severity == "MEDIUM"
                )
            )
            or 0
        )
        vuln_low = (
            db.scalar(
                select(func.count(VulnerabilityFindingRow.id)).where(
                    VulnerabilityFindingRow.severity == "LOW"
                )
            )
            or 0
        )
        vuln_act = (
            db.scalar(
                select(func.count(VulnerabilityFindingRow.id)).where(
                    VulnerabilityFindingRow.status.in_(["OPEN", "CONFIRMED"])
                )
            )
            or 0
        )

        capture_state = "READY" if (total_packets > 0 or pkt_status.state != "NOT INITIALIZED") else "IDLE"

        # Layer 10 Risk Metrics
        risk_score = None
        risk_status = "READY"
        try:
            from app.layers.layer10_risk_engine.service import get_risk_engine_service
            risk_svc = get_risk_engine_service()
            risk_summary = risk_svc.get_summary(db)
            if risk_summary.assessed_sessions_count > 0 and risk_summary.overall_risk_score is not None:
                risk_score = risk_summary.overall_risk_score
                risk_status = risk_summary.overall_risk_level or "OPERATIONAL"
            else:
                risk_status = "READY"
        except Exception:
            risk_status = "NOT INITIALIZED"

        return DashboardMetrics(
            overall_risk_score=risk_score,
            overall_risk_status=risk_status,
            active_vpn_sessions=active_sessions,
            active_sas=active_sas,
            packets_analyzed=total_packets,
            ai_anomalies=anomalies_count,
            drift_events=drift_count,
            vulnerabilities_total=vuln_total,
            vulnerabilities_critical=vuln_crit,
            vulnerabilities_high=vuln_high,
            vulnerabilities_medium=vuln_med,
            vulnerabilities_low=vuln_low,
            vulnerabilities_active=vuln_act,
            capture_status=capture_state,
        )

    def get_recent_sessions(self, db: Session, limit: int = 10) -> list[SessionActivityItem]:
        """Fetch recent sessions with correlated anomalies, drift, and vulnerability flags."""
        sessions = db.scalars(
            select(IPsecSession).order_by(IPsecSession.discovered_at.desc()).limit(limit)
        ).all()

        results: list[SessionActivityItem] = []
        for s in sessions:
            anom = db.scalar(
                select(AnomalyAnalysisRow)
                .where(AnomalyAnalysisRow.session_id == s.id)
                .order_by(AnomalyAnalysisRow.analyzed_at.desc())
            )
            drift = db.scalar(
                select(DriftAnalysisRow)
                .where(DriftAnalysisRow.session_id == s.id)
                .order_by(DriftAnalysisRow.analyzed_at.desc())
            )
            v_count = (
                db.scalar(
                    select(func.count(VulnerabilityFindingRow.id)).where(
                        VulnerabilityFindingRow.affected_session_id == s.id
                    )
                )
                or 0
            )
            sa_count = (
                db.scalar(
                    select(func.count(SecurityAssociationRow.id)).where(
                        SecurityAssociationRow.session_id == s.id
                    )
                )
                or 0
            )

            results.append(
                SessionActivityItem(
                    session_id=s.id,
                    start_time=s.start_time,
                    duration_seconds=s.duration_seconds or 0.0,
                    peer_a=s.source,
                    peer_b=s.destination,
                    ike_version=s.ike_version,
                    sa_count=sa_count,
                    packet_count=s.packet_count,
                    has_anomaly=(anom.classification == "ANOMALOUS") if anom else False,
                    anomaly_score=anom.display_score if anom else None,
                    has_drift=(drift.features_drifting > 0) if drift else False,
                    drift_status=drift.status if drift else None,
                    vulnerabilities_count=v_count,
                    status=s.state,
                )
            )
        return results

    def get_timeline(self, db: Session, limit: int = 50) -> list[SecurityTimelineEvent]:
        """Aggregate chronological security events across layers without fabrication."""
        events: list[SecurityTimelineEvent] = []

        # 1. Vulnerability Findings (Layer 09)
        findings = db.scalars(
            select(VulnerabilityFindingRow)
            .order_by(VulnerabilityFindingRow.last_seen.desc())
            .limit(limit)
        ).all()
        for f in findings:
            events.append(
                SecurityTimelineEvent(
                    id=f"evt-vuln-{f.id}",
                    timestamp=f.last_seen.isoformat(),
                    layer="Layer 09 — Security Rules",
                    layer_number=9,
                    event_type="Vulnerability Detected",
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    source_id=f.affected_session_id or f.affected_sa_id or f.id,
                    details={
                        "rule_id": f.rule_id,
                        "category": f.category,
                        "confidence": f.confidence,
                        "status": f.status,
                    },
                )
            )

        # 2. AI / ML Anomalies (Layer 08)
        anomalies = db.scalars(
            select(AnomalyAnalysisRow)
            .where(AnomalyAnalysisRow.classification == "ANOMALOUS")
            .order_by(AnomalyAnalysisRow.analyzed_at.desc())
            .limit(limit)
        ).all()
        for a in anomalies:
            events.append(
                SecurityTimelineEvent(
                    id=f"evt-ml-{a.id}",
                    timestamp=a.analyzed_at.isoformat(),
                    layer="Layer 08 — AI/ML Anomaly",
                    layer_number=8,
                    event_type="AI Anomaly Detected",
                    severity="HIGH" if a.display_score >= 70 else "MEDIUM",
                    title=f"Anomaly Flagged: Session {a.session_id}",
                    description=a.explanation_summary or f"Anomaly score: {a.display_score:.1f}/100",
                    source_id=a.session_id,
                    details={
                        "display_score": a.display_score,
                        "raw_score": a.raw_score,
                        "features_anomalous": a.features_anomalous,
                        "model_id": a.model_id,
                    },
                )
            )

        # 3. Security Drift Events (Layer 07)
        drifts = db.scalars(
            select(DriftAnalysisRow)
            .where(DriftAnalysisRow.features_drifting > 0)
            .order_by(DriftAnalysisRow.analyzed_at.desc())
            .limit(limit)
        ).all()
        for d in drifts:
            events.append(
                SecurityTimelineEvent(
                    id=f"evt-drift-{d.id}",
                    timestamp=d.analyzed_at.isoformat(),
                    layer="Layer 07 — Drift Detection",
                    layer_number=7,
                    event_type="Security Drift Detected",
                    severity=d.severity if d.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                    title=f"Security Drift: Session {d.session_id}",
                    description=f"{d.features_drifting} features drifted from baseline profile {d.baseline_id}",
                    source_id=d.session_id,
                    details={
                        "baseline_id": d.baseline_id,
                        "status": d.status,
                        "features_drifting": d.features_drifting,
                    },
                )
            )

        # 4. SA Lifecycle Events (Layer 04)
        sa_events = db.scalars(
            select(SALifecycleEventRow).order_by(SALifecycleEventRow.id.desc()).limit(limit)
        ).all()
        for e in sa_events:
            iso_time = e.timestamp or _utc_now().isoformat()
            events.append(
                SecurityTimelineEvent(
                    id=f"evt-sa-{e.id}",
                    timestamp=iso_time,
                    layer="Layer 04 — SA Lifecycle",
                    layer_number=4,
                    event_type="SA Established" if e.new_state == "ESTABLISHED" else "SA Rekey" if "REKEY" in e.event_type else e.event_type,
                    severity="INFO",
                    title=f"SA {e.sa_id}: {e.event_type}",
                    description=e.description,
                    source_id=e.sa_id,
                    details={
                        "previous_state": e.previous_state,
                        "new_state": e.new_state,
                        "packet_number": e.packet_number,
                        "spi": e.spi,
                    },
                )
            )

        # Sort combined events descending by timestamp
        events.sort(key=lambda ev: ev.timestamp, reverse=True)
        return events[:limit]

    def get_protocol_posture(self, db: Session) -> ProtocolPosture:
        """Extract observed protocol transforms, IKE versions, and distribution."""
        ike_versions: set[str] = set()
        encryption_algos: set[str] = set()
        integrity_algos: set[str] = set()
        dh_groups: set[str] = set()
        prf_algos: set[str] = set()
        pfs_enabled: bool | None = None

        # Inspect sessions
        sessions = db.scalars(select(IPsecSession)).all()
        for s in sessions:
            if s.ike_version:
                ike_versions.add(s.ike_version)
            if s.detail_json:
                try:
                    data = json.loads(s.detail_json)
                    if isinstance(data, dict):
                        ike_info = data.get("ike_info") or {}
                        if isinstance(ike_info, dict):
                            if ike_info.get("version"):
                                ike_versions.add(str(ike_info["version"]))
                            if ike_info.get("cipher"):
                                encryption_algos.add(str(ike_info["cipher"]))
                            if ike_info.get("integrity"):
                                integrity_algos.add(str(ike_info["integrity"]))
                            if ike_info.get("dh_group"):
                                dh_groups.add(str(ike_info["dh_group"]))
                            if ike_info.get("prf"):
                                prf_algos.add(str(ike_info["prf"]))
                        esp_info = data.get("esp_info") or {}
                        if isinstance(esp_info, dict):
                            if esp_info.get("cipher"):
                                encryption_algos.add(str(esp_info["cipher"]))
                            if esp_info.get("auth"):
                                integrity_algos.add(str(esp_info["auth"]))
                except Exception:
                    pass

        # Inspect SAs
        sas = db.scalars(select(SecurityAssociationRow)).all()
        for sa in sas:
            if sa.ike_version:
                ike_versions.add(sa.ike_version)
            if sa.detail_json:
                try:
                    data = json.loads(sa.detail_json)
                    if isinstance(data, dict):
                        if data.get("cipher"):
                            encryption_algos.add(str(data["cipher"]))
                        if data.get("encryption_algorithm"):
                            encryption_algos.add(str(data["encryption_algorithm"]))
                        if data.get("integrity_algorithm"):
                            integrity_algos.add(str(data["integrity_algorithm"]))
                        if data.get("auth"):
                            integrity_algos.add(str(data["auth"]))
                        if data.get("dh_group"):
                            dh_groups.add(str(data["dh_group"]))
                        if data.get("prf"):
                            prf_algos.add(str(data["prf"]))
                        if "pfs_enabled" in data:
                            pfs_enabled = bool(data["pfs_enabled"])
                except Exception:
                    pass

        # Protocol counts from packet service or sessions
        protocol_counts: dict[str, int] = {}
        pkt_status = packet_service.status()
        if pkt_status.protocol_counts:
            pc = pkt_status.protocol_counts
            protocol_counts = {
                "IKE": getattr(pc, "IKE", getattr(pc, "ike", 0)),
                "ESP": getattr(pc, "ESP", getattr(pc, "esp", 0)),
                "AH": getattr(pc, "AH", getattr(pc, "ah", 0)),
                "UDP": getattr(pc, "UDP", getattr(pc, "udp", 0)),
                "TCP": getattr(pc, "TCP", getattr(pc, "tcp", 0)),
                "ICMP": getattr(pc, "ICMP", getattr(pc, "icmp", 0)),
                "OTHER": getattr(pc, "OTHER", getattr(pc, "other", 0)),
            }
        else:
            ike_sum = db.scalar(select(func.sum(IPsecSession.ike_packets))) or 0
            esp_sum = db.scalar(select(func.sum(IPsecSession.esp_packets))) or 0
            ah_sum = db.scalar(select(func.sum(IPsecSession.ah_packets))) or 0
            if (ike_sum + esp_sum + ah_sum) > 0:
                protocol_counts = {
                    "IKE": int(ike_sum),
                    "ESP": int(esp_sum),
                    "AH": int(ah_sum),
                    "UDP": 0,
                    "IP": 0,
                }

        return ProtocolPosture(
            ike_versions=sorted(ike_versions),
            observed_encryption_algorithms=sorted(encryption_algos),
            observed_integrity_algorithms=sorted(integrity_algos),
            observed_dh_groups=sorted(dh_groups),
            observed_prf_algorithms=sorted(prf_algos),
            pfs_enabled=pfs_enabled,
            protocol_counts=protocol_counts,
        )

    def get_summary(self, db: Session) -> DashboardSummaryResponse:
        """Assemble the complete unified dashboard summary."""
        posture = self.get_system_posture(db)
        metrics = self.get_metrics(db)
        recent_sessions = self.get_recent_sessions(db, limit=10)
        recent_events = self.get_timeline(db, limit=20)
        protocol_posture = self.get_protocol_posture(db)

        # Vulnerability breakdown
        vuln_breakdown = {
            "CRITICAL": metrics.vulnerabilities_critical,
            "HIGH": metrics.vulnerabilities_high,
            "MEDIUM": metrics.vulnerabilities_medium,
            "LOW": metrics.vulnerabilities_low,
        }

        # SA state breakdown
        sa_state_counts: dict[str, int] = {}
        sa_states = db.execute(
            select(SecurityAssociationRow.state, func.count(SecurityAssociationRow.id)).group_by(
                SecurityAssociationRow.state
            )
        ).all()
        for state, count in sa_states:
            sa_state_counts[str(state)] = int(count)

        # ML Engine status
        active_model = db.scalar(
            select(MLModelRow).where(MLModelRow.is_active.is_(True))
        )
        total_models = db.scalar(select(func.count(MLModelRow.id))) or 0
        ml_engine_status: dict[str, Any] = {
            "active_model_id": active_model.id if active_model else None,
            "active_model_name": active_model.name if active_model else None,
            "model_type": active_model.model_type if active_model else None,
            "total_models": total_models,
            "total_anomalies": metrics.ai_anomalies,
        }

        # Drift Engine status
        total_drifts = db.scalar(select(func.count(DriftAnalysisRow.id))) or 0
        active_baselines = db.scalar(select(func.count(BaselineProfileRow.id))) or 0
        drift_engine_status: dict[str, Any] = {
            "total_drift_analyses": total_drifts,
            "active_baselines_count": active_baselines,
            "drift_events_count": metrics.drift_events,
        }

        return DashboardSummaryResponse(
            posture=posture,
            metrics=metrics,
            recent_sessions=recent_sessions,
            recent_events=recent_events,
            protocol_posture=protocol_posture,
            vulnerability_breakdown=vuln_breakdown,
            sa_state_breakdown=sa_state_counts,
            ml_engine_status=ml_engine_status,
            drift_engine_status=drift_engine_status,
        )


dashboard_service = DashboardService()
