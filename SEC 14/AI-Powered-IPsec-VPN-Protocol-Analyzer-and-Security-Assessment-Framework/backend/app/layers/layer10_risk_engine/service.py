"""Service implementation for Layer 10 — Risk Assessment & Decision Engine.

Aggregates factual detection signals from Layers 4, 5, 6, 7, 8, and 9 to
evaluate holistic session risk scores, determine security posture decisions,
and persist deterministic assessment records.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.layers.layer10_risk_engine.evaluator import EvaluationInput, RiskEvaluator
from app.layers.layer10_risk_engine.schemas import (
    DECISION_TO_ALIAS,
    ContributingSignal,
    RiskAssessmentResponse,
    RiskEvidenceItem,
    RiskExportResponse,
    RiskScoreBreakdown,
    RiskSummaryResponse,
)
from app.models.baseline import (
    BaselineProfileRow,
    BaselineSessionLinkRow,
    SessionFingerprintRow,
)
from app.models.drift import DriftAnalysisRow
from app.models.feature_vector import FeatureVectorRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import AnomalyAnalysisRow
from app.models.risk import RiskAssessmentRow
from app.models.security_association import SALifecycleEventRow, SecurityAssociationRow
from app.models.vulnerability import VulnerabilityFindingRow

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RiskEngineService:
    """Core service for computing, querying, and managing session risk assessments."""

    def evaluate_session(
        self, db: Session, session_id: str, force_refresh: bool = False
    ) -> RiskAssessmentResponse:
        """Perform deterministic risk assessment for an IPsec session from live telemetry."""
        # 1. Verify target session exists
        session_row = db.scalar(select(IPsecSession).where(IPsecSession.id == session_id))
        if session_row is None:
            raise ValueError(f"IPsec session '{session_id}' does not exist.")

        # Check existing assessment cache if refresh not requested
        if not force_refresh:
            existing = db.scalar(
                select(RiskAssessmentRow)
                .where(RiskAssessmentRow.session_id == session_id)
                .order_by(RiskAssessmentRow.evaluated_at.desc())
            )
            if existing is not None:
                return self._row_to_response(existing)

        # 2. Collect Layer 04: SAs & Lifecycle events
        sas_rows = db.scalars(
            select(SecurityAssociationRow).where(SecurityAssociationRow.session_id == session_id)
        ).all()
        sas_data = [
            {
                "id": sa.id,
                "protocol": sa.protocol,
                "state": sa.state,
                "rekey_count": sa.rekey_count,
            }
            for sa in sas_rows
        ]

        lifecycle_events: List[Dict[str, Any]] = []
        for sa in sas_rows:
            for ev in sa.events:
                lifecycle_events.append({
                    "event_type": ev.event_type,
                    "description": ev.description,
                    "sa_id": sa.id,
                })

        # 3. Collect Layer 05: Feature Vector
        fv_row = db.scalar(
            select(FeatureVectorRow).where(
                FeatureVectorRow.entity_id == session_id,
                func.lower(FeatureVectorRow.entity_type) == "session",
            )
        )
        if fv_row is None:
            try:
                from app.services.feature_service import feature_service
                from app.services.packet_service import packet_service
                if packet_service.capture_id and packet_service.capture_id == session_row.capture_id:
                    feature_service.extract("SESSION", session_id)
                    fv_row = db.scalar(
                        select(FeatureVectorRow).where(
                            FeatureVectorRow.entity_id == session_id,
                            func.lower(FeatureVectorRow.entity_type) == "session",
                        )
                    )
            except Exception as exc:
                logger.warning("On-demand feature extraction deferred for %s: %s", session_id, exc)

        has_features = fv_row is not None
        feature_count = len(fv_row.values) if fv_row and hasattr(fv_row, "values") else (1 if fv_row else 0)

        # 4. Collect Layer 06: Baseline Profile Link & Session Fingerprint
        bl_link = db.scalar(
            select(BaselineSessionLinkRow).where(BaselineSessionLinkRow.session_id == session_id)
        )
        has_baseline = bl_link is not None
        baseline_id = bl_link.baseline_id if bl_link else None

        fp_row = db.scalar(
            select(SessionFingerprintRow).where(SessionFingerprintRow.session_id == session_id)
        )
        if fp_row is None and has_features:
            try:
                from app.services.fingerprint_service import fingerprint_service
                fingerprint_service.get_or_create_for_session(session_id)
                fp_row = db.scalar(
                    select(SessionFingerprintRow).where(SessionFingerprintRow.session_id == session_id)
                )
            except Exception as exc:
                logger.warning("On-demand fingerprint generation deferred for %s: %s", session_id, exc)

        has_fingerprint = fp_row is not None
        fingerprint_id = fp_row.id if fp_row else None

        # 5. Collect Layer 07: Security Drift
        drift_row = db.scalar(
            select(DriftAnalysisRow)
            .where(DriftAnalysisRow.session_id == session_id)
            .order_by(DriftAnalysisRow.analyzed_at.desc())
        )
        if drift_row is None:
            try:
                from app.services.drift_service import drift_service
                active_base = db.scalar(
                    select(BaselineProfileRow).where(BaselineProfileRow.is_active.is_(True))
                )
                if active_base is not None:
                    drift_service.analyze(session_id, baseline_id=active_base.id)
                    drift_row = db.scalar(
                        select(DriftAnalysisRow)
                        .where(DriftAnalysisRow.session_id == session_id)
                        .order_by(DriftAnalysisRow.analyzed_at.desc())
                    )
            except Exception as exc:
                logger.warning("On-demand drift evaluation deferred for %s: %s", session_id, exc)

        drift_data = (
            {
                "id": drift_row.id,
                "drift_detected": (drift_row.status == "DRIFT_DETECTED" or drift_row.features_drifting > 0),
                "severity": drift_row.severity,
                "overall_drift_score": round(drift_row.features_drifting / max(1, drift_row.features_analyzed), 2),
                "features_drifting": drift_row.features_drifting,
            }
            if drift_row
            else None
        )

        # 6. Collect Layer 08: ML Anomaly Analysis
        ml_row = db.scalar(
            select(AnomalyAnalysisRow)
            .where(AnomalyAnalysisRow.session_id == session_id)
            .order_by(AnomalyAnalysisRow.analyzed_at.desc())
        )
        if ml_row is None and has_features:
            try:
                from app.layers.layer08_ai_ml.service import AIAnomalyService
                from app.layers.layer08_ai_ml.schemas import AnomalyInferenceRequest
                ai_svc = AIAnomalyService(db)
                ai_svc.run_inference(AnomalyInferenceRequest(session_id=session_id))
                ml_row = db.scalar(
                    select(AnomalyAnalysisRow)
                    .where(AnomalyAnalysisRow.session_id == session_id)
                    .order_by(AnomalyAnalysisRow.analyzed_at.desc())
                )
            except Exception as exc:
                logger.warning("On-demand anomaly evaluation deferred for %s: %s", session_id, exc)

        ml_data = (
            {
                "analysis_id": ml_row.id,
                "classification": ml_row.classification,
                "raw_score": ml_row.raw_score,
                "display_score": ml_row.display_score,
                "model_id": ml_row.model_id,
            }
            if ml_row
            else None
        )

        # 7. Collect Layer 09: Vulnerability Findings
        vuln_rows = db.scalars(
            select(VulnerabilityFindingRow).where(
                VulnerabilityFindingRow.affected_session_id == session_id
            )
        ).all()

        if not vuln_rows:
            # Trigger Layer 09 rules if session hasn't been evaluated yet
            try:
                from app.layers.layer09_vulnerability_engine.service import VulnerabilityService
                vuln_svc = VulnerabilityService()
                findings = vuln_svc.analyze_session(db, session_id)
                if findings:
                    vuln_rows = db.scalars(
                        select(VulnerabilityFindingRow).where(
                            VulnerabilityFindingRow.affected_session_id == session_id
                        )
                    ).all()
            except Exception as exc:
                logger.warning("On-demand vulnerability evaluation deferred: %s", exc)

        CONFIDENCE_MAP = {
            "CRITICAL": 1.0,
            "HIGH": 0.95,
            "MEDIUM": 0.75,
            "LOW": 0.5,
            "INFO": 0.3,
        }

        vulns_data = []
        for v in vuln_rows:
            raw_c = getattr(v, "confidence", 1.0)
            if isinstance(raw_c, (int, float)):
                conf_val = float(raw_c)
            elif str(raw_c).upper() in CONFIDENCE_MAP:
                conf_val = CONFIDENCE_MAP[str(raw_c).upper()]
            else:
                try:
                    conf_val = float(raw_c)
                except (ValueError, TypeError):
                    conf_val = 1.0

            vulns_data.append({
                "id": v.id,
                "rule_id": v.rule_id,
                "title": v.title,
                "severity": v.severity,
                "status": getattr(v, "status", "OPEN"),
                "confidence": conf_val,
                "recurrence_count": getattr(v, "occurrence_count", 1),
                "affected_object_id": v.affected_object_id,
            })

        # 8. Assemble Evaluation Input
        eval_input = EvaluationInput(
            session_id=session_id,
            session_info={
                "source": session_row.source,
                "destination": session_row.destination,
                "state": session_row.state,
                "ike_version": session_row.ike_version,
            },
            sas=sas_data,
            lifecycle_events=lifecycle_events,
            has_features=has_features,
            feature_count=feature_count,
            has_baseline=has_baseline,
            baseline_id=baseline_id,
            has_fingerprint=has_fingerprint,
            fingerprint_id=fingerprint_id,
            drift_data=drift_data,
            ml_data=ml_data,
            vulnerabilities=vulns_data,
        )

        # 9. Execute Deterministic Evaluation
        (
            total_risk_score,
            risk_level,
            decision,
            data_quality,
            confidence_score,
            breakdown,
            signals,
            evidence,
            recommendations,
            available_signals,
            unavailable_signals,
        ) = RiskEvaluator.evaluate(eval_input)

        now = _utc_now()

        # 10. Persist or update RiskAssessmentRow
        row = db.scalar(
            select(RiskAssessmentRow).where(RiskAssessmentRow.session_id == session_id)
        )
        if row is None:
            assessment_id = f"RISK-{uuid.uuid4().hex[:12].upper()}"
            row = RiskAssessmentRow(
                id=assessment_id,
                session_id=session_id,
                risk_score=total_risk_score,
                risk_level=risk_level,
                decision=decision,
                data_quality=data_quality,
                confidence_score=confidence_score,
                vulnerability_score=breakdown.vulnerability_score,
                ml_score=breakdown.ml_score,
                drift_score=breakdown.drift_score,
                state_score=breakdown.state_score,
                contributing_signals_json=json.dumps([s.model_dump() for s in signals]),
                evidence_json=json.dumps([e.model_dump() for e in evidence]),
                recommended_actions_json=json.dumps(recommendations),
                available_signals_json=json.dumps(available_signals),
                unavailable_signals_json=json.dumps(unavailable_signals),
                evaluated_at=now,
                created_at=now,
            )
            db.add(row)
        else:
            row.risk_score = total_risk_score
            row.risk_level = risk_level
            row.decision = decision
            row.data_quality = data_quality
            row.confidence_score = confidence_score
            row.vulnerability_score = breakdown.vulnerability_score
            row.ml_score = breakdown.ml_score
            row.drift_score = breakdown.drift_score
            row.state_score = breakdown.state_score
            row.contributing_signals_json = json.dumps([s.model_dump() for s in signals])
            row.evidence_json = json.dumps([e.model_dump() for e in evidence])
            row.recommended_actions_json = json.dumps(recommendations)
            row.available_signals_json = json.dumps(available_signals)
            row.unavailable_signals_json = json.dumps(unavailable_signals)
            row.evaluated_at = now

        db.commit()
        db.refresh(row)
        return self._row_to_response(row)

    def get_session_assessment(
        self, db: Session, session_id: str
    ) -> Optional[RiskAssessmentResponse]:
        """Retrieve existing risk assessment or trigger evaluation if not yet assessed."""
        row = db.scalar(
            select(RiskAssessmentRow)
            .where(RiskAssessmentRow.session_id == session_id)
            .order_by(RiskAssessmentRow.evaluated_at.desc())
        )
        if row is not None:
            return self._row_to_response(row)

        # Check if session exists; if so, perform initial assessment
        session_exists = db.scalar(
            select(func.count(IPsecSession.id)).where(IPsecSession.id == session_id)
        )
        if session_exists:
            return self.evaluate_session(db, session_id)

        return None

    def get_all_assessments(
        self, db: Session, limit: int = 50
    ) -> List[RiskAssessmentResponse]:
        """Retrieve all session risk assessments ordered by recency."""
        rows = db.scalars(
            select(RiskAssessmentRow)
            .order_by(RiskAssessmentRow.evaluated_at.desc())
            .limit(limit)
        ).all()
        return [self._row_to_response(r) for r in rows]

    def evaluate_all_sessions(
        self, db: Session, capture_id: Optional[str] = None
    ) -> List[RiskAssessmentResponse]:
        """Batch evaluate discovered sessions in the telemetry database.
        
        If capture_id is provided or an active capture is loaded in packet_service,
        scopes evaluation to the sessions belonging to that capture.
        """
        from app.services.packet_service import packet_service

        target_capture = capture_id or packet_service.capture_id
        stmt = select(IPsecSession.id)
        if target_capture:
            stmt = stmt.where(IPsecSession.capture_id == target_capture)

        session_ids = db.scalars(stmt).all()
        # Fallback to all sessions only if no sessions matched target_capture
        if not session_ids and not target_capture:
            session_ids = db.scalars(select(IPsecSession.id)).all()

        results: List[RiskAssessmentResponse] = []
        for sid in session_ids:
            try:
                res = self.evaluate_session(db, sid, force_refresh=True)
                results.append(res)
            except Exception as exc:
                logger.error("Failed evaluating session %s: %s", sid, exc)
        return results

    def get_summary(self, db: Session, capture_id: Optional[str] = None) -> RiskSummaryResponse:
        """Compile executive risk summary across observed sessions, optionally scoped to capture_id."""
        if capture_id:
            total_sessions = (
                db.scalar(
                    select(func.count(IPsecSession.id)).where(
                        IPsecSession.capture_id == capture_id
                    )
                )
                or 0
            )
            session_ids_subq = select(IPsecSession.id).where(
                IPsecSession.capture_id == capture_id
            )
            assessed_sessions = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.session_id.in_(session_ids_subq)
                    )
                )
                or 0
            )
            latest_row = db.scalar(
                select(RiskAssessmentRow)
                .where(RiskAssessmentRow.session_id.in_(session_ids_subq))
                .order_by(RiskAssessmentRow.evaluated_at.desc())
            )
            crit_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.session_id.in_(session_ids_subq),
                        RiskAssessmentRow.risk_level == "CRITICAL",
                    )
                )
                or 0
            )
            high_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.session_id.in_(session_ids_subq),
                        RiskAssessmentRow.risk_level == "HIGH",
                    )
                )
                or 0
            )
            med_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.session_id.in_(session_ids_subq),
                        RiskAssessmentRow.risk_level == "MEDIUM",
                    )
                )
                or 0
            )
            low_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.session_id.in_(session_ids_subq),
                        RiskAssessmentRow.risk_level == "LOW",
                    )
                )
                or 0
            )
            max_score = db.scalar(
                select(func.max(RiskAssessmentRow.risk_score)).where(
                    RiskAssessmentRow.session_id.in_(session_ids_subq)
                )
            )
        else:
            total_sessions = db.scalar(select(func.count(IPsecSession.id))) or 0
            assessed_sessions = db.scalar(select(func.count(RiskAssessmentRow.id))) or 0
            latest_row = db.scalar(
                select(RiskAssessmentRow).order_by(RiskAssessmentRow.evaluated_at.desc())
            )
            crit_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.risk_level == "CRITICAL"
                    )
                )
                or 0
            )
            high_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.risk_level == "HIGH"
                    )
                )
                or 0
            )
            med_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.risk_level == "MEDIUM"
                    )
                )
                or 0
            )
            low_count = (
                db.scalar(
                    select(func.count(RiskAssessmentRow.id)).where(
                        RiskAssessmentRow.risk_level == "LOW"
                    )
                )
                or 0
            )
            max_score = db.scalar(select(func.max(RiskAssessmentRow.risk_score)))

        if assessed_sessions == 0 or latest_row is None:
            return RiskSummaryResponse(
                state="READY",
                overall_risk_score=None,
                overall_risk_level=None,
                decision=None,
                decision_alias=None,
                is_advisory=True,
                data_quality=None,
                assessed_sessions_count=0,
                total_sessions_count=total_sessions,
                critical_risk_count=0,
                high_risk_count=0,
                medium_risk_count=0,
                low_risk_count=0,
                latest_assessment=None,
            )

        latest_resp = self._row_to_response(latest_row)

        return RiskSummaryResponse(
            state="OPERATIONAL",
            overall_risk_score=round(max_score, 1) if max_score is not None else latest_row.risk_score,
            overall_risk_level=latest_row.risk_level,
            decision=latest_row.decision,
            decision_alias=DECISION_TO_ALIAS.get(latest_row.decision, "ALLOW"),
            is_advisory=True,
            data_quality=latest_row.data_quality,
            assessed_sessions_count=assessed_sessions,
            total_sessions_count=total_sessions,
            critical_risk_count=crit_count,
            high_risk_count=high_count,
            medium_risk_count=med_count,
            low_risk_count=low_count,
            latest_assessment=latest_resp,
        )

    def get_layer_status(self, db: Optional[Session] = None) -> str:
        """Return dynamic status of Layer 10 based on database readiness and evaluator integrity."""
        try:
            if RiskEvaluator is None:
                return "ERROR"
            # Validate mathematical evaluator logic on dry-run input
            dry_run = RiskEvaluator.evaluate(EvaluationInput(session_id="dry-run"))
            if dry_run[0] != 0.0 or dry_run[1] != "LOW" or dry_run[2] != "ALLOW":
                return "DEGRADED"

            if db is not None:
                # Ensure risk_assessments table exists and can be queried
                db.scalar(select(func.count(RiskAssessmentRow.id)))
            return "OPERATIONAL"
        except Exception as exc:
            logger.warning("Layer 10 Risk Engine status verification error: %s", exc)
            return "ERROR"

    def get_detailed_status(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Return comprehensive machine-readable diagnostics for Layer 10."""
        checks: Dict[str, Any] = {
            "evaluator_loaded": RiskEvaluator is not None,
            "dry_run_passed": False,
            "database_connected": False,
            "tables_verified": False,
        }
        try:
            dry_run = RiskEvaluator.evaluate(EvaluationInput(session_id="health-check"))
            checks["dry_run_passed"] = (dry_run[0] == 0.0 and dry_run[1] == "LOW" and dry_run[2] == "ALLOW")
        except Exception as exc:
            checks["dry_run_error"] = str(exc)

        if db is not None:
            try:
                db.scalar(select(func.count(RiskAssessmentRow.id)))
                checks["database_connected"] = True
                checks["tables_verified"] = True
            except Exception as exc:
                checks["database_error"] = str(exc)

        overall = "OPERATIONAL" if all(checks.get(k) for k in ("evaluator_loaded", "dry_run_passed", "database_connected", "tables_verified") if k in checks) else "DEGRADED"
        return {
            "layer_number": 10,
            "layer_name": "Risk Assessment & Decision Engine",
            "status": overall,
            "is_advisory": True,
            "checks": checks,
        }

    def get_assessment_by_id(
        self, db: Session, assessment_id: str
    ) -> Optional[RiskAssessmentResponse]:
        """Retrieve a specific risk assessment by its unique record ID."""
        row = db.scalar(
            select(RiskAssessmentRow).where(RiskAssessmentRow.id == assessment_id)
        )
        if row is None:
            return None
        return self._row_to_response(row)

    def export_assessments(
        self,
        db: Session,
        session_id: Optional[str] = None,
        limit: int = 200,
    ) -> RiskExportResponse:
        """Produce structured SIEM/SOAR/compliance JSON export of risk assessments."""
        stmt = select(RiskAssessmentRow).order_by(RiskAssessmentRow.evaluated_at.desc())
        if session_id:
            stmt = stmt.where(RiskAssessmentRow.session_id == session_id)
        stmt = stmt.limit(limit)

        rows = db.scalars(stmt).all()
        assessments = [self._row_to_response(r) for r in rows]

        return RiskExportResponse(
            export_version="1.0.0",
            exported_at=_utc_now(),
            total_assessments=len(assessments),
            assessments=assessments,
            metadata={
                "filter_session_id": session_id,
                "limit": limit,
                "is_advisory": True,
                "authoritative_source": "Layer 10 Risk Assessment & Decision Engine",
            },
        )

    def _row_to_response(self, row: RiskAssessmentRow) -> RiskAssessmentResponse:
        """Convert a database ORM row to typed Pydantic response schema."""
        signals_raw = json.loads(row.contributing_signals_json) if row.contributing_signals_json else []
        evidence_raw = json.loads(row.evidence_json) if row.evidence_json else []
        recs_raw = json.loads(row.recommended_actions_json) if row.recommended_actions_json else []
        avail_raw = json.loads(row.available_signals_json) if row.available_signals_json else []
        unavail_raw = json.loads(row.unavailable_signals_json) if row.unavailable_signals_json else []

        parsed_signals = []
        for s in signals_raw:
            if isinstance(s, dict):
                src = s.get("source") or s.get("layer") or "LAYER_10_RISK_ENGINE"
                contrib = float(s.get("contribution") or s.get("points") or 0.0)
                reason = s.get("reason") or s.get("rule") or "Signal contribution"
                parsed_signals.append(ContributingSignal(
                    source=src,
                    contribution=contrib,
                    reason=reason,
                    evidence_reference=s.get("evidence_reference"),
                    confidence=s.get("confidence"),
                    finding_status=s.get("finding_status"),
                    recurrence_count=s.get("recurrence_count"),
                ))
        signals = parsed_signals
        parsed_evidence = []
        for e in evidence_raw:
            if isinstance(e, dict):
                src = e.get("source_layer") or "LAYER_09_VULNERABILITY_ENGINE"
                ev_type = e.get("evidence_type") or "VULNERABILITY_FINDING"
                ident = e.get("identifier") or e.get("finding_id") or "UNKNOWN"
                summ = e.get("summary") or f"Evidence finding {ident}"
                details = e.get("details") or {}
                parsed_evidence.append(RiskEvidenceItem(
                    source_layer=src,
                    evidence_type=ev_type,
                    identifier=ident,
                    summary=summ,
                    details=details,
                ))
        evidence = parsed_evidence

        breakdown = RiskScoreBreakdown(
            vulnerability_score=row.vulnerability_score,
            ml_score=row.ml_score,
            drift_score=row.drift_score,
            state_score=row.state_score,
            total_risk_score=row.risk_score,
        )

        # Compute active severity summary from evidence items
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for e in evidence_raw:
            if e.get("source_layer") == "LAYER_09_VULNERABILITY_ENGINE":
                summ = e.get("summary", "")
                if "STATUS: RESOLVED" not in summ and "STATUS: FALSE_POSITIVE" not in summ and "STATUS: SUPPRESSED" not in summ:
                    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                        if f"[{s}]" in summ:
                            sev_counts[s] += 1
                            break

        return RiskAssessmentResponse(
            id=row.id,
            session_id=row.session_id,
            risk_score=row.risk_score,
            risk_level=row.risk_level,
            decision=row.decision,
            decision_alias=DECISION_TO_ALIAS.get(row.decision, "ALLOW"),
            is_advisory=True,
            data_quality=row.data_quality,
            confidence_score=row.confidence_score,
            breakdown=breakdown,
            severity_summary=sev_counts,
            contributing_signals=signals,
            evidence=evidence,
            recommended_actions=recs_raw,
            available_signals=avail_raw,
            unavailable_signals=unavail_raw,
            evaluated_at=row.evaluated_at,
        )


_risk_service: Optional[RiskEngineService] = None


def get_risk_engine_service() -> RiskEngineService:
    """Singleton provider for RiskEngineService."""
    global _risk_service
    if _risk_service is None:
        _risk_service = RiskEngineService()
    return _risk_service


def get_layer_status(db: Optional[Session] = None) -> str:
    """Convenience module-level function to check Layer 10 operational status."""
    return get_risk_engine_service().get_layer_status(db)


def get_detailed_status(db: Optional[Session] = None) -> Dict[str, Any]:
    """Convenience module-level function to get full Layer 10 diagnostic status."""
    return get_risk_engine_service().get_detailed_status(db)

