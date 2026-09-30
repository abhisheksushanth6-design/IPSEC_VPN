"""Deterministic Risk Evaluator for Layer 10 — Risk Assessment & Decision Engine.

Implements exact weighted scoring, bounded clamping, risk level categorization,
policy decisions, data quality analysis, and actionable remediation generation
strictly from empirical upstream signals without synthetic values.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.layers.layer10_risk_engine.schemas import (
    DECISION_TO_ALIAS,
    ALIAS_TO_DECISION,
    ContributingSignal,
    RiskEvidenceItem,
    RiskScoreBreakdown,
)

logger = logging.getLogger(__name__)

# Maximum component weights
MAX_VULNERABILITY_SCORE = 50.0
MAX_ML_SCORE = 30.0
MAX_DRIFT_SCORE = 12.0
MAX_STATE_SCORE = 8.0
MAX_TOTAL_SCORE = 100.0

# Vulnerability severity weights
VULN_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 3.0,
    "INFO": 0.0,
}

# Finding lifecycle categorization
ACTIVE_VULN_STATUSES = {"OPEN", "ACTIVE", "CONFIRMED"}
INACTIVE_VULN_STATUSES = {"RESOLVED", "FALSE_POSITIVE", "SUPPRESSED"}

# Drift severity weights
DRIFT_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 12.0,
    "HIGH": 8.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "NONE": 0.0,
}

# All expected architectural signal layers
ALL_SIGNALS = [
    "LAYER_04_SA_LIFECYCLE",
    "LAYER_05_FEATURE_EXTRACTION",
    "LAYER_06_BASELINE_PROFILING",
    "LAYER_07_DRIFT_DETECTION",
    "LAYER_08_AI_ML_ANOMALY",
    "LAYER_09_VULNERABILITY_ENGINE",
]


@dataclass
class EvaluationInput:
    """Consolidated input container collecting factual upstream signals for a session."""

    session_id: str
    session_info: Optional[Dict[str, Any]] = None
    sas: List[Dict[str, Any]] = field(default_factory=list)
    lifecycle_events: List[Dict[str, Any]] = field(default_factory=list)
    has_features: bool = False
    feature_count: int = 0
    has_baseline: bool = False
    baseline_id: Optional[str] = None
    has_fingerprint: bool = False
    fingerprint_id: Optional[str] = None
    drift_data: Optional[Dict[str, Any]] = None  # None if unanalyzed
    ml_data: Optional[Dict[str, Any]] = None      # None if unanalyzed
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


class RiskEvaluator:
    """Pure deterministic evaluator for computing bounded risk scores and policy decisions."""

    @staticmethod
    def classify_risk_level(score: float) -> str:
        """Deterministically map a bounded risk score to discrete risk band.

        Bands:
            LOW: [0.0, 19.9]
            MEDIUM: [20.0, 44.9]
            HIGH: [45.0, 69.9]
            CRITICAL: [70.0, 100.0]
        """
        clamped = min(MAX_TOTAL_SCORE, max(0.0, round(score, 2)))
        if clamped >= 70.0:
            return "CRITICAL"
        elif clamped >= 45.0:
            return "HIGH"
        elif clamped >= 20.0:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def determine_decision(
        score: float,
        has_critical: bool = False,
        has_high: bool = False,
    ) -> Tuple[str, str]:
        """Determine policy decision and standard alias.

        Rules:
            TERMINATE / BLOCK: score >= 70.0 or has_critical finding
            RESTRICT / ISOLATE: score >= 45.0
            INSPECT / WARN: score >= 20.0 or has_high finding
            ALLOW / ALLOW: score < 20.0 and no critical/high finding

        Returns:
            (canonical_decision, decision_alias)
        """
        clamped = min(MAX_TOTAL_SCORE, max(0.0, round(score, 2)))
        if clamped >= 70.0 or has_critical:
            dec = "TERMINATE"
        elif clamped >= 45.0:
            dec = "RESTRICT"
        elif clamped >= 20.0 or has_high:
            dec = "INSPECT"
        else:
            dec = "ALLOW"

        alias = DECISION_TO_ALIAS.get(dec, "ALLOW")
        return dec, alias

    @staticmethod
    def count_severity_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count active security findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        seen_ids = set()
        for f in findings:
            fid = f.get("id")
            if fid and fid in seen_ids:
                continue
            if fid:
                seen_ids.add(fid)
            status = str(f.get("status", "OPEN")).upper()
            if status in INACTIVE_VULN_STATUSES:
                continue
            sev = str(f.get("severity", "INFO")).upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def calculate_vulnerability_score(
        findings: List[Dict[str, Any]],
    ) -> Tuple[float, List[ContributingSignal], List[RiskEvidenceItem], bool, bool]:
        """Compute vulnerability score (capped at 50.0) from findings.

        Applies:
        1. Status filtering: Only OPEN, ACTIVE, CONFIRMED findings add active risk points.
           RESOLVED, FALSE_POSITIVE, and SUPPRESSED findings contribute 0.0 points.
        2. Confidence weighting: Effective score = base_weight * confidence (0.0 to 1.0).
        3. Recurrence damping: For repeat occurrences on the same object, subsequent
           occurrences contribute damped points = min(base_weight * 0.2 * log2(recurrence), base_weight * 0.5).
        4. Deduplication: Duplicate records by finding ID are deduplicated.
        5. Score clamping: Clamped strictly to [0.0, 50.0].

        Returns:
            (score, contributing_signals, evidence_items, has_critical, has_high)
        """
        raw_score = 0.0
        signals: List[ContributingSignal] = []
        evidence: List[RiskEvidenceItem] = []
        has_critical = False
        has_high = False

        seen_finding_ids = set()
        object_rule_counts: Dict[Tuple[str, str], int] = {}

        for f in findings:
            fid = f.get("id")
            if fid and fid in seen_finding_ids:
                continue
            if fid:
                seen_finding_ids.add(fid)

            rule_id = str(f.get("rule_id", "UNKNOWN-RULE"))
            title = str(f.get("title", "Security Rule Finding"))
            sev = str(f.get("severity", "INFO")).upper()
            status = str(f.get("status", "OPEN")).upper()
            obj_id = str(f.get("affected_object_id") or "")

            # Confidence weighting (default 1.0)
            raw_conf = f.get("confidence")
            if raw_conf is not None:
                try:
                    conf = max(0.0, min(1.0, float(raw_conf)))
                except (ValueError, TypeError):
                    conf = 1.0
            else:
                conf = 1.0

            # Recurrence count
            raw_rec = f.get("recurrence_count") or f.get("occurrence_count")
            if raw_rec is not None:
                try:
                    rec_count = max(1, int(raw_rec))
                except (ValueError, TypeError):
                    rec_count = 1
            else:
                rec_count = 1

            rule_key = (rule_id, obj_id)
            object_rule_counts[rule_key] = object_rule_counts.get(rule_key, 0) + 1
            seen_index = object_rule_counts[rule_key]

            base_weight = VULN_WEIGHTS.get(sev, 0.0)

            # Check status triage
            is_active = status in ACTIVE_VULN_STATUSES or status not in INACTIVE_VULN_STATUSES
            if not is_active:
                # Inactive / resolved finding: 0 active risk contribution
                evidence.append(
                    RiskEvidenceItem(
                        source_layer="LAYER_09_VULNERABILITY_ENGINE",
                        evidence_type="VULNERABILITY_FINDING",
                        identifier=str(fid or rule_id),
                        summary=f"[{sev}][STATUS: {status}] {rule_id}: {title} (affected: {obj_id or 'session'})",
                        details={"status": status, "confidence": conf, "recurrence": rec_count, "excluded_from_score": True},
                    )
                )
                continue

            # Active finding calculation
            effective_base = base_weight * conf
            total_rec = max(rec_count, seen_index)
            if total_rec > 1:
                # Logarithmic damping for repeat occurrences
                rec_damping = min(base_weight * 0.2 * math.log2(total_rec), base_weight * 0.5)
            else:
                rec_damping = 0.0

            finding_points = round(effective_base + rec_damping, 2)
            raw_score += finding_points

            if sev == "CRITICAL" and conf >= 0.5:
                has_critical = True
            elif sev == "HIGH" and conf >= 0.5:
                has_high = True

            if finding_points > 0:
                reason_rec = f" (recurrence={total_rec})" if total_rec > 1 else ""
                reason_conf = f" [conf={conf:.2f}]" if conf < 1.0 else ""
                signals.append(
                    ContributingSignal(
                        source="LAYER_09",
                        contribution=finding_points,
                        reason=f"Rule violation [{rule_id}] ({sev}){reason_conf}{reason_rec}: {title}",
                        evidence_reference=str(fid) if fid is not None else None,
                        confidence=conf,
                        finding_status=status,
                        recurrence_count=total_rec,
                    )
                )

            evidence.append(
                RiskEvidenceItem(
                    source_layer="LAYER_09_VULNERABILITY_ENGINE",
                    evidence_type="VULNERABILITY_FINDING",
                    identifier=str(fid or rule_id),
                    summary=f"[{sev}][{status}] {rule_id}: {title} (affected: {obj_id or 'session'})",
                    details={"status": status, "confidence": conf, "recurrence": total_rec, "points": finding_points},
                )
            )

        clamped_score = min(MAX_VULNERABILITY_SCORE, max(0.0, round(raw_score, 2)))
        return clamped_score, signals, evidence, has_critical, has_high

    @staticmethod
    def calculate_ml_score(
        ml_data: Optional[Dict[str, Any]]
    ) -> Tuple[float, List[ContributingSignal], List[RiskEvidenceItem]]:
        """Compute ML attack probability score (capped at 30.0).
        
        Specification:
            If anomalous -> 30.0 * raw_score
            Else -> 10.0 * raw_score
            Clamped to [0.0, 30.0]
        """
        if not ml_data:
            return 0.0, [], []

        raw_score = float(ml_data.get("raw_score", 0.0))
        classification = str(ml_data.get("classification", "NORMAL")).upper()
        model_id = ml_data.get("model_id") or ml_data.get("analysis_id", "ML-MODEL")

        is_anomalous = classification == "ANOMALOUS"
        multiplier = 30.0 if is_anomalous else 10.0
        calculated = round(raw_score * multiplier, 2)
        clamped_score = min(MAX_ML_SCORE, max(0.0, calculated))

        signals: List[ContributingSignal] = []
        evidence: List[RiskEvidenceItem] = []

        if clamped_score > 0.0 or is_anomalous:
            signals.append(
                ContributingSignal(
                    source="LAYER_08",
                    contribution=clamped_score,
                    reason=(
                        f"AI/ML detection flagged {classification} (raw attack probability={raw_score:.4f}, "
                        f"weight={multiplier:.0f}x)"
                    ),
                    evidence_reference=model_id,
                )
            )

        evidence.append(
            RiskEvidenceItem(
                source_layer="LAYER_08_AI_ML",
                evidence_type="ML_ANOMALY_ANALYSIS",
                identifier=model_id,
                summary=(
                    f"Model classification: {classification}, raw_score: {raw_score:.4f}, "
                    f"display_score: {ml_data.get('display_score', 0.0):.2f}"
                ),
            )
        )

        return clamped_score, signals, evidence

    @staticmethod
    def calculate_drift_score(
        drift_data: Optional[Dict[str, Any]]
    ) -> Tuple[float, List[ContributingSignal], List[RiskEvidenceItem]]:
        """Compute drift score (capped at 12.0).
        
        Specification:
            CRITICAL = 12
            HIGH = 8
            MEDIUM = 4
            LOW = 1
            NONE = 0
            Unanalyzed = 0 (marked NOT_ANALYZED)
        """
        if not drift_data:
            return 0.0, [], []

        drift_detected = bool(drift_data.get("drift_detected", False))
        severity = str(drift_data.get("severity", "NONE")).upper()
        analysis_id = drift_data.get("id") or drift_data.get("analysis_id", "DRIFT-ANALYSIS")
        overall_drift_score = float(drift_data.get("overall_drift_score", 0.0))
        features_drifting = int(drift_data.get("features_drifting", 0))

        if not drift_detected and severity == "NONE":
            weight = 0.0
        else:
            weight = DRIFT_WEIGHTS.get(severity, 0.0)

        clamped_score = min(MAX_DRIFT_SCORE, weight)

        signals: List[ContributingSignal] = []
        evidence: List[RiskEvidenceItem] = []

        if clamped_score > 0.0:
            signals.append(
                ContributingSignal(
                    source="LAYER_07",
                    contribution=clamped_score,
                    reason=(
                        f"Behavioral drift severity {severity} detected across "
                        f"{features_drifting} features (drift score={overall_drift_score:.2f})"
                    ),
                    evidence_reference=analysis_id,
                )
            )

        evidence.append(
            RiskEvidenceItem(
                source_layer="LAYER_07_DRIFT_DETECTION",
                evidence_type="DRIFT_ANALYSIS",
                identifier=analysis_id,
                summary=(
                    f"Drift detected: {drift_detected}, severity: {severity}, "
                    f"drifting features: {features_drifting}, overall drift score: {overall_drift_score:.2f}"
                ),
            )
        )

        return clamped_score, signals, evidence

    @staticmethod
    def calculate_state_score(
        sas: List[Dict[str, Any]],
        lifecycle_events: List[Dict[str, Any]],
    ) -> Tuple[float, List[ContributingSignal], List[RiskEvidenceItem], bool]:
        """Compute protocol / SA state score (capped at 8.0).
        
        Specification:
            Rekey failure / unauthenticated drop -> +5
            Anti-replay violation -> +3
        
        Returns:
            (score, signals, evidence, has_critical_protocol_finding)
        """
        score = 0.0
        signals: List[ContributingSignal] = []
        evidence: List[RiskEvidenceItem] = []
        has_critical_protocol = False

        has_rekey_failure = False
        has_replay_violation = False

        for ev in lifecycle_events:
            ev_type = str(ev.get("event_type", "")).upper()
            desc = str(ev.get("description", "")).upper()
            if "REKEY" in ev_type and ("FAIL" in ev_type or "FAIL" in desc or "ERROR" in desc):
                has_rekey_failure = True
            if "REPLAY" in ev_type or "REPLAY" in desc:
                has_replay_violation = True
            if "DROP" in ev_type or "UNAUTHENTICATED" in desc:
                has_rekey_failure = True

        for sa in sas:
            sa_state = str(sa.get("state", "")).upper()
            if sa_state in ("FAILED", "ERROR"):
                has_rekey_failure = True

        if has_rekey_failure:
            score += 5.0
            has_critical_protocol = True
            signals.append(
                ContributingSignal(
                    source="LAYER_04",
                    contribution=5.0,
                    reason="Active SA rekey failure or unauthenticated drop observed",
                    evidence_reference=sas[0].get("id") if sas else None,
                )
            )
            evidence.append(
                RiskEvidenceItem(
                    source_layer="LAYER_04_SA_LIFECYCLE",
                    evidence_type="SA_LIFECYCLE_ANOMALY",
                    identifier=sas[0].get("id", "SA-EVENT") if sas else "SA-EVENT",
                    summary="Security Association rekey failure or unauthenticated packet drop recorded",
                )
            )

        if has_replay_violation:
            score += 3.0
            signals.append(
                ContributingSignal(
                    source="LAYER_04",
                    contribution=3.0,
                    reason="Anti-replay window sequence violation observed on IPsec SA",
                    evidence_reference=sas[0].get("id") if sas else None,
                )
            )
            evidence.append(
                RiskEvidenceItem(
                    source_layer="LAYER_04_SA_LIFECYCLE",
                    evidence_type="ANTI_REPLAY_VIOLATION",
                    identifier=sas[0].get("id", "SA-EVENT") if sas else "SA-EVENT",
                    summary="Anti-replay sequence number mismatch or duplicated packet window violation",
                )
            )

        clamped_score = min(MAX_STATE_SCORE, score)
        return clamped_score, signals, evidence, has_critical_protocol

    @classmethod
    def evaluate(cls, inp: EvaluationInput) -> Tuple[
        float, str, str, str, float, RiskScoreBreakdown,
        List[ContributingSignal], List[RiskEvidenceItem], List[str],
        List[str], List[str]
    ]:
        """Execute full deterministic evaluation across all upstream signals."""
        # 1. Sub-scores
        vuln_score, vuln_signals, vuln_evidence, has_critical_vuln, has_high_vuln = (
            cls.calculate_vulnerability_score(inp.vulnerabilities)
        )
        ml_score, ml_signals, ml_evidence = cls.calculate_ml_score(inp.ml_data)
        drift_score, drift_signals, drift_evidence = cls.calculate_drift_score(inp.drift_data)
        state_score, state_signals, state_evidence, has_critical_protocol = (
            cls.calculate_state_score(inp.sas, inp.lifecycle_events)
        )

        # 2. Total Risk Score capped strictly at 100.0
        raw_total = vuln_score + ml_score + drift_score + state_score
        total_risk_score = min(MAX_TOTAL_SCORE, max(0.0, round(raw_total, 2)))

        breakdown = RiskScoreBreakdown(
            vulnerability_score=vuln_score,
            ml_score=ml_score,
            drift_score=drift_score,
            state_score=state_score,
            total_risk_score=total_risk_score,
        )

        # 3. Categorize Risk Band
        risk_level = cls.classify_risk_level(total_risk_score)

        # 4. Determine Policy Decision
        has_critical_finding = has_critical_vuln or has_critical_protocol
        decision, _ = cls.determine_decision(
            total_risk_score,
            has_critical=has_critical_finding,
            has_high=has_high_vuln,
        )

        # 5. Signal Completeness & Confidence
        available_signals: List[str] = []
        unavailable_signals: List[str] = []

        # Layer 4
        if inp.sas or inp.lifecycle_events or inp.session_info:
            available_signals.append("LAYER_04_SA_LIFECYCLE")
        else:
            unavailable_signals.append("LAYER_04_SA_LIFECYCLE")

        # Layer 5
        if inp.has_features and inp.feature_count > 0:
            available_signals.append("LAYER_05_FEATURE_EXTRACTION")
        else:
            unavailable_signals.append("LAYER_05_FEATURE_EXTRACTION")

        # Layer 6: Session Fingerprinting & Baseline Profiling
        has_l6 = (inp.has_baseline and bool(inp.baseline_id)) or (inp.has_fingerprint and bool(inp.fingerprint_id))
        if has_l6:
            available_signals.append("LAYER_06_BASELINE_PROFILING")
        else:
            unavailable_signals.append("LAYER_06_BASELINE_PROFILING")

        # Layer 7
        if inp.drift_data is not None:
            available_signals.append("LAYER_07_DRIFT_DETECTION")
        else:
            unavailable_signals.append("LAYER_07_DRIFT_DETECTION")

        # Layer 8
        if inp.ml_data is not None:
            available_signals.append("LAYER_08_AI_ML_ANOMALY")
        else:
            unavailable_signals.append("LAYER_08_AI_ML_ANOMALY")

        # Layer 9
        available_signals.append("LAYER_09_VULNERABILITY_ENGINE")

        data_quality = "COMPLETE" if len(available_signals) == 6 else "PARTIAL"
        confidence_score = round(len(available_signals) / 6.0, 2)

        # 6. Consolidate Signals & Evidence
        all_signals = vuln_signals + ml_signals + drift_signals + state_signals
        all_evidence = vuln_evidence + ml_evidence + drift_evidence + state_evidence

        # Add session baseline/feature/fingerprint evidence if present
        if inp.session_info:
            all_evidence.append(
                RiskEvidenceItem(
                    source_layer="LAYER_03_PROTOCOL_ANALYSIS",
                    evidence_type="SESSION_TELEMETRY",
                    identifier=inp.session_id,
                    summary=(
                        f"Session {inp.session_id}: {inp.session_info.get('source')} -> "
                        f"{inp.session_info.get('destination')}, state: {inp.session_info.get('state')}, "
                        f"IKEv{inp.session_info.get('ike_version') or '?'}"
                    ),
                )
            )

        if inp.has_fingerprint and inp.fingerprint_id:
            all_evidence.append(
                RiskEvidenceItem(
                    source_layer="LAYER_06_BASELINE_PROFILING",
                    evidence_type="SESSION_FINGERPRINT",
                    identifier=inp.fingerprint_id,
                    summary=f"Behavioral fingerprint {inp.fingerprint_id} established for session {inp.session_id}.",
                )
            )

        if inp.has_baseline and inp.baseline_id:
            all_evidence.append(
                RiskEvidenceItem(
                    source_layer="LAYER_06_BASELINE_PROFILING",
                    evidence_type="BASELINE_PROFILE",
                    identifier=inp.baseline_id,
                    summary=f"Session associated with baseline profile {inp.baseline_id}.",
                )
            )

        # 7. Actionable Recommendations
        recommendations = cls.generate_recommendations(
            total_risk_score=total_risk_score,
            decision=decision,
            vuln_findings=inp.vulnerabilities,
            ml_data=inp.ml_data,
            drift_data=inp.drift_data,
            has_rekey_failure=has_critical_protocol,
            unavailable_signals=unavailable_signals,
        )

        return (
            total_risk_score,
            risk_level,
            decision,
            data_quality,
            confidence_score,
            breakdown,
            all_signals,
            all_evidence,
            recommendations,
            available_signals,
            unavailable_signals,
        )

    @staticmethod
    def generate_recommendations(
        total_risk_score: float,
        decision: str,
        vuln_findings: List[Dict[str, Any]],
        ml_data: Optional[Dict[str, Any]],
        drift_data: Optional[Dict[str, Any]],
        has_rekey_failure: bool,
        unavailable_signals: List[str],
    ) -> List[str]:
        """Generate targeted actionable remediations based on empirical findings."""
        actions: List[str] = []

        if decision == "TERMINATE":
            actions.append("CRITICAL ACTION: Immediately isolate or terminate active IPsec SA session to prevent compromise.")
        elif decision == "RESTRICT":
            actions.append("RESTRICTION ACTION: Limit tunnel throughput and enforce strict traffic rate-limiting pending investigation.")
        elif decision == "INSPECT":
            actions.append("INSPECTION ACTION: Route session traffic through deep packet inspection and increase telemetry capture resolution.")

        # Vulnerability-driven actions
        for vf in vuln_findings:
            rule_id = vf.get("rule_id", "")
            title = vf.get("title", "")
            sev = str(vf.get("severity", "")).upper()
            if "3DES" in title or "DES" in title:
                actions.append("Cryptographic Upgrade: Deprecate 3DES cipher suites; transition immediately to AES-256-GCM (RFC 4106).")
            elif "MD5" in title or "SHA1" in title:
                actions.append("Integrity Upgrade: Deprecate MD5/SHA1 HMACs; enforce SHA-256 or SHA-384 for message integrity.")
            elif "DH" in title or "GROUP" in title:
                actions.append("Diffie-Hellman Hardening: Upgrade DH Groups < 14 to Curve25519 (Group 19) or ECP-384 (Group 20).")
            elif "UNANSWERED" in title or "RULE-IKE-003" in rule_id:
                actions.append("Handshake Audit: Investigate unanswered IKE_SA_INIT packets for possible peer downtime, firewall drops, or SYN/IKE flooding.")
            else:
                if sev in ("CRITICAL", "HIGH"):
                    actions.append(f"Remediate {sev} Finding [{rule_id}]: {title}.")

        # ML-driven actions
        if ml_data and str(ml_data.get("classification", "")).upper() == "ANOMALOUS":
            actions.append("Statistical Anomaly: Investigate abnormal burst rate and packet size distribution flagged by AI/ML anomaly detection.")

        # Drift-driven actions
        if drift_data and bool(drift_data.get("drift_detected", False)):
            actions.append("Behavioral Drift: Re-align traffic pattern with established behavioral baseline profile to eliminate drift.")

        # State-driven actions
        if has_rekey_failure:
            actions.append("Protocol State Audit: Review lifetime rekey negotiation parameters and responder logs for pre-shared key or identity mismatches.")

        # Signal completeness actions
        if unavailable_signals:
            missing_names = ", ".join([s.replace("LAYER_", "L").replace("_", " ") for s in unavailable_signals])
            actions.append(f"Telemetry Coverage: Incomplete assessment telemetry. Run missing pipelines for full confidence ({missing_names}).")

        if not actions:
            actions.append("System Posture Clean: No immediate security remediations required. Continue continuous monitoring.")

        # Deduplicate preserving order
        seen = set()
        deduped = []
        for a in actions:
            if a not in seen:
                seen.add(a)
                deduped.append(a)

        return deduped
