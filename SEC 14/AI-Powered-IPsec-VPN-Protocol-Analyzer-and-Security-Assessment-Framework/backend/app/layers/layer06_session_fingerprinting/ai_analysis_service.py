"""Layer 06 AI-Powered Security Analysis Service.

Coordinates AI provider selection, engine verification, risk report translation,
and analysis artifact lifecycle management.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from app.layers.layer05_feature_engineering.assessment_models import (
    RiskAssessmentReport,
    SecurityFinding,
)
from app.layers.layer06_session_fingerprinting.ai_analysis_models import (
    AISecurityAnalysis,
)
from app.layers.layer06_session_fingerprinting.ai_analysis_providers import (
    BaseAIAnalysisProvider,
    ConfigurableRealLLMProvider,
    DeterministicAIProvider,
)

logger = logging.getLogger(__name__)


class AISecurityAnalysisService:
    """Service managing Layer 06 AI-Powered Security Analysis."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._verify_lock = threading.Lock()
        self._verified: bool = False
        self._last_analysis: Optional[AISecurityAnalysis] = None

        self._deterministic_provider = DeterministicAIProvider()
        self._real_llm_provider = ConfigurableRealLLMProvider(
            fallback_provider=self._deterministic_provider
        )

    def verify_engine(self) -> bool:
        """Run automated self-test validating synthesis of AI security analysis."""
        with self._verify_lock:
            if self._verified:
                return True
            try:
                # 1. Synthesize sample report with weak crypto and sequence findings
                test_findings = [
                    SecurityFinding(
                        finding_id="TEST-CRYPTO-01",
                        rule_id="SEC-CRYPTO-001",
                        title="Deprecated 3DES Cipher Suite",
                        category="CRYPTOGRAPHY",
                        severity="CRITICAL",
                        confidence=1.0,
                        explanation="3DES is vulnerable to Sweet32 block collisions.",
                        evidence={"cipher": "3DES-CBC"},
                        remediation="Upgrade to AES-GCM-256.",
                        cve_references=["CVE-2016-2183"],
                    ),
                    SecurityFinding(
                        finding_id="TEST-INTEG-01",
                        rule_id="SEC-INTEG-001",
                        title="ESP Sequence Replay Detected",
                        category="INTEGRITY",
                        severity="HIGH",
                        confidence=0.9,
                        explanation="Duplicate sequence numbers violate anti-replay invariants.",
                        evidence={"replayed_sequence": 42},
                        remediation="Inspect network paths for packet reinjection.",
                    ),
                ]

                test_report = RiskAssessmentReport(
                    capture_id="verify_test",
                    overall_risk_score=68.5,
                    risk_level="HIGH",
                    findings_count=len(test_findings),
                    findings_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                    findings=test_findings,
                    evaluated_sessions_count=1,
                    evaluated_tunnels_count=1,
                    evaluated_packets_count=50,
                    assessment_timestamp=datetime.now(timezone.utc).isoformat(),
                )

                # 2. Run analysis with deterministic provider
                analysis = self._deterministic_provider.generate_analysis(test_report)

                # 3. Assertions
                if not analysis.prioritized_findings or not analysis.attack_implications or not analysis.remediation_steps:
                    logger.error("Layer 06 verification failed: empty prioritized findings or attack implications")
                    return False

                if not analysis.executive_summary.overall_posture or not analysis.technical_summary.cryptographic_assessment:
                    logger.error("Layer 06 verification failed: missing executive or technical summary narratives")
                    return False

                has_p1 = any(p.priority_rank == "P1_CRITICAL" for p in analysis.prioritized_findings)
                if not has_p1:
                    logger.error("Layer 06 verification failed: CRITICAL finding was not prioritized as P1_CRITICAL")
                    return False

                self._verified = True
                logger.info("Layer 06 AI-Powered Security Analysis engine verified successfully (status: READY)")
                return True
            except Exception as e:
                logger.error("Layer 06 self-verification error: %s", e, exc_info=True)
                return False

    def get_layer_status(self) -> str:
        """Report Layer 06 dynamic status based on engine verification."""
        return "READY" if self.verify_engine() else "NOT INITIALIZED"

    def analyze_assessment(
        self,
        report: RiskAssessmentReport,
        provider_preference: Optional[str] = None,
    ) -> AISecurityAnalysis:
        """Generate an AI Security Analysis for the provided RiskAssessmentReport."""
        provider: BaseAIAnalysisProvider
        if provider_preference == "real_llm":
            provider = self._real_llm_provider
        else:
            # Default to deterministic provider for predictable, offline, fast execution
            provider = self._deterministic_provider

        analysis = provider.generate_analysis(report)
        with self._lock:
            self._last_analysis = analysis
        return analysis

    def analyze_current_capture(
        self,
        provider_preference: Optional[str] = None,
    ) -> AISecurityAnalysis:
        """Generate an AI analysis based on the latest Layer 05 assessment report."""
        from app.layers.layer05_feature_engineering.assessment_service import (
            get_security_assessment_service,
        )

        l5_service = get_security_assessment_service()
        report = l5_service.get_last_report()

        if report is None:
            # If no capture has been assessed yet, build baseline minimal report
            now_iso = datetime.now(timezone.utc).isoformat()
            report = RiskAssessmentReport(
                capture_id="none",
                overall_risk_score=0.0,
                risk_level="MINIMAL",
                findings_count=0,
                findings_by_severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                findings=[],
                evaluated_sessions_count=0,
                evaluated_tunnels_count=0,
                evaluated_packets_count=0,
                assessment_timestamp=now_iso,
                status="READY",
            )

        return self.analyze_assessment(report, provider_preference=provider_preference)

    def get_last_analysis(self) -> Optional[AISecurityAnalysis]:
        with self._lock:
            return self._last_analysis


_ai_security_analysis_service: Optional[AISecurityAnalysisService] = None
_service_lock = threading.Lock()


def get_ai_security_analysis_service() -> AISecurityAnalysisService:
    global _ai_security_analysis_service
    with _service_lock:
        if _ai_security_analysis_service is None:
            _ai_security_analysis_service = AISecurityAnalysisService()
        return _ai_security_analysis_service
