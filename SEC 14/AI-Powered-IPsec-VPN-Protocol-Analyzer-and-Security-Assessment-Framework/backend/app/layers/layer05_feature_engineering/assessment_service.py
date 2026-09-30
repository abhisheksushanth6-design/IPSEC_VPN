"""Layer 05 Security Assessment Service.

Orchestrates security rule evaluations across decoded traffic, SA states,
and protocol anomalies, managing Layer 05 verification and health status.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from app.layers.layer03_protocol_analysis.models import (
    IPLayer,
    IPsecAnalysis,
    PacketAnalysisResult,
    ProtocolAnomaly,
)
from app.layers.layer04_sa_lifecycle.models import VPNSessionFingerprint
from app.layers.layer05_feature_engineering.assessment_models import (
    RiskAssessmentReport,
)
from app.layers.layer05_feature_engineering.assessment_rules import (
    run_security_assessment,
)

logger = logging.getLogger(__name__)


class SecurityAssessmentService:
    """Service managing Layer 05 Security Assessment and Risk Engine."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._verify_lock = threading.Lock()
        self._verified: bool = False
        self._last_report: Optional[RiskAssessmentReport] = None

    def verify_engine(self) -> bool:
        """Run automated self-test validating rule evaluations and risk scoring."""
        with self._verify_lock:
            if self._verified:
                return True
            try:
                # 1. Synthesize test session with weak cipher
                test_sess = VPNSessionFingerprint(
                    session_id="test_sess_01",
                    capture_id="verify",
                    fingerprint="0" * 64,
                    short_signature="0" * 16,
                    initiator_ip="192.168.1.1",
                    responder_ip="192.168.1.2",
                    endpoint_pair=["192.168.1.1", "192.168.1.2"],
                    protocols=["IKE", "ESP"],
                    state="ACTIVE",
                    start_time="1.0",
                    end_time="2.0",
                    duration_seconds=1.0,
                    total_packets=2,
                    total_bytes=200,
                    ike_packets=1,
                    esp_packets=1,
                    ah_packets=0,
                    ike_version="IKEv2",
                    initiator_spi="0102030405060708",
                    responder_spi="1122334455667788",
                    child_sa_spis=["0x12345678"],
                    encapsulation_mode="TUNNEL",
                    nat_traversal=False,
                    crypto_summary={
                        "encryption": ["3DES-CBC"],
                        "integrity": ["HMAC-MD5-96"],
                        "dh_groups": ["1024-bit MODP (Group 2)"],
                        "prf": ["PRF_HMAC_MD5"],
                    },
                )

                # 2. Run assessment
                report = run_security_assessment(
                    packets=[],
                    sessions=[test_sess],
                    protocol_report=None,
                    capture_id="verify_test",
                )

                # 3. Assertions on findings
                if report.findings_count < 2 or report.overall_risk_score <= 0.0:
                    logger.error("Layer 05 verification failed: expected >=2 findings and risk_score > 0, got %s, score=%s", report.findings_count, report.overall_risk_score)
                    return False

                has_crypto_finding = any(f.rule_id == "SEC-CRYPTO-001" for f in report.findings)
                if not has_crypto_finding:
                    logger.error("Layer 05 verification failed: SEC-CRYPTO-001 not triggered")
                    return False

                self._verified = True
                logger.info("Layer 05 Security Assessment engine verified successfully (status: READY)")
                return True
            except Exception as e:
                logger.error("Layer 05 self-verification error: %s", e, exc_info=True)
                return False

    def get_layer_status(self) -> str:
        """Report Layer 05 dynamic status based on engine verification."""
        return "READY" if self.verify_engine() else "NOT INITIALIZED"

    def evaluate_capture(
        self,
        packets: list[PacketAnalysisResult],
        capture_id: str = "default",
    ) -> RiskAssessmentReport:
        """Evaluate loaded capture packets and correlated sessions."""
        from app.layers.layer03_protocol_analysis.service import get_protocol_analysis_service
        from app.layers.layer04_sa_lifecycle.service import get_layer04_service

        proto_svc = get_protocol_analysis_service()
        protocol_report = proto_svc.analyze(packets, capture_id=capture_id)

        layer04_svc = get_layer04_service()
        sessions = layer04_svc.correlate_capture(packets, capture_id=capture_id)

        report = run_security_assessment(
            packets=packets,
            sessions=sessions,
            protocol_report=protocol_report,
            capture_id=capture_id,
        )

        with self._lock:
            self._last_report = report
        return report

    def get_last_report(self) -> Optional[RiskAssessmentReport]:
        with self._lock:
            return self._last_report


_security_assessment_service: Optional[SecurityAssessmentService] = None
_service_lock = threading.Lock()


def get_security_assessment_service() -> SecurityAssessmentService:
    global _security_assessment_service
    with _service_lock:
        if _security_assessment_service is None:
            _security_assessment_service = SecurityAssessmentService()
        return _security_assessment_service
