"""Tests for SIH 26160 Security Assessment Engine (Layer 08 / Layer 09).

Verifies:
1. Cryptographic strength evaluation
2. Configuration compliance against policy
3. SA parameters evaluation
4. Key lifetime analysis
5. Replay protection evaluation
6. Forward Secrecy (PFS)
7. Cipher suite strength
8. Metadata exposure (5 vectors)
9. Explainable findings: Finding -> Evidence -> Severity -> Reason -> Recommendation
10. REST API endpoints
"""

from __future__ import annotations

import json
from starlette.testclient import TestClient

from app.db.base import SessionLocal
from app.layers.layer09_vulnerability_engine.security_assessment import SecurityAssessmentEngine
from app.main import app
from app.models.ipsec_session import IPsecSession
import synthetic_traffic_generator as STG


def test_comprehensive_security_assessment_evaluation() -> None:
    client = TestClient(app)

    # Ingest synthetic traffic
    frames = STG.build_voip_traffic(count=30)
    pcap = STG.timed_pcap(frames)
    client.post("/api/packets/upload", files={"file": ("sec_eval.pcap", pcap, "application/octet-stream")})
    client.post("/api/sessions/discover")

    sessions_resp = client.get("/api/sessions")
    assert sessions_resp.status_code == 200
    sessions = sessions_resp.json()["items"]
    assert len(sessions) > 0
    session_id = sessions[0]["id"]

    with SessionLocal() as db:
        session = db.get(IPsecSession, session_id)
        assert session is not None

        assessment = SecurityAssessmentEngine.evaluate_session(db, session)
        assert assessment.session_id == session_id
        assert 0.0 <= assessment.overall_security_score <= 100.0
        assert 0.0 <= assessment.overall_risk_score <= 100.0
        assert assessment.security_posture in ("ROBUST", "MODERATE", "ELEVATED_RISK", "CRITICAL_DEFICIENCIES")

        # 1. Cryptographic Strength
        assert assessment.cryptographic_strength.grade in ("A+", "A", "B", "C", "F")
        assert assessment.cryptographic_strength.status in ("SECURE", "ACCEPTABLE", "WEAK", "INSECURE")
        assert assessment.cryptographic_strength.key_length_bits in (128, 192, 256)

        # 2. Configuration Compliance
        assert assessment.configuration_compliance.compliance_status in ("COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT")
        assert assessment.configuration_compliance.rules_evaluated > 0

        # 3. SA Parameters
        assert assessment.sa_parameters.active_sas_count >= 1
        assert assessment.sa_parameters.status in ("OPTIMAL", "WARNING", "DEGRADED")

        # 4. Key Lifetime
        assert assessment.key_lifetime.lifetime_status in ("COMPLIANT", "NEAR_EXPIRATION", "EXCEEDED")
        assert assessment.key_lifetime.observed_volume_bytes >= 0

        # 5. Replay Protection
        assert assessment.replay_protection.status in ("ENABLED", "DISABLED", "UNVERIFIED")
        assert assessment.replay_protection.replay_window_size == 64
        assert assessment.replay_protection.verdict in ("PROTECTED", "VULNERABLE")

        # 6. Forward Secrecy
        assert isinstance(assessment.forward_secrecy.pfs_enabled, bool)
        assert assessment.forward_secrecy.security_level in ("STRONG", "MODERATE", "INSECURE")

        # 7. Cipher Suite
        assert assessment.cipher_suite_strength.quantum_readiness in ("LOW", "MEDIUM", "HIGH")

        # 8. Metadata Exposure
        assert assessment.metadata_exposure.exposure_level in ("LOW", "MEDIUM", "HIGH")
        assert 0.0 <= assessment.metadata_exposure.composite_score <= 100.0
        assert len(assessment.metadata_exposure.observable_vectors) >= 3

        # 9. Explainable Findings: Finding -> Evidence -> Severity -> Reason -> Recommendation
        for finding in assessment.explainable_findings:
            assert len(finding.finding) > 0
            assert len(finding.evidence) > 0
            assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            assert len(finding.reason) > 0
            assert len(finding.recommendation) > 0

    # 10. REST API verification
    resp = client.get(f"/api/security-assessment/comprehensive/{session_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == session_id
    assert "cryptographic_strength" in data
    assert "configuration_compliance" in data
    assert "metadata_exposure" in data
    assert "explainable_findings" in data
