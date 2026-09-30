"""Tests for the SIH 26160 Security Assessment Engine (Layer 08 / Layer 09).

Verifies, with provenance-aware semantics:
1. Cryptographic strength evaluation (graded only when the suite was observed or decisively inferred)
2. Configuration compliance against the rule set and the published algorithm profiles
3. SA parameters evaluation
4. Key lifetime analysis
5. Replay protection evaluation (per-SPI sequence analysis)
6. Forward Secrecy (PFS) — ENABLED / DISABLED / UNKNOWN, never a fabricated boolean
7. Cipher suite strength
8. Metadata exposure (5 vectors, traffic-aware)
9. Explainable findings: Finding -> Evidence -> Severity -> Reason -> Recommendation
10. REST API endpoints
"""

from __future__ import annotations

from sqlalchemy import select
from starlette.testclient import TestClient

import synthetic_traffic_generator as STG
from app.db.base import SessionLocal
from app.layers.layer01_test_environment.software_testbed import generate_capture
from app.layers.layer09_vulnerability_engine.security_assessment import SecurityAssessmentEngine
from app.models.ipsec_session import IPsecSession
from app.services.packet_service import packet_service


def _load(client: TestClient, filename: str, pcap: bytes) -> str:
    resp = client.post("/api/packets/upload", files={"file": (filename, pcap, "application/octet-stream")})
    assert resp.status_code == 201, resp.text
    client.post("/api/sessions/discover")
    client.post("/api/sas/discover")
    with SessionLocal() as db:
        rows = db.scalars(select(IPsecSession).where(IPsecSession.capture_id == packet_service.capture_id)).all()
    assert rows
    return max(rows, key=lambda s: s.packet_count).id


def _check_common(assessment) -> None:
    assert 0.0 <= assessment.overall_security_score <= 100.0
    assert 0.0 <= assessment.overall_risk_score <= 100.0
    assert assessment.security_posture in ("ROBUST", "MODERATE", "ELEVATED_RISK", "CRITICAL_DEFICIENCIES")
    assert 0.0 <= assessment.ai_confidence <= 1.0
    assert assessment.coverage.summary

    # 2. Configuration compliance
    comp = assessment.configuration_compliance
    assert comp.compliance_status in ("COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT")
    assert comp.rules_evaluated > 0
    assert {p["profile_id"] for p in comp.profiles} == {"IETF-BASELINE", "NIST-SP800-77R1", "CNSA-1.0"}
    for profile in comp.profiles:
        assert profile["status"] in ("COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT", "NOT_ASSESSABLE")
        assert 0.0 <= profile["coverage"] <= 1.0

    # 3. SA parameters
    assert assessment.sa_parameters.active_sas_count >= 1
    assert assessment.sa_parameters.status in ("OPTIMAL", "WARNING", "DEGRADED")

    # 4. Key lifetime
    assert assessment.key_lifetime.lifetime_status in ("COMPLIANT", "NEAR_EXPIRATION", "EXCEEDED", "UNKNOWN")
    assert assessment.key_lifetime.observed_volume_bytes >= 0

    # 5. Replay protection — per-SPI sequence analysis, ESN never claimed
    replay = assessment.replay_protection
    assert replay.status in ("ENABLED", "DISABLED", "UNVERIFIED")
    assert replay.replay_window_size == 64
    assert replay.verdict in ("PROTECTED", "DEGRADED", "REPLAY_INDICATORS", "UNVERIFIED")
    assert replay.esn_observable is False and replay.esn_supported is None

    # 6. Forward secrecy — tri-state
    assert assessment.forward_secrecy.pfs_status in ("ENABLED", "DISABLED", "UNKNOWN")
    assert assessment.forward_secrecy.security_level in ("STRONG", "MODERATE", "INSECURE", "UNKNOWN")

    # 7. Cipher suite
    assert assessment.cipher_suite_strength.quantum_readiness in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")

    # 8. Metadata exposure
    assert assessment.metadata_exposure.exposure_level in ("LOW", "MEDIUM", "HIGH")
    assert 0.0 <= assessment.metadata_exposure.composite_score <= 100.0
    assert len(assessment.metadata_exposure.observable_vectors) >= 3

    # 9. Explainable findings
    for finding in assessment.explainable_findings:
        assert len(finding.finding) > 0
        assert len(finding.evidence) > 0
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert len(finding.reason) > 0
        assert len(finding.recommendation) > 0
        assert finding.provenance in ("OBSERVED", "INFERRED", "PREDICTED", "ASSUMED")


def test_comprehensive_security_assessment_esp_only(client: TestClient) -> None:
    """Without IKE in the capture the crypto suite is NOT ASSESSABLE and the score says so."""
    session_id = _load(client, "sec_eval.pcap", STG.timed_pcap(STG.build_voip_traffic(count=30)))

    with SessionLocal() as db:
        session = db.get(IPsecSession, session_id)
        assert session is not None
        assessment = SecurityAssessmentEngine.evaluate_session(db, session)

    assert assessment.session_id == session_id
    _check_common(assessment)

    crypto = assessment.cryptographic_strength
    assert crypto.provenance in ("INFERRED", "UNAVAILABLE")
    if not crypto.assessable:
        assert crypto.grade == "N/A" and crypto.status == "NOT_ASSESSABLE" and crypto.score is None
        assert crypto.key_length_bits is None
    else:  # decisively inferred from ESP framing → a provisional grade
        assert crypto.provisional is True
        assert crypto.grade in ("A+", "A", "B", "C", "F")
    assert assessment.forward_secrecy.pfs_status == "UNKNOWN"
    assert assessment.forward_secrecy.pfs_enabled is None
    assert assessment.forward_secrecy.assessable is False
    assert any(u["component"] in ("forward_secrecy", "pfs", "cryptographic_strength", "crypto") for u in assessment.coverage.unassessable)
    assert assessment.replay_protection.verdict == "PROTECTED"
    assert assessment.replay_protection.duplicates_count == 0

    # 10. REST API
    resp = client.get(f"/api/security-assessment/comprehensive/{session_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == session_id
    for key in ("cryptographic_strength", "configuration_compliance", "metadata_exposure", "explainable_findings",
                "coverage", "ai_confidence", "traffic_prediction", "protocol_identification", "component_scores"):
        assert key in data
    assert data["coverage"]["summary"]


def test_comprehensive_security_assessment_observed_strong_suite(client: TestClient) -> None:
    """IKEv2 AES-256-GCM / ECP-256 / PFS from the testbed is graded from the observed negotiation."""
    cap = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=4242, duration=30.0)
    session_id = _load(client, cap.filename, cap.pcap_bytes)

    with SessionLocal() as db:
        session = db.get(IPsecSession, session_id)
        assessment = SecurityAssessmentEngine.evaluate_session(db, session)
    _check_common(assessment)

    crypto = assessment.cryptographic_strength
    assert crypto.provenance == "OBSERVED"
    assert crypto.assessable is True and crypto.provisional is False
    assert crypto.grade in ("A+", "A")
    assert crypto.status == "SECURE"
    assert crypto.key_length_bits == 256
    assert "GCM" in crypto.cipher.upper()
    assert assessment.forward_secrecy.pfs_status != "DISABLED"
    assert assessment.cipher_suite_strength.quantum_readiness in ("MEDIUM", "HIGH")
    assert assessment.overall_security_score >= 70.0
    profiles = {p["profile_id"]: p for p in assessment.configuration_compliance.profiles}
    assert profiles["IETF-BASELINE"]["status"] in ("COMPLIANT", "PARTIALLY_COMPLIANT")
    assert profiles["NIST-SP800-77R1"]["status"] in ("COMPLIANT", "PARTIALLY_COMPLIANT")
    assert profiles["CNSA-1.0"]["status"] != "COMPLIANT", "ECP-256 does not meet CNSA 1.0 (ECP-384 required)"
    assert not any(f.rule_id == "RULE-CRYPTO-006" for f in assessment.explainable_findings)


def test_comprehensive_security_assessment_observed_weak_suite(client: TestClient) -> None:
    """IKEv1 aggressive mode with 3DES / MD5 / MODP-1024 and no PFS fails every profile with explainable findings."""
    cap = generate_capture("PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4", seed=4243, duration=30.0)
    session_id = _load(client, cap.filename, cap.pcap_bytes)

    with SessionLocal() as db:
        session = db.get(IPsecSession, session_id)
        assessment = SecurityAssessmentEngine.evaluate_session(db, session)
    _check_common(assessment)

    crypto = assessment.cryptographic_strength
    assert crypto.provenance == "OBSERVED"
    assert crypto.grade == "F"
    assert crypto.status == "INSECURE"
    assert "3DES" in crypto.cipher.upper()
    assert assessment.forward_secrecy.pfs_status != "ENABLED"
    assert assessment.security_posture in ("ELEVATED_RISK", "CRITICAL_DEFICIENCIES")
    assert assessment.overall_security_score < 65.0
    assert all(p["status"] == "NON_COMPLIANT" for p in assessment.configuration_compliance.profiles)
    severities = {f.severity for f in assessment.explainable_findings}
    assert severities & {"CRITICAL", "HIGH"}
    assert len(assessment.explainable_findings) >= 3
    rule_ids = {f.rule_id for f in assessment.explainable_findings if f.rule_id}
    assert len(rule_ids) == len([f for f in assessment.explainable_findings if f.rule_id]), "no duplicated rule findings"
