"""Layer 05: Security Assessment & Risk Engine Test Suite.

Verifies:
- Rule-based evaluation of cryptographic proposals (DES, 3DES, MD5, weak DH)
- Sequence integrity evaluation (replays, seq=0, sequence gaps)
- Cleartext leakage and split-tunnel risk detection
- Weighted risk score calculation and risk tier mapping
- Structured finding generation with remediations, CVEs, and evidence
- Dynamic Layer 05 READY status via engine self-verification
- FastAPI endpoints (/api/security-assessment, /findings, /risk-score)
"""

from __future__ import annotations

import io
import pytest

from packet_builders import esp, ethernet, ikev2, ipv4, pcap, udp

from app.layers.layer03_protocol_analysis.models import (
    ESPLayer,
    IKELayer,
    IKEProposal,
    IPLayer,
    IPsecAnalysis,
    PacketAnalysisResult,
    ProtocolAnalysisReport,
    ProtocolAnomaly,
)
from app.layers.layer04_sa_lifecycle.models import VPNSessionFingerprint
from app.layers.layer05_feature_engineering.assessment_models import (
    RiskAssessmentReport,
    SecurityFinding,
)
from app.layers.layer05_feature_engineering.assessment_rules import (
    run_security_assessment,
)
from app.layers.layer05_feature_engineering.assessment_service import (
    SecurityAssessmentService,
    get_security_assessment_service,
)


def _make_test_session(
    encryption: list[str] = None,
    integrity: list[str] = None,
    dh_groups: list[str] = None,
    state: str = "ACTIVE",
) -> VPNSessionFingerprint:
    return VPNSessionFingerprint(
        session_id="sess_test_123",
        capture_id="cap_01",
        fingerprint="a" * 64,
        short_signature="a" * 16,
        initiator_ip="192.168.1.10",
        responder_ip="192.168.1.20",
        endpoint_pair=["192.168.1.10", "192.168.1.20"],
        protocols=["IKE", "ESP"],
        state=state,  # type: ignore[arg-type]
        start_time="1.0",
        end_time="5.0",
        duration_seconds=4.0,
        total_packets=10,
        total_bytes=1200,
        ike_packets=4,
        esp_packets=6,
        ah_packets=0,
        ike_version="IKEv2",
        initiator_spi="0102030405060708",
        responder_spi="8070605040302010",
        child_sa_spis=["0x12345678"],
        encapsulation_mode="TUNNEL",
        nat_traversal=False,
        crypto_summary={
            "encryption": encryption or ["AES-CBC-256"],
            "integrity": integrity or ["HMAC-SHA2-256"],
            "dh_groups": dh_groups or ["2048-bit MODP (Group 14)"],
            "prf": ["PRF_HMAC_SHA2_256"],
        },
    )


# =============================================================================
# Unit Tests: Cryptographic Rule Evaluations
# =============================================================================

def test_insecure_cipher_detection_3des_and_des() -> None:
    session = _make_test_session(encryption=["3DES-CBC", "DES-CBC"])
    report = run_security_assessment(packets=[], sessions=[session], protocol_report=None)

    findings = [f for f in report.findings if f.rule_id == "SEC-CRYPTO-001"]
    assert len(findings) >= 1

    finding = findings[0]
    assert finding.category == "CRYPTOGRAPHY"
    assert finding.severity in ("HIGH", "CRITICAL")
    assert finding.confidence == 1.0
    assert "CVE-2016-2183" in finding.cve_references
    assert "remediation" in finding.__dict__ and len(finding.remediation) > 10
    assert report.overall_risk_score > 0.0


def test_weak_hash_and_dh_group_detection() -> None:
    session = _make_test_session(
        encryption=["AES-CBC-128"],
        integrity=["HMAC-MD5-96"],
        dh_groups=["1024-bit MODP (Group 2)"],
    )
    report = run_security_assessment(packets=[], sessions=[session], protocol_report=None)

    rule_ids = {f.rule_id for f in report.findings}
    assert "SEC-CRYPTO-002" in rule_ids  # MD5
    assert "SEC-CRYPTO-003" in rule_ids  # DH Group 2

    dh_finding = next(f for f in report.findings if f.rule_id == "SEC-CRYPTO-003")
    assert dh_finding.severity == "HIGH"
    assert "CVE-2015-4000" in dh_finding.cve_references


def test_modern_crypto_suite_compliant_info_finding() -> None:
    session = _make_test_session(
        encryption=["AES-GCM-256"],
        integrity=[],
        dh_groups=["2048-bit MODP (Group 14)"],
    )
    report = run_security_assessment(packets=[], sessions=[session], protocol_report=None)

    rule_ids = {f.rule_id for f in report.findings}
    assert "SEC-CRYPTO-004" in rule_ids
    assert report.risk_level == "MINIMAL"
    assert report.overall_risk_score == 0.0


# =============================================================================
# Unit Tests: Protocol Anomaly & Leakage Rules
# =============================================================================

def test_sequence_replay_and_sequence_zero_assessment() -> None:
    session = _make_test_session()
    proto_report = ProtocolAnalysisReport(
        capture_id="cap_anom",
        total_packets_analyzed=5,
        ipsec_packets=5,
        ike_summary={},
        anomalies=[
            ProtocolAnomaly(
                id="anom-1",
                anomaly_type="SEQ_REPLAY",
                severity="HIGH",
                packet_number=3,
                spi="0x12345678",
                source_ip="192.168.1.10",
                destination_ip="192.168.1.20",
                description="Duplicate sequence number",
                evidence={"spi": "0x12345678", "sequence_number": 1},
            ),
            ProtocolAnomaly(
                id="anom-2",
                anomaly_type="SEQ_ZERO",
                severity="HIGH",
                packet_number=1,
                spi="0x12345678",
                source_ip="192.168.1.10",
                destination_ip="192.168.1.20",
                description="Sequence number 0",
                evidence={"spi": "0x12345678"},
            ),
        ],
        analysis_timestamp="2026-09-11T00:00:00Z",
    )

    report = run_security_assessment(packets=[], sessions=[session], protocol_report=proto_report)
    rule_ids = {f.rule_id for f in report.findings}

    assert "SEC-INTEG-001" in rule_ids
    assert "SEC-INTEG-002" in rule_ids
    assert report.overall_risk_score >= 36.0  # 18 + 18


def test_cleartext_leakage_critical_assessment() -> None:
    session = _make_test_session()
    proto_report = ProtocolAnalysisReport(
        capture_id="cap_leak",
        total_packets_analyzed=10,
        ipsec_packets=8,
        ike_summary={},
        anomalies=[
            ProtocolAnomaly(
                id="leak-1",
                anomaly_type="CLEARTEXT_LEAK",
                severity="CRITICAL",
                packet_number=5,
                spi=None,
                source_ip="192.168.1.10",
                destination_ip="192.168.1.20",
                description="Unencrypted cleartext traffic",
                evidence={"protocol": "TCP", "dport": 80},
            )
        ],
        analysis_timestamp="2026-09-11T00:00:00Z",
    )

    report = run_security_assessment(packets=[], sessions=[session], protocol_report=proto_report)

    leak_findings = [f for f in report.findings if f.rule_id == "SEC-LEAK-001"]
    assert len(leak_findings) == 1
    assert leak_findings[0].severity == "CRITICAL"
    assert leak_findings[0].category == "DATA_LEAKAGE"
    assert report.risk_level == "CRITICAL"


# =============================================================================
# Unit Tests: Layer 5 Service Verification & Dynamic Status
# =============================================================================

def test_layer05_self_verification_and_ready_status() -> None:
    svc = SecurityAssessmentService()
    verified = svc.verify_engine()
    assert verified is True, "Layer 05 engine self-verification failed"
    assert svc.get_layer_status() == "READY"


# =============================================================================
# Integration Tests: FastAPI Endpoints
# =============================================================================

def test_fastapi_security_assessment_endpoints(client) -> None:
    # 1. Upload capture with IKE and ESP packets
    f1 = ethernet(ipv4(udp(ikev2(), 500, 500), proto=17, src="192.168.10.1", dst="192.168.20.1"))
    f2 = ethernet(ipv4(esp(spi=0x12345678, seq=1), proto=50, src="192.168.10.1", dst="192.168.20.1"))
    pcap_data = pcap([f1, f2])

    upload_res = client.post(
        "/api/packets/upload",
        files={"file": ("test_layer5.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
    )
    assert upload_res.status_code == 201

    # 2. Test GET /api/security-assessment
    res = client.get("/api/security-assessment")
    assert res.status_code == 200
    data = res.json()
    assert "overall_risk_score" in data
    assert "risk_level" in data
    assert "findings" in data
    assert "status" in data
    assert data["status"] == "READY"

    # 3. Test GET /api/security-assessment/findings
    res_findings = client.get("/api/security-assessment/findings")
    assert res_findings.status_code == 200
    assert isinstance(res_findings.json(), list)

    # 4. Test GET /api/security-assessment/risk-score
    res_score = client.get("/api/security-assessment/risk-score")
    assert res_score.status_code == 200
    score_data = res_score.json()
    assert "overall_risk_score" in score_data
    assert "risk_level" in score_data
    assert score_data["status"] == "READY"

    # 5. Test Layer 5 in GET /api/system/status
    res_sys = client.get("/api/system/status")
    assert res_sys.status_code == 200
    sys_data = res_sys.json()
    layer5 = next(l for l in sys_data["architecture_layers"] if l["number"] == 5)
    assert layer5["status"] == "READY"
