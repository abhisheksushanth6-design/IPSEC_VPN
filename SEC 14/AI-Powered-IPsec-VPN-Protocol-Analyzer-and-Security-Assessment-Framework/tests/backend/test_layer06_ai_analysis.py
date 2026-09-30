"""Automated test suite for Layer 06: AI-Powered Security Analysis."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.layers.layer05_feature_engineering.assessment_models import (
    RiskAssessmentReport,
    SecurityFinding,
)
from app.layers.layer06_session_fingerprinting.ai_analysis_models import (
    AISecurityAnalysis,
    ExecutiveSummary,
    PrioritizedFinding,
    RemediationStep,
    TechnicalSummary,
)
from app.layers.layer06_session_fingerprinting.ai_analysis_providers import (
    ConfigurableRealLLMProvider,
    DeterministicAIProvider,
)
from app.layers.layer06_session_fingerprinting.ai_analysis_service import (
    AISecurityAnalysisService,
    get_ai_security_analysis_service,
)


@pytest.fixture
def client():
    return TestClient(app)


def _build_sample_findings() -> list[SecurityFinding]:
    return [
        SecurityFinding(
            finding_id="F-CRYPTO-01",
            rule_id="SEC-CRYPTO-001",
            title="Insecure Cipher: 3DES",
            category="CRYPTOGRAPHY",
            severity="CRITICAL",
            confidence=1.0,
            explanation="3DES is deprecated and vulnerable to Sweet32 collisions.",
            evidence={"cipher": "3DES-CBC"},
            remediation="Upgrade to AES-256-GCM.",
            cve_references=["CVE-2016-2183"],
        ),
        SecurityFinding(
            finding_id="F-DH-01",
            rule_id="SEC-CRYPTO-003",
            title="Weak Diffie-Hellman Group: Group 2",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            confidence=0.95,
            explanation="MODP 1024-bit provides less than 112 bits of security.",
            evidence={"dh_group": "MODP 1024 (Group 2)"},
            remediation="Enforce MODP 2048 (Group 14) or Curve25519.",
        ),
        SecurityFinding(
            finding_id="F-HASH-01",
            rule_id="SEC-CRYPTO-002",
            title="Deprecated Hash: SHA-1",
            category="CRYPTOGRAPHY",
            severity="MEDIUM",
            confidence=0.9,
            explanation="SHA-1 suffers from collision attacks.",
            evidence={"hash": "SHA-1"},
            remediation="Upgrade to SHA-256.",
        ),
        SecurityFinding(
            finding_id="F-LEAK-01",
            rule_id="SEC-LEAK-001",
            title="Cleartext Traffic Leakage",
            category="DATA_LEAKAGE",
            severity="HIGH",
            confidence=1.0,
            explanation="Unencrypted TCP packets observed between tunnel endpoints.",
            evidence={"cleartext_packet_count": 4},
            remediation="Implement egress drop firewall rules for non-ESP frames.",
        ),
    ]


def _build_sample_report(findings: list[SecurityFinding], score: float = 75.0, level: str = "CRITICAL") -> RiskAssessmentReport:
    return RiskAssessmentReport(
        capture_id="cap_test_01",
        overall_risk_score=score,
        risk_level=level,
        findings_count=len(findings),
        findings_by_severity={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0},
        findings=findings,
        evaluated_sessions_count=2,
        evaluated_tunnels_count=1,
        evaluated_packets_count=120,
        assessment_timestamp=datetime.now(timezone.utc).isoformat(),
        status="READY",
    )


def test_deterministic_provider_empty_report():
    """Verify that an empty/clean report produces coherent baseline security narratives."""
    empty_report = RiskAssessmentReport(
        capture_id="clean_cap",
        overall_risk_score=0.0,
        risk_level="MINIMAL",
        findings_count=0,
        findings_by_severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        findings=[],
        evaluated_sessions_count=1,
        evaluated_tunnels_count=1,
        evaluated_packets_count=30,
        assessment_timestamp=datetime.now(timezone.utc).isoformat(),
        status="READY",
    )
    provider = DeterministicAIProvider()
    analysis = provider.generate_analysis(empty_report)

    assert analysis.overall_risk_score == 0.0
    assert analysis.risk_level == "MINIMAL"
    assert len(analysis.prioritized_findings) == 0
    assert len(analysis.attack_implications) == 1
    assert "Compliant" in analysis.attack_implications[0].vector_name
    assert "ROBUST" in analysis.executive_summary.overall_posture
    assert len(analysis.remediation_steps) >= 1  # Architectural phase step
    assert "RFC 8221" in analysis.technical_summary.rfc_compliance_citations[2]


def test_deterministic_provider_with_critical_findings():
    """Verify finding prioritization, attack modeling, and remediation for vulnerable captures."""
    findings = _build_sample_findings()
    report = _build_sample_report(findings)

    provider = DeterministicAIProvider()
    analysis = provider.generate_analysis(report)

    # Prioritization checks
    assert len(analysis.prioritized_findings) == 4
    p1 = analysis.prioritized_findings[0]
    assert p1.finding_id == "F-CRYPTO-01"
    assert p1.priority_rank == "P1_CRITICAL"
    assert p1.urgency == "IMMEDIATE"
    assert p1.exploitability_score >= 9.0
    assert "Sweet32" in p1.justification

    p2_ranks = [p for p in analysis.prioritized_findings if p.priority_rank == "P2_HIGH"]
    assert len(p2_ranks) == 2  # DH group & cleartext leak

    # Attack Implications checks
    vectors = {atk.attack_id: atk for atk in analysis.attack_implications}
    assert "ATK-VEC-001" in vectors  # Sweet32
    assert "CVE-2016-2183" in vectors["ATK-VEC-001"].exploit_scenario or "3DES" in vectors["ATK-VEC-001"].exploit_scenario
    assert "ATK-VEC-002" in vectors  # Logjam DH
    assert "ATK-VEC-004" in vectors  # Cleartext leakage

    # Remediation Steps checks
    phases = {step.phase for step in analysis.remediation_steps}
    assert "PHASE_1_IMMEDIATE" in phases
    assert "PHASE_2_HARDENING" in phases
    assert "PHASE_3_ARCHITECTURAL" in phases

    rem_01 = next(s for s in analysis.remediation_steps if s.step_id == "REM-01")
    assert "aes256gcm" in rem_01.config_snippet

    # Executive & Technical summaries
    assert "HIGH RISK" in analysis.executive_summary.overall_posture
    assert "3DES" in analysis.technical_summary.cryptographic_assessment
    assert "Cleartext" in analysis.technical_summary.leakage_and_exposure_analysis


def test_finding_prioritization_sorting_order():
    """Verify that findings of mixed severities are strictly sorted by triage priority."""
    mixed_findings = [
        SecurityFinding(
            finding_id="F-LOW",
            rule_id="SEC-INTEG-003",
            title="Sequence Gap",
            category="INTEGRITY",
            severity="LOW",
            confidence=0.5,
            explanation="Gap > 1000",
        ),
        SecurityFinding(
            finding_id="F-CRIT",
            rule_id="SEC-CRYPTO-001",
            title="3DES",
            category="CRYPTOGRAPHY",
            severity="CRITICAL",
            confidence=1.0,
            explanation="Sweet32",
        ),
        SecurityFinding(
            finding_id="F-MED",
            rule_id="SEC-CRYPTO-002",
            title="MD5",
            category="CRYPTOGRAPHY",
            severity="MEDIUM",
            confidence=0.8,
            explanation="MD5 collision",
        ),
        SecurityFinding(
            finding_id="F-HIGH",
            rule_id="SEC-INTEG-001",
            title="Replay",
            category="INTEGRITY",
            severity="HIGH",
            confidence=0.9,
            explanation="Replay detected",
        ),
    ]
    report = _build_sample_report(mixed_findings)
    provider = DeterministicAIProvider()
    analysis = provider.generate_analysis(report)

    ranks = [p.priority_rank for p in analysis.prioritized_findings]
    assert ranks == ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"]


def test_configurable_real_llm_graceful_fallback():
    """Verify that ConfigurableRealLLMProvider falls back smoothly without requiring an API key."""
    report = _build_sample_report(_build_sample_findings())

    # Case 1: No API key provided (offline / test default)
    offline_provider = ConfigurableRealLLMProvider(api_key=None)
    analysis = offline_provider.generate_analysis(report)
    assert analysis.provider_used == "deterministic"
    assert len(analysis.prioritized_findings) > 0

    # Case 2: Configured with invalid endpoint (network failure simulation)
    failing_provider = ConfigurableRealLLMProvider(
        api_key="sk-dummy-mock-key",
        base_url="http://127.0.0.1:54321/v1",  # Non-existent endpoint
    )
    fallback_analysis = failing_provider.generate_analysis(report)
    assert fallback_analysis.provider_used == "deterministic_fallback"
    assert len(fallback_analysis.prioritized_findings) > 0
    assert len(fallback_analysis.attack_implications) > 0


def test_layer06_self_verification_and_ready_status():
    """Verify that Layer 06 self-verification executes and returns READY status."""
    service = AISecurityAnalysisService()
    assert service.verify_engine() is True
    assert service.get_layer_status() == "READY"

    # Global singleton verification
    global_svc = get_ai_security_analysis_service()
    assert global_svc.get_layer_status() == "READY"


def test_fastapi_ai_analysis_endpoints(client: TestClient):
    """Verify that all Layer 06 FastAPI endpoints serve valid structured responses."""
    # 1. Full analysis endpoint
    resp = client.get("/api/ai-analysis")
    assert resp.status_code == 200
    data = resp.json()
    assert "analysis_id" in data
    assert "executive_summary" in data
    assert "technical_summary" in data
    assert "prioritized_findings" in data
    assert "attack_implications" in data
    assert "remediation_steps" in data

    # 2. Executive summary endpoint
    resp_exec = client.get("/api/ai-analysis/executive-summary")
    assert resp_exec.status_code == 200
    exec_data = resp_exec.json()
    assert "overall_posture" in exec_data
    assert "risk_score_summary" in exec_data
    assert "business_impact" in exec_data

    # 3. Remediation roadmap endpoint
    resp_rem = client.get("/api/ai-analysis/remediation")
    assert resp_rem.status_code == 200
    rem_steps = resp_rem.json()
    assert isinstance(rem_steps, list)
    assert len(rem_steps) >= 1

    # 4. Filtered remediation
    resp_filter = client.get("/api/ai-analysis/remediation?phase=PHASE_3_ARCHITECTURAL")
    assert resp_filter.status_code == 200
    for step in resp_filter.json():
        assert step["phase"] == "PHASE_3_ARCHITECTURAL"

    # 5. Technical summary endpoint
    resp_tech = client.get("/api/ai-analysis/technical-summary")
    assert resp_tech.status_code == 200
    tech_data = resp_tech.json()
    assert "protocol_health" in tech_data
    assert "cryptographic_assessment" in tech_data
    assert "rfc_compliance_citations" in tech_data

    # 6. POST analyze endpoint
    resp_post = client.post("/api/ai-analysis/analyze", json={"provider": "deterministic"})
    assert resp_post.status_code == 200
    assert resp_post.json()["provider_used"] == "deterministic"
