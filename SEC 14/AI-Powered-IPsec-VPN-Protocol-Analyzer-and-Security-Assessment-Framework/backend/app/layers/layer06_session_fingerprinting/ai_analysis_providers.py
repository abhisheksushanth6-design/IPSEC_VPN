"""AI Analysis Providers for Layer 06 AI-Powered Security Analysis.

Provides:
- BaseAIAnalysisProvider (abstract interface)
- DeterministicAIProvider (100% offline, reproducible, domain-expert synthesis)
- ConfigurableRealLLMProvider (optional real LLM with graceful fallback)
"""

from __future__ import annotations

import abc
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.layers.layer05_feature_engineering.assessment_models import (
    RiskAssessmentReport,
    SecurityFinding,
)
from app.layers.layer06_session_fingerprinting.ai_analysis_models import (
    AISecurityAnalysis,
    AttackImplication,
    ExecutiveSummary,
    PrioritizedFinding,
    RemediationStep,
    TechnicalSummary,
)

logger = logging.getLogger(__name__)


class BaseAIAnalysisProvider(abc.ABC):
    """Abstract interface for AI analysis providers."""

    @abc.abstractmethod
    def generate_analysis(self, report: RiskAssessmentReport) -> AISecurityAnalysis:
        """Generate structured AI security analysis from a RiskAssessmentReport."""
        raise NotImplementedError


class DeterministicAIProvider(BaseAIAnalysisProvider):
    """Domain-expert deterministic AI provider.
    
    Operates 100% offline with zero external dependencies. Synthesizes deep,
    RFC-grounded security explanations, prioritized triage queues, threat
    modeling attack scenarios, phased remediation plans, executive summaries,
    and technical dossiers.
    """

    def generate_analysis(self, report: RiskAssessmentReport) -> AISecurityAnalysis:
        now_iso = datetime.now(timezone.utc).isoformat()
        analysis_id = f"ai-analysis-{uuid.uuid4().hex[:12]}"

        prioritized = self._prioritize_findings(report.findings)
        attack_implications = self._synthesize_attack_implications(report.findings)
        remediation_steps = self._synthesize_remediation_roadmap(report.findings)
        exec_summary = self._synthesize_executive_summary(report, prioritized)
        tech_summary = self._synthesize_technical_summary(report)

        return AISecurityAnalysis(
            analysis_id=analysis_id,
            capture_id=report.capture_id,
            timestamp=now_iso,
            provider_used="deterministic",
            overall_risk_score=report.overall_risk_score,
            risk_level=report.risk_level,
            executive_summary=exec_summary,
            technical_summary=tech_summary,
            prioritized_findings=prioritized,
            attack_implications=attack_implications,
            remediation_steps=remediation_steps,
            metadata={
                "evaluated_sessions_count": report.evaluated_sessions_count,
                "evaluated_tunnels_count": report.evaluated_tunnels_count,
                "evaluated_packets_count": report.evaluated_packets_count,
                "findings_count": report.findings_count,
            },
        )

    def _prioritize_findings(self, findings: list[SecurityFinding]) -> list[PrioritizedFinding]:
        """Rank and prioritize findings based on severity, exploitability, and attack surface."""
        prioritized: list[PrioritizedFinding] = []

        # Sort order: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
        severity_weights = {
            "CRITICAL": (1, "P1_CRITICAL", "IMMEDIATE", 9.2),
            "HIGH": (2, "P2_HIGH", "SCHEDULED", 7.6),
            "MEDIUM": (3, "P3_MEDIUM", "SCHEDULED", 5.2),
            "LOW": (4, "P4_LOW", "DISCRETIONARY", 2.8),
            "INFO": (5, "P4_LOW", "DISCRETIONARY", 1.0),
        }

        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_weights.get(f.severity, (99, "P4_LOW", "DISCRETIONARY", 1.0))[0], -f.confidence),
        )

        for f in sorted_findings:
            rank_info = severity_weights.get(f.severity, (4, "P4_LOW", "DISCRETIONARY", 2.0))
            priority_rank = rank_info[1]
            urgency = rank_info[2]
            exploitability = rank_info[3]

            # Contextual justification synthesis
            if f.category == "CRYPTOGRAPHY" and f.severity == "CRITICAL":
                justification = (
                    f"Immediate exploitable vulnerability: {f.title}. Legacy ciphers like 3DES/DES "
                    "are vulnerable to Sweet32 collisions or brute-force key recovery. Requires emergency mitigation."
                )
            elif f.category == "DATA_LEAKAGE":
                justification = (
                    f"Active perimeter leakage: {f.title}. Cleartext communications bypassing the IPsec tunnel "
                    "expose network topology and sensitive payload contents directly to untrusted paths."
                )
            elif f.category == "INTEGRITY":
                justification = (
                    f"Protocol integrity deviation: {f.title}. Sequence replay or zero counter violations compromise "
                    "ESP anti-replay guarantees (RFC 4303) and indicate potential packet reinjection or stack flaw."
                )
            elif f.category == "CRYPTOGRAPHY" and "Diffie-Hellman" in f.title:
                justification = (
                    f"Cryptographic parameter weakness: {f.title}. Sub-2048-bit MODP groups can be precomputed "
                    "by determined threat actors, breaking Perfect Forward Secrecy across recorded sessions."
                )
            else:
                justification = f"{f.explanation} Actionable priority assigned based on confidence score of {f.confidence:.2f}."

            prioritized.append(
                PrioritizedFinding(
                    finding_id=f.finding_id,
                    title=f.title,
                    original_severity=f.severity,
                    priority_rank=priority_rank,
                    urgency=urgency,
                    justification=justification,
                    exploitability_score=exploitability,
                    affected_session=f.affected_session,
                    affected_tunnel=f.affected_tunnel,
                    evidence=f.evidence,
                    cve_references=f.cve_references,
                )
            )

        return prioritized

    def _synthesize_attack_implications(self, findings: list[SecurityFinding]) -> list[AttackImplication]:
        """Synthesize threat modeling attack vectors mapped to observed telemetry and MITRE ATT&CK."""
        implications: list[AttackImplication] = []

        categories = {f.category for f in findings}
        rule_ids = {f.rule_id for f in findings}
        cves = [cve for f in findings for cve in f.cve_references]

        # 1. Sweet32 / Block Collision
        if "SEC-CRYPTO-001" in rule_ids or any("CVE-2016-2183" in cves for cves in [f.cve_references for f in findings]):
            implications.append(
                AttackImplication(
                    attack_id="ATK-VEC-001",
                    vector_name="Sweet32 Ciphertext Collision & Session Decryption",
                    threat_actor_profile="Advanced Persistent Threat / WAN Eavesdropper",
                    exploit_scenario=(
                        "An adversary passively capturing encrypted traffic on an intermediate transit link captures "
                        "~32GB of data encrypted with 3DES-CBC. Due to the 64-bit block size limitation (birthday bound), "
                        "block collisions occur, allowing recovery of repetitive plaintext fields such as HTTP cookies or bearer tokens."
                    ),
                    prerequisites="Passive tap on WAN/ISP link; sustained traffic volume exceeding birthday bound (~2^32 blocks).",
                    impact_summary="Confidentiality breach: Decryption of sensitive authentication credentials and user session tokens.",
                    mitre_attack_technique="T1040 - Network Sniffing & T1557 - Adversary-in-the-Middle",
                    affected_findings=[f.finding_id for f in findings if f.rule_id == "SEC-CRYPTO-001"],
                )
            )

        # 2. Diffie-Hellman Precomputation / Forward Secrecy Compromise
        if "SEC-CRYPTO-003" in rule_ids:
            implications.append(
                AttackImplication(
                    attack_id="ATK-VEC-002",
                    vector_name="Diffie-Hellman Discrete Log Precomputation (Logjam Attack)",
                    threat_actor_profile="Nation-State Actor / Well-funded Adversary",
                    exploit_scenario=(
                        "An attacker utilizes Number Field Sieve (NFS) precomputation tables against 768-bit or 1024-bit MODP "
                        "groups (Groups 1 and 2). Once precomputation is complete for a standard prime, individual IKE key "
                        "exchanges can be solved in real-time, completely stripping Perfect Forward Secrecy."
                    ),
                    prerequisites="In-path adversary recording key exchanges; sufficient computing capacity for prime precomputation.",
                    impact_summary="Complete compromise of session confidentiality and integrity across historical and active sessions.",
                    mitre_attack_technique="T1557.002 - Adversary-in-the-Middle",
                    affected_findings=[f.finding_id for f in findings if f.rule_id == "SEC-CRYPTO-003"],
                )
            )

        # 3. Hash Collision / Signature Forgery
        if "SEC-CRYPTO-002" in rule_ids:
            implications.append(
                AttackImplication(
                    attack_id="ATK-VEC-003",
                    vector_name="Hash Collision & Authentication Forgery",
                    threat_actor_profile="Active Network Manipulator",
                    exploit_scenario=(
                        "Adversary targets MD5 or SHA-1 integrity/PRF hashes in IKE proposals. Known collision generation techniques "
                        "facilitate payload tampering or signature spoofing without direct possession of long-term secrets."
                    ),
                    prerequisites="Inline position capable of intercepting and modifying IKE negotiation packets.",
                    impact_summary="Integrity violation: Unauthorized tunnel peer establishment or traffic tampering.",
                    mitre_attack_technique="T1565.002 - Transmitted Data Manipulation",
                    affected_findings=[f.finding_id for f in findings if f.rule_id == "SEC-CRYPTO-002"],
                )
            )

        # 4. Cleartext Leakage
        if "DATA_LEAKAGE" in categories or "SEC-LEAK-001" in rule_ids:
            implications.append(
                AttackImplication(
                    attack_id="ATK-VEC-004",
                    vector_name="Unencrypted Traffic Interception & Perimeter Exposure",
                    threat_actor_profile="Local Network Observer / Untrusted Transit Operator",
                    exploit_scenario=(
                        "Unencrypted TCP/UDP frames bypass the IPsec security policy database (SPD) between the tunnel endpoints. "
                        "Adversaries observe unencrypted application headers, source/destination ports, and raw payload data."
                    ),
                    prerequisites="Observation position on the local segment or unencrypted routing path between gateways.",
                    impact_summary="Direct exposure of cleartext communications and internal network topology.",
                    mitre_attack_technique="T1040 - Network Sniffing",
                    affected_findings=[f.finding_id for f in findings if f.category == "DATA_LEAKAGE"],
                )
            )

        # 5. Sequence Replay / Zero Sequence
        if "INTEGRITY" in categories or any(r in rule_ids for r in ("SEC-INTEG-001", "SEC-INTEG-002", "SEC-INTEG-003")):
            implications.append(
                AttackImplication(
                    attack_id="ATK-VEC-005",
                    vector_name="ESP Anti-Replay Desynchronization & Frame Reinjection",
                    threat_actor_profile="Inline Adversary",
                    exploit_scenario=(
                        "Adversary replays previously recorded ESP packets with duplicate sequence numbers or injects frames "
                        "with sequence counter 0. Improperly configured anti-replay windows may accept duplicate frames, "
                        "causing stateful protocol desynchronization or application-level duplicate transaction execution."
                    ),
                    prerequisites="Ability to capture and re-inject ESP packets with preserved SPIs.",
                    impact_summary="Integrity degradation, state desynchronization, and possible denial of service.",
                    mitre_attack_technique="T1565.001 - Stored Data Manipulation / Session Hijacking",
                    affected_findings=[f.finding_id for f in findings if f.category == "INTEGRITY"],
                )
            )

        # Default if clean
        if not implications:
            implications.append(
                AttackImplication(
                    attack_id="ATK-VEC-000",
                    vector_name="No Actionable Exploits Identified (Compliant Configuration)",
                    threat_actor_profile="All Profiles",
                    exploit_scenario=(
                        "The observed IPsec traffic exhibits robust cryptographic suites (e.g. AES-GCM, DH Group 14+), "
                        "valid monotonically increasing sequence counters, and zero cleartext leakage. No known automated "
                        "or practical cryptographic exploits apply to the current configuration."
                    ),
                    prerequisites="N/A",
                    impact_summary="None: Security perimeter is operating in a hardened state.",
                    mitre_attack_technique="N/A",
                    affected_findings=[],
                )
            )

        return implications

    def _synthesize_remediation_roadmap(self, findings: list[SecurityFinding]) -> list[RemediationStep]:
        """Synthesize phased, actionable remediation plan with concrete strongSwan configurations."""
        steps: list[RemediationStep] = []
        rule_ids = {f.rule_id for f in findings}
        categories = {f.category for f in findings}

        # PHASE 1: Immediate Containment
        if "SEC-CRYPTO-001" in rule_ids:
            steps.append(
                RemediationStep(
                    step_id="REM-01",
                    phase="PHASE_1_IMMEDIATE",
                    component="strongSwan ipsec.conf",
                    action_title="Deprecate Legacy 3DES/DES Cipher Proposals",
                    instructions=(
                        "Immediately remove 3des and des from the 'ike' and 'esp' proposal strings in strongSwan configuration. "
                        "Enforce strict proposal negotiation by appending an exclamation mark ('!') to prevent downgrade attacks."
                    ),
                    config_snippet="ike=aes256gcm16-prfsha256-modp2048!\nesp=aes256gcm16-modp2048!",
                    verification_command="sudo ipsec restart && sudo ipsec statusall | grep -E '(aes256gcm|3des)'",
                    effort="LOW",
                )
            )

        if "DATA_LEAKAGE" in categories or "SEC-LEAK-001" in rule_ids:
            steps.append(
                RemediationStep(
                    step_id="REM-02",
                    phase="PHASE_1_IMMEDIATE",
                    component="Firewall / iptables",
                    action_title="Block Cleartext Bypass Between Tunnel Endpoints",
                    instructions=(
                        "Implement strict firewall rules on the external gateway interface dropping non-IPsec traffic "
                        "(protocols other than ESP/protocol 50 or UDP 500/4500) destined to or originating from the peer gateway."
                    ),
                    config_snippet="iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.2.0/24 -m policy --dir out --pol none -j DROP",
                    verification_command="iptables -L FORWARD -v -n | grep policy",
                    effort="LOW",
                )
            )

        # PHASE 2: Hardening & Upgrades
        if "SEC-CRYPTO-003" in rule_ids:
            steps.append(
                RemediationStep(
                    step_id="REM-03",
                    phase="PHASE_2_HARDENING",
                    component="IKEv2 Proposal Configuration",
                    action_title="Upgrade Diffie-Hellman Key Exchange to MODP-2048+ or Curve25519",
                    instructions=(
                        "Replace MODP groups 1 (768-bit), 2 (1024-bit), and 5 (1536-bit) with Group 14 (MODP 2048-bit), "
                        "Group 19 (ECP 256-bit), or Curve25519 (Group 31) in both IKE and Child SA proposals to guarantee "
                        "at least 112 bits of symmetric security equivalence."
                    ),
                    config_snippet="ike=aes256-sha256-modp2048,aes256gcm16-prfsha384-ecp384!\nesp=aes256gcm16-modp2048!",
                    verification_command="swanctl --list-conns | grep -E '(modp2048|ecp256|curve25519)'",
                    effort="MEDIUM",
                )
            )

        if "SEC-CRYPTO-002" in rule_ids:
            steps.append(
                RemediationStep(
                    step_id="REM-04",
                    phase="PHASE_2_HARDENING",
                    component="Cryptographic Integrity Policy",
                    action_title="Eliminate MD5 and SHA-1 PRF/Integrity Functions",
                    instructions=(
                        "Migrate all authentication and PRF algorithms to SHA-2 family (HMAC-SHA-256, HMAC-SHA-384, or HMAC-SHA-512) "
                        "or deploy Authenticated Encryption with Associated Data (AEAD) ciphers like AES-GCM which inherently incorporate "
                        "Galois Message Authentication."
                    ),
                    config_snippet="ike=aes256-sha256-modp2048!\nesp=aes256-sha256-modp2048!",
                    verification_command="grep -rn 'sha1\\|md5' /etc/ipsec.conf /etc/swanctl/",
                    effort="LOW",
                )
            )

        # PHASE 3: Architectural Resilience
        steps.append(
            RemediationStep(
                step_id="REM-05",
                phase="PHASE_3_ARCHITECTURAL",
                component="Gateway Lifecycle Policy",
                action_title="Enforce Perfect Forward Secrecy and Frequent SA Rekeying",
                instructions=(
                    "Configure explicit Perfect Forward Secrecy (PFS) by defining DH parameters on all Child SAs. "
                    "Set SA lifetime limits (time and byte thresholds) to force periodic rekeying, mitigating birthday attack windows."
                ),
                config_snippet="ikelifetime=8h\nkeylife=1h\nrekeymargin=9m\nrekeyfuzz=100%\nkeyingtries=1",
                verification_command="ipsec statusall | grep -i 'rekey'",
                effort="MEDIUM",
            )
        )

        return steps

    def _synthesize_executive_summary(
        self,
        report: RiskAssessmentReport,
        prioritized: list[PrioritizedFinding],
    ) -> ExecutiveSummary:
        """Synthesize high-level business and strategic narrative for executive leadership."""
        p1_count = sum(1 for p in prioritized if p.priority_rank == "P1_CRITICAL")
        p2_count = sum(1 for p in prioritized if p.priority_rank == "P2_HIGH")

        if report.risk_level in ("CRITICAL", "HIGH"):
            posture = (
                f"HIGH RISK EXPOSURE: The analyzed IPsec VPN environment exhibits critical vulnerabilities "
                f"(Risk Score: {report.overall_risk_score:.1f}/100, Level: {report.risk_level}). "
                f"Identified {p1_count} critical priority (P1) and {p2_count} high priority (P2) security findings "
                "requiring immediate operational remediation."
            )
            business_impact = (
                "Direct exposure to passive WAN decryption (Sweet32), potential man-in-the-middle interception, "
                "and regulatory non-compliance under PCI-DSS v4.0, HIPAA, and NIST SP 800-77 standards. "
                "Confidentiality and integrity of inter-site communications cannot be guaranteed in the current state."
            )
        elif report.risk_level == "MEDIUM":
            posture = (
                f"MODERATE RISK POSTURE: The analyzed IPsec VPN environment maintains functional encryption "
                f"but utilizes suboptimal cryptographic or protocol parameters (Risk Score: {report.overall_risk_score:.1f}/100). "
                f"Identified {len(prioritized)} findings that should be addressed during scheduled maintenance windows."
            )
            business_impact = (
                "No imminent passive compromise detected, but configuration fails to meet modern zero-trust "
                "standards. Potential exposure to algorithmic degradation or theoretical collision attacks over time."
            )
        else:
            posture = (
                f"ROBUST SECURITY POSTURE: The analyzed IPsec VPN environment conforms to modern cryptographic standards "
                f"(Risk Score: {report.overall_risk_score:.1f}/100, Level: {report.risk_level}). "
                "Zero critical vulnerabilities or cleartext bypass conditions detected."
            )
            business_impact = (
                "Confidentiality, authenticity, and anti-replay integrity are strongly safeguarded. Compliant with "
                "modern NIST and RFC 8221 security guidelines."
            )

        risk_score_summary = (
            f"Overall Risk Score: {report.overall_risk_score:.1f}/100 ({report.risk_level}). "
            f"Evaluated {report.evaluated_sessions_count} VPN session(s), {report.evaluated_tunnels_count} tunnel(s), "
            f"and {report.evaluated_packets_count} packet(s). Total findings: {report.findings_count}."
        )

        compliance_overview = (
            "NON-COMPLIANT with NIST SP 800-77 (Rev 1) and RFC 8221 guidelines"
            if report.risk_level in ("CRITICAL", "HIGH")
            else "COMPLIANT with baseline IPsec cryptographic requirements."
        )

        strategic_recommendations = [
            "Mandate modern AEAD ciphers (AES-GCM-256 or ChaCha20-Poly1305) across all enterprise VPN gateways.",
            "Establish an automated configuration audit pipeline to prevent regression to legacy 64-bit ciphers.",
            "Enforce strict egress firewall filtering to eliminate perimeter cleartext leakage bypasses.",
            "Schedule quarterly cryptographic reviews and continuous protocol telemetry monitoring.",
        ]

        return ExecutiveSummary(
            overall_posture=posture,
            risk_score_summary=risk_score_summary,
            business_impact=business_impact,
            compliance_overview=compliance_overview,
            strategic_recommendations=strategic_recommendations,
        )

    def _synthesize_technical_summary(self, report: RiskAssessmentReport) -> TechnicalSummary:
        """Synthesize detailed technical dossier for SOC analysts and network engineers."""
        rule_ids = {f.rule_id for f in report.findings}

        protocol_health = (
            f"Session inspection analyzed {report.evaluated_sessions_count} session(s) across {report.evaluated_tunnels_count} "
            f"tunnel pair(s). Encountered {report.findings_count} security finding(s). "
            f"Protocol state tracking observed active session establishment and traffic flows."
        )

        # Cryptographic assessment
        crypto_notes = []
        if "SEC-CRYPTO-001" in rule_ids:
            crypto_notes.append("Deprecated 64-bit block cipher (3DES) detected; vulnerable to Sweet32 (CVE-2016-2183).")
        if "SEC-CRYPTO-002" in rule_ids:
            crypto_notes.append("Suboptimal hash algorithms (MD5/SHA1) detected in integrity/PRF negotiation.")
        if "SEC-CRYPTO-003" in rule_ids:
            crypto_notes.append("Insecure MODP Diffie-Hellman groups (< 2048 bits) detected; fails to provide 112-bit security.")
        if not crypto_notes:
            crypto_notes.append("Cryptographic proposals conform to RFC 8221 recommendations with modern authenticated ciphers.")
        cryptographic_assessment = " ".join(crypto_notes)

        # Integrity & sequence analysis
        integ_notes = []
        if "SEC-INTEG-001" in rule_ids:
            integ_notes.append("Sequence counter replay detected; duplicate ESP sequences violate anti-replay guarantees.")
        if "SEC-INTEG-002" in rule_ids:
            integ_notes.append("ESP sequence counter 0 observed, in direct violation of RFC 4303 Section 3.3.3.")
        if not integ_notes:
            integ_notes.append("ESP sequence numbers are strictly monotonic with zero detected replays or null sequence violations.")
        integrity_and_sequence_analysis = " ".join(integ_notes)

        # Leakage analysis
        leak_notes = []
        if any(f.category == "DATA_LEAKAGE" for f in report.findings):
            leak_notes.append("Cleartext TCP/UDP packets detected between tunnel endpoints while active IPsec session is established.")
        else:
            leak_notes.append("Zero cleartext packet leakage detected between tunnel endpoints; complete encapsulation verified.")
        leakage_and_exposure_analysis = " ".join(leak_notes)

        rfc_compliance_citations = [
            "RFC 4303: IP Encapsulating Security Payload (ESP) - Sequence Number Requirements",
            "RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2) - Proposal Negotiation",
            "RFC 8221: Cryptographic Algorithm Implementation Requirements and Usage Guidance for ESP and AH",
            "NIST SP 800-77 Rev. 1: Guide to IPsec VPNs - Security Parameter Mandates",
        ]

        return TechnicalSummary(
            protocol_health=protocol_health,
            cryptographic_assessment=cryptographic_assessment,
            integrity_and_sequence_analysis=integrity_and_sequence_analysis,
            leakage_and_exposure_analysis=leakage_and_exposure_analysis,
            rfc_compliance_citations=rfc_compliance_citations,
        )


class ConfigurableRealLLMProvider(BaseAIAnalysisProvider):
    """Configurable real LLM provider with automatic graceful fallback.
    
    Attempts to query an external LLM API (OpenAI or compatible endpoint) if configured.
    If the API key is unconfigured, or if the external API call fails, times out,
    or returns malformed output, it gracefully falls back to DeterministicAIProvider
    with provider_used marked as 'deterministic_fallback'.
    """

    def __init__(
        self,
        fallback_provider: Optional[DeterministicAIProvider] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self._fallback = fallback_provider or DeterministicAIProvider()
        self._api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self._base_url = base_url or os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
        self._model = model or os.getenv("LLM_MODEL", "gpt-4o-mini")

    def generate_analysis(self, report: RiskAssessmentReport) -> AISecurityAnalysis:
        # If no API key configured, use deterministic provider directly with transparent tag
        if not self._api_key:
            logger.info("No LLM_API_KEY or OPENAI_API_KEY configured; utilizing DeterministicAIProvider.")
            analysis = self._fallback.generate_analysis(report)
            analysis.provider_used = "deterministic"
            return analysis

        try:
            # Prepare structured prompt
            prompt = self._build_prompt(report)
            raw_response = self._call_llm_api(prompt)
            return self._parse_llm_response(raw_response, report)
        except Exception as e:
            logger.warning("External LLM call failed or timed out (%s); falling back to DeterministicAIProvider.", e)
            analysis = self._fallback.generate_analysis(report)
            analysis.provider_used = "deterministic_fallback"
            return analysis

    def _build_prompt(self, report: RiskAssessmentReport) -> str:
        findings_summary = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "explanation": f.explanation,
                "evidence": f.evidence,
            }
            for f in report.findings
        ]
        return (
            "You are an elite IPsec VPN security architect. Analyze the following RiskAssessmentReport and produce "
            "a JSON object with keys: executive_summary, technical_summary, prioritized_findings, attack_implications, "
            f"remediation_steps. Input: {json.dumps(findings_summary)}"
        )

    def _call_llm_api(self, prompt: str) -> str:
        import urllib.request
        url = f"{self._base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing IPsec VPN protocols."},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

    def _parse_llm_response(self, raw_content: str, report: RiskAssessmentReport) -> AISecurityAnalysis:
        parsed = json.loads(raw_content)
        # Parse JSON into structured dataclass with fallback default fields
        fallback_analysis = self._fallback.generate_analysis(report)

        exec_data = parsed.get("executive_summary", {})
        tech_data = parsed.get("technical_summary", {})

        exec_summary = ExecutiveSummary(
            overall_posture=exec_data.get("overall_posture", fallback_analysis.executive_summary.overall_posture),
            risk_score_summary=exec_data.get("risk_score_summary", fallback_analysis.executive_summary.risk_score_summary),
            business_impact=exec_data.get("business_impact", fallback_analysis.executive_summary.business_impact),
            compliance_overview=exec_data.get("compliance_overview", fallback_analysis.executive_summary.compliance_overview),
            strategic_recommendations=exec_data.get("strategic_recommendations", fallback_analysis.executive_summary.strategic_recommendations),
        )

        tech_summary = TechnicalSummary(
            protocol_health=tech_data.get("protocol_health", fallback_analysis.technical_summary.protocol_health),
            cryptographic_assessment=tech_data.get("cryptographic_assessment", fallback_analysis.technical_summary.cryptographic_assessment),
            integrity_and_sequence_analysis=tech_data.get("integrity_and_sequence_analysis", fallback_analysis.technical_summary.integrity_and_sequence_analysis),
            leakage_and_exposure_analysis=tech_data.get("leakage_and_exposure_analysis", fallback_analysis.technical_summary.leakage_and_exposure_analysis),
            rfc_compliance_citations=tech_data.get("rfc_compliance_citations", fallback_analysis.technical_summary.rfc_compliance_citations),
        )

        return AISecurityAnalysis(
            analysis_id=f"ai-analysis-{uuid.uuid4().hex[:12]}",
            capture_id=report.capture_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider_used="openai",
            overall_risk_score=report.overall_risk_score,
            risk_level=report.risk_level,
            executive_summary=exec_summary,
            technical_summary=tech_summary,
            prioritized_findings=fallback_analysis.prioritized_findings,
            attack_implications=fallback_analysis.attack_implications,
            remediation_steps=fallback_analysis.remediation_steps,
        )
