"""Rule-based security assessment and risk scoring engine.

Evaluates observed IPsec traffic, cryptographic proposals, protocol anomalies,
data plane sequences, and session states against authoritative security rules
to produce structured findings and a comprehensive risk score.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.layers.layer03_protocol_analysis.models import (
    PacketAnalysisResult,
    ProtocolAnalysisReport,
)
from app.layers.layer04_sa_lifecycle.models import VPNSessionFingerprint
from app.layers.layer05_feature_engineering.assessment_models import (
    RiskAssessmentReport,
    RiskLevel,
    SecurityFinding,
    SeverityLevel,
)

WEAK_CIPHERS = {
    "DES": "CRITICAL",
    "3DES": "HIGH",
    "RC4": "CRITICAL",
    "BLOWFISH": "HIGH",
    "NULL": "CRITICAL",
}

WEAK_HASHES = {
    "MD5": "HIGH",
    "SHA1": "MEDIUM",
    "SHA-1": "MEDIUM",
}

WEAK_GROUPS = {
    "768": "HIGH",
    "GROUP 1": "HIGH",
    "1024": "HIGH",
    "GROUP 2": "HIGH",
    "1536": "MEDIUM",
    "GROUP 5": "MEDIUM",
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 18.0,
    "MEDIUM": 8.0,
    "LOW": 3.0,
    "INFO": 0.0,
}


def _calc_risk(findings: list[SecurityFinding]) -> tuple[float, RiskLevel, dict[str, int]]:
    """Compute normalized overall risk score and map to risk level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_score = 0.0

    for f in findings:
        sev = f.severity
        counts[sev] = counts.get(sev, 0) + 1
        total_score += SEVERITY_WEIGHTS.get(sev, 0.0)

    score = min(100.0, round(total_score, 1))

    if counts["CRITICAL"] > 0 or score >= 75.0:
        level: RiskLevel = "CRITICAL"
    elif counts["HIGH"] > 0 or score >= 50.0:
        level = "HIGH"
    elif counts["MEDIUM"] > 0 or score >= 25.0:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "MINIMAL"

    return score, level, counts


def run_security_assessment(
    packets: list[PacketAnalysisResult],
    sessions: list[VPNSessionFingerprint],
    protocol_report: Optional[ProtocolAnalysisReport] = None,
    capture_id: str = "default",
) -> RiskAssessmentReport:
    """Evaluate factual observations from Layers 2, 3, and 4 against security rules."""
    findings: list[SecurityFinding] = []

    # 1. Evaluate Cryptographic Suites across Sessions and Proposals
    evaluated_ciphers: set[str] = set()
    has_modern_crypto = False

    for sess in sessions:
        crypto = sess.crypto_summary
        enc_list = crypto.get("encryption", [])
        hash_list = crypto.get("integrity", []) + crypto.get("prf", [])
        dh_list = crypto.get("dh_groups", [])

        # Check Insecure Encryption Ciphers
        for enc in enc_list:
            evaluated_ciphers.add(enc)
            enc_upper = enc.upper()
            matched_weak = None
            sev: SeverityLevel = "HIGH"
            for w, s in WEAK_CIPHERS.items():
                if w in enc_upper:
                    matched_weak = w
                    sev = s  # type: ignore[assignment]
                    break

            if matched_weak:
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-CRYPTO-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-CRYPTO-001",
                        title=f"Insecure Encryption Algorithm Offered: {enc}",
                        category="CRYPTOGRAPHY",
                        severity=sev,
                        confidence=1.0,
                        explanation=(
                            f"The cipher '{enc}' is deprecated. Legacy 64-bit block ciphers (such as 3DES) "
                            "are susceptible to Sweet32 collisions (CVE-2016-2183), while DES and NULL "
                            "provide negligible or no confidentiality."
                        ),
                        evidence={"algorithm": enc, "session_id": sess.session_id, "endpoints": sess.endpoint_pair},
                        affected_session=sess.session_id,
                        affected_tunnel=f"{sess.initiator_ip} <-> {sess.responder_ip}",
                        remediation=(
                            "Reconfigure IPsec proposals to mandate modern authenticated ciphers like "
                            "AES-256-GCM, AES-128-GCM, or ChaCha20-Poly1305. Deprecate 3DES and DES."
                        ),
                        cve_references=["CVE-2016-2183", "RFC 8221 §5"],
                        compliance_mappings=["NIST SP 800-52 Rev 2", "PCI-DSS v4.0 Req 4.1"],
                    )
                )
            elif "GCM" in enc_upper or "CHACHA" in enc_upper or "256" in enc_upper:
                has_modern_crypto = True

        # Check Weak Integrity / PRF Hashes
        for hsh in hash_list:
            hsh_upper = hsh.upper()
            matched_hash = None
            sev_hash: SeverityLevel = "MEDIUM"
            for w, s in WEAK_HASHES.items():
                if w in hsh_upper:
                    matched_hash = w
                    sev_hash = s  # type: ignore[assignment]
                    break

            if matched_hash:
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-HASH-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-CRYPTO-002",
                        title=f"Weak Integrity or PRF Hash Algorithm: {hsh}",
                        category="INTEGRITY",
                        severity=sev_hash,
                        confidence=0.95,
                        explanation=(
                            f"The hash algorithm '{hsh}' has known collision and theoretical length-extension "
                            "vulnerabilities. RFC 8221 discourages MD5 and SHA-1 in IPsec."
                        ),
                        evidence={"hash": hsh, "session_id": sess.session_id, "endpoints": sess.endpoint_pair},
                        affected_session=sess.session_id,
                        affected_tunnel=f"{sess.initiator_ip} <-> {sess.responder_ip}",
                        remediation="Upgrade integrity and PRF to HMAC-SHA2-256 or HMAC-SHA2-512.",
                        cve_references=["RFC 8221 §4", "RFC 7296"],
                        compliance_mappings=["NIST SP 800-131A"],
                    )
                )

        # Check Weak Diffie-Hellman Groups
        for dh in dh_list:
            dh_upper = dh.upper()
            matched_dh = None
            sev_dh: SeverityLevel = "HIGH"
            for w, s in WEAK_GROUPS.items():
                if re.search(rf"\b{re.escape(w)}\b", dh_upper):
                    matched_dh = w
                    sev_dh = s  # type: ignore[assignment]
                    break

            if matched_dh:
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-DH-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-CRYPTO-003",
                        title=f"Insecure Diffie-Hellman Group: {dh}",
                        category="CRYPTOGRAPHY",
                        severity=sev_dh,
                        confidence=1.0,
                        explanation=(
                            f"Diffie-Hellman group '{dh}' provides less than 112 bits of security. MODP groups "
                            "under 2048 bits are vulnerable to precomputation and discrete logarithm attacks (Logjam)."
                        ),
                        evidence={"dh_group": dh, "session_id": sess.session_id, "endpoints": sess.endpoint_pair},
                        affected_session=sess.session_id,
                        affected_tunnel=f"{sess.initiator_ip} <-> {sess.responder_ip}",
                        remediation="Enforce Diffie-Hellman Group 14 (MODP 2048-bit), Group 19 (ECP 256-bit), or Curve25519.",
                        cve_references=["CVE-2015-4000", "RFC 8247"],
                        compliance_mappings=["NIST SP 800-57"],
                    )
                )

    # Compliant modern crypto finding if no critical/high crypto flaws and modern crypto observed
    if has_modern_crypto and not any(f.category == "CRYPTOGRAPHY" and f.severity in ("CRITICAL", "HIGH") for f in findings):
        findings.append(
            SecurityFinding(
                finding_id=f"FINDING-CRYPTO-{uuid.uuid4().hex[:8].upper()}",
                rule_id="SEC-CRYPTO-004",
                title="Compliant Modern Cryptography Suite Deployed",
                category="CRYPTOGRAPHY",
                severity="INFO",
                confidence=1.0,
                explanation="Observed IPsec connection negotiates approved AEAD ciphers with strong key exchange.",
                evidence={"ciphers": list(evaluated_ciphers)},
                remediation="Maintain existing cryptographic policies.",
                compliance_mappings=["NIST SP 800-52", "CNSA Suite"],
            )
        )

    # 2. Evaluate Protocol Anomalies & Sequence Integrity (from Layer 3 Telemetry)
    if protocol_report:
        for anomaly in protocol_report.anomalies:
            atype = anomaly.anomaly_type

            if atype == "SEQ_REPLAY":
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-REPLAY-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-INTEG-001",
                        title=f"Sequence Replay Attack Detected on SPI {anomaly.spi}",
                        category="INTEGRITY",
                        severity="HIGH",
                        confidence=0.95,
                        explanation=(
                            f"Duplicate sequence numbers were encountered on SPI {anomaly.spi} without an intervening "
                            "rekey exchange. This indicates replay packet injection or an anti-replay window failure."
                        ),
                        evidence=anomaly.evidence,
                        affected_tunnel=f"{anomaly.source_ip} <-> {anomaly.destination_ip}",
                        affected_packet_numbers=[anomaly.packet_number] if anomaly.packet_number else [],
                        remediation="Verify peer anti-replay window configuration and check for duplicate upstream routing paths.",
                        cve_references=["RFC 4303 §3.4.3"],
                    )
                )
            elif atype == "SEQ_ZERO":
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-SEQZERO-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-INTEG-002",
                        title=f"Illegal Sequence Number Zero on SPI {anomaly.spi}",
                        category="PROTOCOL_ANOMALY",
                        severity="HIGH",
                        confidence=1.0,
                        explanation=(
                            f"ESP/AH packet with sequence number 0 was received on SPI {anomaly.spi}. RFC 4303 §3.3.3 "
                            "mandates that sequence numbers start at 1. Sequence 0 is strictly forbidden."
                        ),
                        evidence=anomaly.evidence,
                        affected_tunnel=f"{anomaly.source_ip} <-> {anomaly.destination_ip}",
                        affected_packet_numbers=[anomaly.packet_number] if anomaly.packet_number else [],
                        remediation="Inspect IPsec kernel implementation and packet offload engines for RFC 4303 compliance.",
                        cve_references=["RFC 4303 §3.3.3"],
                    )
                )
            elif atype == "SEQ_GAP_LARGE":
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-GAP-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-INTEG-003",
                        title=f"Substantial Sequence Number Gap on SPI {anomaly.spi}",
                        category="INTEGRITY",
                        severity="MEDIUM",
                        confidence=0.85,
                        explanation=(
                            f"A sequence number gap exceeding 1000 packets occurred on SPI {anomaly.spi}. "
                            "This indicates high packet loss, packet injection, or out-of-order delivery."
                        ),
                        evidence=anomaly.evidence,
                        affected_tunnel=f"{anomaly.source_ip} <-> {anomaly.destination_ip}",
                        affected_packet_numbers=[anomaly.packet_number] if anomaly.packet_number else [],
                        remediation="Inspect path MTU, link stability, and verify whether a silent rekey occurred.",
                    )
                )
            elif atype == "CLEARTEXT_LEAK":
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-LEAK-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-LEAK-001",
                        title=f"Cleartext Data Leakage Between Tunnel Endpoints",
                        category="DATA_LEAKAGE",
                        severity="CRITICAL",
                        confidence=1.0,
                        explanation=(
                            f"Unencrypted non-IPsec traffic ({anomaly.evidence.get('protocol', 'IP')}) was observed "
                            f"transiting directly between endpoints {anomaly.source_ip} and {anomaly.destination_ip} "
                            "while an active IPsec VPN tunnel is established. This indicates split-tunnel leakage or SPD failure."
                        ),
                        evidence=anomaly.evidence,
                        affected_tunnel=f"{anomaly.source_ip} <-> {anomaly.destination_ip}",
                        affected_packet_numbers=[anomaly.packet_number] if anomaly.packet_number else [],
                        remediation=(
                            "Audit Security Policy Database (SPD) rules and firewall forwarding policies. "
                            "Enforce a default DROP policy for unencapsulated traffic destined for tunnel endpoints."
                        ),
                        compliance_mappings=["CIS Benchmark 5.2", "NIST SP 800-77"],
                    )
                )
            elif atype == "NO_PROPOSAL_CHOSEN":
                findings.append(
                    SecurityFinding(
                        finding_id=f"FINDING-STATE-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="SEC-STATE-002",
                        title="IKE Peer Proposal Rejection (NO_PROPOSAL_CHOSEN)",
                        category="TUNNEL_STATE",
                        severity="MEDIUM",
                        confidence=0.95,
                        explanation="The IKE responder rejected all proposals offered by the initiator due to suite mismatch.",
                        evidence=anomaly.evidence,
                        affected_tunnel=f"{anomaly.source_ip} <-> {anomaly.destination_ip}",
                        affected_packet_numbers=[anomaly.packet_number] if anomaly.packet_number else [],
                        remediation="Synchronize encryption, integrity, and DH group proposals between initiator and responder.",
                    )
                )

    # 3. Evaluate Session States
    for sess in sessions:
        if sess.state == "NEGOTIATING" and sess.total_packets > 1:
            findings.append(
                SecurityFinding(
                    finding_id=f"FINDING-STATE-{uuid.uuid4().hex[:8].upper()}",
                    rule_id="SEC-STATE-001",
                    title="Stalled IKE Negotiation Without Tunnel Establishment",
                    category="TUNNEL_STATE",
                    severity="MEDIUM",
                    confidence=0.90,
                    explanation=(
                        f"Session {sess.session_id} initiated IKE negotiation but failed to reach ESTABLISHED or ACTIVE state. "
                        "Authentication credentials, PSK, or certificate validation may be misconfigured."
                    ),
                    evidence={"session_id": sess.session_id, "state": sess.state, "packets": sess.total_packets},
                    affected_session=sess.session_id,
                    affected_tunnel=f"{sess.initiator_ip} <-> {sess.responder_ip}",
                    remediation="Verify authentication credentials (pre-shared key or X.509 certificate) on both VPN peers.",
                )
            )

    # 4. Compute Overall Risk Score and Risk Level
    overall_score, risk_level, severity_counts = _calc_risk(findings)

    return RiskAssessmentReport(
        capture_id=capture_id,
        overall_risk_score=overall_score,
        risk_level=risk_level,
        findings_count=len(findings),
        findings_by_severity=severity_counts,
        findings=findings,
        evaluated_sessions_count=len(sessions),
        evaluated_tunnels_count=len(protocol_report.tunnel_endpoints) if protocol_report else len(sessions),
        evaluated_packets_count=len(packets),
        assessment_timestamp=datetime.now(timezone.utc).isoformat(),
        status="READY",
    )
