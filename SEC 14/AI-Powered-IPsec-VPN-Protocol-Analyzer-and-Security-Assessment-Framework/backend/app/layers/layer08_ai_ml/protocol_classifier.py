"""Layer 07 — AI-Based Protocol & Traffic Classification.

Implements SIH Problem Statement 26160 requirements:
A. IPsec Protocol Identification (Determine whether traffic is IPsec-related)
B. IKE Identification (IKE version, exchanges, SPIs, characteristics)
C. VPN Mode Identification (Tunnel Mode vs Transport Mode)
D. Cryptographic Configuration Identification (AES-128, AES-256, AES-GCM, AES-CBC+HMAC, DH groups, PFS)
E. Security Association Characteristics (SPIs, lifetimes, states, rekeying)
F. Encrypted Traffic Classification (VoIP, WhatsApp, Web browsing, Email, ICMP, Video streaming, Other)
G. Calibrated AI Confidence Scores for every classification dimension

Every dimension carries a *provenance* tag so that a reader can tell apart:
    OBSERVED   — read directly from cleartext protocol fields (e.g. the IKE_SA_INIT proposal);
    INFERRED   — derived from side channels (ESP framing arithmetic, message sizes);
    PREDICTED  — produced by the supervised traffic classifier;
    ASSUMED    — a documented default that the capture cannot confirm;
    UNAVAILABLE— the evidence is absent or encrypted.
Nothing is filled in with a plausible-looking default: the old behaviour of reporting
"AES-256-GCM / DH14 / PFS on" for a capture that never showed an IKE exchange is gone.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.layers.layer03_protocol_analysis.crypto_negotiation import extract_negotiated_crypto
from app.layers.layer04_sa_lifecycle.replay_analysis import analyze_replay
from app.layers.layer08_ai_ml.crypto_inference import icv_length_for, infer_esp_crypto, infer_pfs, infer_transport_mode
from app.layers.layer08_ai_ml.traffic_classifier import (
    FlowFeatures,
    TrafficClassificationService,
    TrafficClassifier,
    TrafficPrediction,
)
from app.models.ipsec_session import IPsecSession
from app.models.security_association import SecurityAssociationRow
from app.services.packet_service import packet_service

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProtocolIdentificationResult:
    is_ipsec: bool
    protocol_type: str  # "ESP", "AH", "IKE", "ESP+IKE", "AH+IKE", "NON_IPSEC"
    confidence: float
    provenance: str = "OBSERVED"
    evidence: List[str] = field(default_factory=list)


@dataclass
class IKEIdentificationResult:
    detected: bool
    version: str  # "2.0", "1.0", "NONE"
    initiator_spi: Optional[str]
    responder_spi: Optional[str]
    exchanges: List[str] = field(default_factory=list)
    confidence: float = 0.0
    provenance: str = "OBSERVED"
    nat_traversal: bool = False
    notify_types: List[str] = field(default_factory=list)
    auth_method: Optional[str] = None
    evidence: List[str] = field(default_factory=list)


@dataclass
class VPNModeIdentificationResult:
    mode: str  # "TUNNEL" or "TRANSPORT"
    confidence: float
    evidence: str
    provenance: str = "ASSUMED"


@dataclass
class CryptoConfigurationResult:
    cipher: str
    key_size_bits: Optional[int]
    cipher_family: str  # "AES-GCM", "AES-CBC", "3DES", "CHACHA20", "UNKNOWN"
    integrity: str
    prf: Optional[str]
    dh_group: str
    pfs_enabled: Optional[bool]
    confidence: float
    observable_source: str  # IKE_SA_INIT_RESPONSE | IKE_SA_INIT_REQUEST | IKEV1_PHASE1 | ESP_FRAMING_INFERENCE | NONE
    provenance: str         # OBSERVED | INFERRED | UNAVAILABLE
    ike_sa: Dict[str, Any] = field(default_factory=dict)
    esp_inference: Dict[str, Any] = field(default_factory=dict)
    pfs: Dict[str, Any] = field(default_factory=dict)
    downgrade: Optional[Dict[str, Any]] = None
    weak_offered: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)


@dataclass
class SACharacteristicsResult:
    ike_sas_count: int
    child_sas_count: int
    observed_spis: List[str]
    rekey_count: int
    sa_state: str  # "ESTABLISHED", "ACTIVE", "REKEYED", "TERMINATED", "NEGOTIATING", "NONE"
    replay_protection_active: bool
    replay_verdict: str
    replay_window_size: int
    esn_enabled: Optional[bool]
    esn_observable: bool = False
    lifetime_seconds: Optional[int] = None
    lifetime_provenance: str = "UNAVAILABLE"
    provenance: str = "OBSERVED"
    replay: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)


@dataclass
class TrafficClassificationResult:
    predicted_type: str  # "VOIP", "WHATSAPP", "WEB_BROWSING", "EMAIL", "ICMP", "VIDEO_STREAMING", "OTHER"
    confidence: float
    probabilities: Dict[str, float]
    flow_features: Dict[str, Any]
    explanations: List[Dict[str, Any]]
    provenance: str = "PREDICTED"
    abstained: bool = False
    data_packets: int = 0
    model_version: Optional[str] = None


@dataclass
class AIComprehensiveAnalysis:
    session_id: str
    capture_id: str
    timestamp: str
    protocol_identification: ProtocolIdentificationResult
    ike_identification: IKEIdentificationResult
    vpn_mode_identification: VPNModeIdentificationResult
    crypto_configuration: CryptoConfigurationResult
    sa_characteristics: SACharacteristicsResult
    traffic_classification: TrafficClassificationResult
    overall_ai_confidence: float
    confidence_breakdown: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AIProtocolTrafficClassifier:
    """Core AI engine for comprehensive IPsec protocol and traffic classification."""

    @classmethod
    def _session_packets(cls, session: IPsecSession) -> List[Any]:
        if packet_service.capture_id != session.capture_id:
            return []
        return [
            p for sp in session.packets
            if (p := packet_service.by_number(sp.packet_number)) is not None
        ]

    @classmethod
    def analyze_session(
        cls,
        session: IPsecSession,
        db: Optional[Session] = None,
    ) -> AIComprehensiveAnalysis:
        """Perform end-to-end multi-criteria protocol and traffic classification on an IPsec session."""
        packets = cls._session_packets(session)
        detail: Dict[str, Any] = {}
        if getattr(session, "detail_json", None):
            try:
                detail = json.loads(session.detail_json)
            except (TypeError, ValueError):
                detail = {}

        sa_rows: List[SecurityAssociationRow] = []
        if db is not None:
            sa_rows = list(
                db.scalars(
                    select(SecurityAssociationRow).where(SecurityAssociationRow.session_id == session.id)
                ).all()
            )

        proto_ident = cls._identify_ipsec_protocol(session, packets)
        ike_ident = cls._identify_ike(session, packets, detail)
        mode_ident = cls._identify_vpn_mode(session, packets)
        crypto_ident = cls._identify_crypto_config(session, packets, detail)
        sa_chars = cls._extract_sa_characteristics(session, packets, sa_rows, detail, crypto_ident)

        flow_feats = TrafficClassifier.extract_flow_features(session)
        prediction = TrafficClassifier.classify(flow_feats)
        traf_result = TrafficClassificationResult(
            predicted_type=prediction.predicted_type,
            confidence=round(prediction.confidence, 4),
            probabilities=prediction.probabilities,
            flow_features=flow_feats.to_dict(),
            explanations=prediction.explanations,
            provenance="PREDICTED" if flow_feats.packet_count > 0 else "UNAVAILABLE",
            abstained=prediction.abstained,
            data_packets=flow_feats.packet_count,
            model_version=prediction.model_version,
        )

        # Calibrated overall confidence: weighted mean over the dimensions that actually
        # have evidence. Unavailable dimensions are excluded and listed, never scored as if
        # they were confidently known.
        components = {
            "protocol_identification": (0.20, proto_ident.confidence, proto_ident.provenance),
            "ike_identification": (0.15, ike_ident.confidence, ike_ident.provenance),
            "vpn_mode_identification": (0.15, mode_ident.confidence, mode_ident.provenance),
            "crypto_configuration": (0.20, crypto_ident.confidence, crypto_ident.provenance),
            "traffic_classification": (0.30, traf_result.confidence, traf_result.provenance),
        }
        scored = {k: v for k, v in components.items() if v[2] != "UNAVAILABLE"}
        weight_sum = sum(w for w, _c, _p in scored.values()) or 1.0
        overall_conf = round(sum(w * c for w, c, _p in scored.values()) / weight_sum, 4)
        breakdown = {
            k: {"weight": w, "confidence": c, "provenance": p, "scored": p != "UNAVAILABLE"}
            for k, (w, c, p) in components.items()
        }
        breakdown["unavailable_dimensions"] = [k for k, v in components.items() if v[2] == "UNAVAILABLE"]

        return AIComprehensiveAnalysis(
            session_id=session.id,
            capture_id=session.capture_id,
            timestamp=_utc_now(),
            protocol_identification=proto_ident,
            ike_identification=ike_ident,
            vpn_mode_identification=mode_ident,
            crypto_configuration=crypto_ident,
            sa_characteristics=sa_chars,
            traffic_classification=traf_result,
            overall_ai_confidence=overall_conf,
            confidence_breakdown=breakdown,
        )

    # ------------------------------------------------------------------ #
    # A. Protocol identification
    # ------------------------------------------------------------------ #

    @classmethod
    def _identify_ipsec_protocol(cls, session: IPsecSession, packets: List[Any]) -> ProtocolIdentificationResult:
        evidence: List[str] = []
        esp_cnt = int(getattr(session, "esp_packets", 0) or 0) or sum(1 for p in packets if p.protocol == "ESP")
        ah_cnt = int(getattr(session, "ah_packets", 0) or 0) or sum(1 for p in packets if p.protocol == "AH")
        ike_cnt = int(getattr(session, "ike_packets", 0) or 0) or sum(1 for p in packets if p.protocol == "IKE")
        nat_t = bool(getattr(session, "nat_traversal", False))

        if esp_cnt and ike_cnt:
            proto_type, conf = "ESP+IKE", 0.99
            evidence.append(f"Observed {ike_cnt} IKE control message(s) on UDP/500{'/4500' if nat_t else ''} and {esp_cnt} ESP data frame(s) between the same endpoints.")
        elif ah_cnt and ike_cnt:
            proto_type, conf = "AH+IKE", 0.98
            evidence.append(f"Observed {ike_cnt} IKE control message(s) and {ah_cnt} AH frame(s) between the same endpoints.")
        elif esp_cnt:
            proto_type, conf = "ESP", 0.97
            evidence.append(f"IP protocol 50 (ESP){' encapsulated in UDP/4500' if nat_t else ''} verified on {esp_cnt} frame(s) with a non-zero 32-bit SPI.")
        elif ah_cnt:
            proto_type, conf = "AH", 0.96
            evidence.append(f"IP protocol 51 (AH) verified on {ah_cnt} frame(s) with an ICV trailer.")
        elif ike_cnt:
            proto_type, conf = "IKE", 0.95
            evidence.append("ISAKMP/IKE header structure validated on UDP/500 or UDP/4500.")
        else:
            return ProtocolIdentificationResult(False, "NON_IPSEC", 0.90, "OBSERVED", ["No IPsec (ESP/AH/IKE) headers observed on this flow."])
        if nat_t:
            evidence.append("NAT-Traversal (RFC 3948) encapsulation observed.")
        return ProtocolIdentificationResult(True, proto_type, conf, "OBSERVED", evidence)

    # ------------------------------------------------------------------ #
    # B. IKE identification
    # ------------------------------------------------------------------ #

    @classmethod
    def _identify_ike(cls, session: IPsecSession, packets: List[Any], detail: Dict[str, Any]) -> IKEIdentificationResult:
        ike_packets = [p for p in packets if p.ipsec and p.ipsec.type == "IKE" and p.ipsec.ike]
        ike_info = detail.get("ike") or {}
        if not ike_packets and not session.ike_version:
            return IKEIdentificationResult(
                detected=False, version="NONE", initiator_spi=None, responder_spi=None, exchanges=[],
                confidence=0.0, provenance="UNAVAILABLE",
                evidence=["No IKE negotiation messages observed in session scope; the SA may have been established before the capture started."],
            )

        ver = session.ike_version or ike_info.get("version") or "?"
        init_spi = (ike_info.get("initiator_spis") or [None])[0]
        resp_spi = (ike_info.get("responder_spis") or [None])[0]
        exchanges: List[str] = list(ike_info.get("exchange_types") or [])
        evidence: List[str] = []
        for p in ike_packets:
            ike = p.ipsec.ike
            if ike.version:
                ver = ike.version
            if ike.initiator_spi and not init_spi:
                init_spi = ike.initiator_spi
            if ike.responder_spi and ike.responder_spi != "0" * 16 and not resp_spi:
                resp_spi = ike.responder_spi
            if ike.exchange_name and ike.exchange_name not in exchanges:
                exchanges.append(ike.exchange_name)

        evidence.append(f"ISAKMP header major/minor version field reads {ver} on {len(ike_packets) or ike_info.get('packet_count', 0)} message(s).")
        if exchanges:
            evidence.append(f"Observed exchanges: {', '.join(exchanges)}.")
        if init_spi:
            evidence.append(f"Initiator SPI {init_spi}.")
        if resp_spi:
            evidence.append(f"Responder SPI {resp_spi}.")
        if ike_info.get("auth_method"):
            evidence.append(f"IKEv1 Phase 1 authentication method attribute: {ike_info['auth_method']}.")
        return IKEIdentificationResult(
            detected=True, version=ver, initiator_spi=init_spi, responder_spi=resp_spi, exchanges=exchanges,
            confidence=0.98 if ike_packets else 0.88, provenance="OBSERVED",
            nat_traversal=bool(ike_info.get("nat_traversal") or session.nat_traversal),
            notify_types=list(ike_info.get("notify_types") or []),
            auth_method=ike_info.get("auth_method"),
            evidence=evidence,
        )

    # ------------------------------------------------------------------ #
    # C. VPN mode identification
    # ------------------------------------------------------------------ #

    @classmethod
    def _identify_vpn_mode(cls, session: IPsecSession, packets: List[Any]) -> VPNModeIdentificationResult:
        # 1. AH exposes the next-header field in cleartext: transport when it names a transport protocol.
        for p in packets:
            if p.ipsec and p.ipsec.ah:
                if p.ipsec.ah.next_header in (1, 6, 17, 58):
                    return VPNModeIdentificationResult("TRANSPORT", 0.97, f"AH next-header field = {p.ipsec.ah.next_header_name} (packet {p.number}): the authenticated payload is a transport segment, not an inner IP packet.", "OBSERVED")
                if p.ipsec.ah.next_header in (4, 41):
                    return VPNModeIdentificationResult("TUNNEL", 0.97, f"AH next-header field = {p.ipsec.ah.next_header_name} (packet {p.number}): an inner IP packet is encapsulated.", "OBSERVED")
        # 2. A cleartext USE_TRANSPORT_MODE notify (only visible when an implementation sends it outside SK).
        for p in packets:
            if p.ipsec and p.ipsec.ike:
                for pl in p.ipsec.ike.payloads:
                    if pl.notify_type == 16391:
                        return VPNModeIdentificationResult("TRANSPORT", 0.95, f"IKEv2 USE_TRANSPORT_MODE notification (type 16391) observed in cleartext (packet {p.number}).", "OBSERVED")
        # 3. ESP hides the inner header, but payload lengths still betray the mode: a payload shorter than any
        #    tunnel-mode packet, or bare TCP ACKs sitting at the transport-mode (or tunnel-mode) ACK size.
        esp_pkts = [p for p in packets if p.ipsec and p.ipsec.esp]
        if esp_pkts:
            framing = infer_esp_crypto(esp_pkts).framing_hypothesis
            nego = extract_negotiated_crypto(packets)
            icv = icv_length_for(nego.cipher, nego.integrity) if nego.provenance == "OBSERVED" else None
            mode_inf = infer_transport_mode(esp_pkts, framing, icv_length=icv)
            if mode_inf.mode == "TRANSPORT" and mode_inf.confidence >= 0.60:
                return VPNModeIdentificationResult("TRANSPORT", mode_inf.confidence, " ".join(mode_inf.evidence), "INFERRED")
        recorded = (getattr(session, "ipsec_mode", "TUNNEL") or "TUNNEL").upper()
        if recorded == "TRANSPORT":
            return VPNModeIdentificationResult("TRANSPORT", 0.70, "Transport-mode evidence recorded on the session (AH next-header, IKE notification or ESP payload-length floor).", "INFERRED")
        has_esp = bool(esp_pkts) or (getattr(session, "esp_packets", 0) or 0) > 0
        if has_esp:
            return VPNModeIdentificationResult(
                "TUNNEL", 0.55,
                "ESP encrypts the inner header, so tunnel vs. transport is not directly observable (RFC 4303 §3.1) and no ESP payload was short enough "
                "to prove transport mode. Tunnel mode is the default deployment assumption for gateway-to-gateway ESP; confirm with the operator "
                "configuration or an AH/IKEv1 Quick Mode capture.",
                "ASSUMED",
            )
        return VPNModeIdentificationResult("TUNNEL", 0.30, "No data-plane packets observed; mode cannot be determined.", "UNAVAILABLE")

    # ------------------------------------------------------------------ #
    # D. Cryptographic configuration
    # ------------------------------------------------------------------ #

    @classmethod
    def _identify_crypto_config(cls, session: IPsecSession, packets: List[Any], detail: Dict[str, Any]) -> CryptoConfigurationResult:
        ike_info = detail.get("ike") or {}
        esp_info = detail.get("esp") or {}

        # Prefer live packets (richer); fall back to the persisted negotiation summary.
        negotiated = extract_negotiated_crypto(packets) if packets else None
        if negotiated is not None and negotiated.provenance == "OBSERVED":
            ike_sa = negotiated.to_dict()
            cipher = negotiated.cipher or "UNKNOWN"
            key_len = negotiated.key_length
            integrity = negotiated.integrity or "UNKNOWN"
            prf = negotiated.prf
            dh = negotiated.dh_group or "UNKNOWN"
            basis = negotiated.selection_basis
            confirmed = negotiated.selection_confirmed
            downgrade = asdict(negotiated.downgrade) if negotiated.downgrade else None
            weak_offered = negotiated.weak_offered
            evidence = list(negotiated.evidence)
        elif ike_info.get("crypto_provenance") == "OBSERVED":
            ike_sa = {k: ike_info.get(k) for k in ("cipher", "key_length", "integrity", "prf", "dh_group", "dh_group_number", "esn", "auth_method", "lifetime_seconds", "security_bits", "selection_basis", "selection_confirmed", "selected_proposal", "offered_proposals")}
            cipher = ike_info.get("cipher") or "UNKNOWN"
            key_len = ike_info.get("key_length")
            integrity = ike_info.get("integrity") or "UNKNOWN"
            prf = ike_info.get("prf")
            dh = ike_info.get("dh_group") or "UNKNOWN"
            basis = ike_info.get("selection_basis", "NONE")
            confirmed = bool(ike_info.get("selection_confirmed"))
            downgrade = {"detected": ike_info.get("downgrade_detected"), "reason": ike_info.get("downgrade_reason")} if ike_info.get("downgrade_detected") is not None else None
            weak_offered = list(ike_info.get("weak_offered") or [])
            evidence = list(ike_info.get("negotiation_evidence") or [])
        else:
            ike_sa, cipher, key_len, integrity, prf, dh = {}, "NOT_OBSERVED", None, "NOT_OBSERVED", None, "NOT_OBSERVED"
            basis, confirmed, downgrade, weak_offered = "NONE", False, None, []
            evidence = ["No cleartext IKE SA proposal in this session: the negotiated cipher, integrity, PRF and DH group are not observable."]

        esp_inf = infer_esp_crypto(packets).to_dict() if packets else (esp_info.get("inferred") or {})
        pfs_inf = infer_pfs(packets).to_dict() if packets else {
            "status": {True: "ENABLED", False: "DISABLED"}.get(ike_info.get("pfs_enabled"), "UNKNOWN"),
            "provenance": ike_info.get("pfs_provenance", "UNAVAILABLE"),
            "confidence": ike_info.get("pfs_confidence", 0.0),
            "evidence": ike_info.get("pfs_evidence", []),
        }
        pfs_flag = {"ENABLED": True, "DISABLED": False}.get(pfs_inf.get("status"))

        if ike_sa:
            provenance = "OBSERVED"
            source = {
                "RESPONDER_SA_PAYLOAD": "IKE_SA_INIT_RESPONSE" if str(ike_info.get("version") or (negotiated.ike_version if negotiated else "")).startswith("2") else "IKEV1_PHASE1",
                "SINGLE_OFFERED_PROPOSAL": "IKE_SA_INIT_REQUEST",
                "INITIATOR_PREFERRED_UNCONFIRMED": "IKE_SA_INIT_REQUEST",
            }.get(basis, "IKE_SA_PAYLOAD")
            confidence = 0.98 if confirmed else (0.85 if basis == "SINGLE_OFFERED_PROPOSAL" else 0.60)
            family = cls._family(cipher)
        elif esp_inf.get("provenance") == "INFERRED":
            provenance = "INFERRED"
            source = "ESP_FRAMING_INFERENCE"
            confidence = float(esp_inf.get("confidence") or 0.0)
            family = cls._family_from_hypothesis(esp_inf.get("framing_hypothesis"))
            cipher = f"{esp_inf.get('cipher_family')} [inferred from ESP framing]"
            integrity = "; ".join(esp_inf.get("integrity_candidates") or []) or "NOT_OBSERVED"
            evidence = evidence + list(esp_inf.get("evidence") or [])
        else:
            provenance, source, confidence, family = "UNAVAILABLE", "NONE", 0.0, "UNKNOWN"

        details = {
            "aead": bool(ike_sa.get("aead")) if ike_sa else (family == "AES-GCM"),
            "key_length_observable": provenance == "OBSERVED",
            "esp_algorithms_note": (
                "IKEv2 Child SA (ESP) transforms are negotiated inside the encrypted SK payload; the IKE SA suite above is what the "
                "wire shows and the ESP cipher family is inferred from framing arithmetic." if ike_sa else
                "Without an IKE exchange in the capture only the ESP framing inference is available."
            ),
            "selection_basis": basis,
            "selection_confirmed": confirmed,
            "recommended_rfc8221": family in ("AES-GCM", "CHACHA20") and (key_len or 128) >= 128,
            "esp_null_suspected": bool(esp_inf.get("null_encryption_suspected")),
            "legacy_block_cipher_suspected": bool(esp_inf.get("legacy_block_cipher_suspected")),
        }
        return CryptoConfigurationResult(
            cipher=cipher, key_size_bits=key_len, cipher_family=family, integrity=integrity, prf=prf, dh_group=dh,
            pfs_enabled=pfs_flag, confidence=round(confidence, 3), observable_source=source, provenance=provenance,
            ike_sa=ike_sa, esp_inference=esp_inf, pfs=pfs_inf, downgrade=downgrade, weak_offered=weak_offered,
            details=details, evidence=evidence,
        )

    @staticmethod
    def _family(cipher: str) -> str:
        c = (cipher or "").upper()
        if "GCM" in c or "CCM" in c:
            return "AES-GCM"
        if "CHACHA" in c:
            return "CHACHA20"
        if "CBC" in c and "AES" in c:
            return "AES-CBC"
        if "CTR" in c:
            return "AES-CTR"
        if "3DES" in c:
            return "3DES"
        if c == "DES":
            return "DES"
        if c == "NULL":
            return "NULL"
        return "UNKNOWN" if not c or c in ("NOT_OBSERVED",) else c

    @staticmethod
    def _family_from_hypothesis(h: Optional[str]) -> str:
        return {"CBC-16": "AES-CBC", "CTR-OR-CBC-8": "AEAD/CTR or 64-bit CBC"}.get(h or "", "UNKNOWN")

    # ------------------------------------------------------------------ #
    # E. Security Association characteristics
    # ------------------------------------------------------------------ #

    @classmethod
    def _extract_sa_characteristics(
        cls, session: IPsecSession, packets: List[Any], sa_rows: List[SecurityAssociationRow],
        detail: Dict[str, Any], crypto: CryptoConfigurationResult,
    ) -> SACharacteristicsResult:
        ike_count = sum(1 for sa in sa_rows if (sa.type or "").upper() == "IKE")
        child_count = sum(1 for sa in sa_rows if (sa.type or "").upper() in ("CHILD", "ESP", "AH"))

        spis: List[str] = []
        def _add(v: Optional[str]) -> None:
            if v and v != "0" * 16 and v not in spis:
                spis.append(v)
        for sa in sa_rows:
            _add(sa.initiator_spi)
            _add(sa.responder_spi)
            _add(sa.spi)
        for key in ("esp", "ah"):
            for entry in (detail.get(key) or {}).get("spis", []) or []:
                _add(entry.get("spi"))
        for p in packets:
            if p.ipsec and p.ipsec.esp:
                _add(p.ipsec.esp.spi)
            if p.ipsec and p.ipsec.ah:
                _add(p.ipsec.ah.spi)

        rekeys = sum(int(getattr(sa, "rekey_count", 0) or 0) for sa in sa_rows)
        ike_states = [sa.state for sa in sa_rows if (sa.type or "").upper() == "IKE"]
        if rekeys > 0:
            state = "REKEYED"
        elif any(s in ("TERMINATED",) for s in ike_states):
            state = "TERMINATED"
        elif any(s in ("ESTABLISHED", "ACTIVE") for s in ike_states) or (getattr(session, "state", "") or "").upper() in ("ESTABLISHED", "ACTIVE"):
            state = "ESTABLISHED"
        elif ike_states:
            state = ike_states[0]
        else:
            state = "NONE" if not spis else "ACTIVE"

        replay = analyze_replay(packets).to_dict() if packets else ((detail.get("esp") or {}).get("replay") or (detail.get("ah") or {}).get("replay") or {})
        verdict = replay.get("verdict", "UNVERIFIED")
        ike_info = detail.get("ike") or {}
        lifetime = ike_info.get("lifetime_seconds")
        evidence = list(replay.get("details") or [])[:4]
        if lifetime:
            evidence.append(f"IKEv1 Phase 1 SA lifetime attribute observed: {lifetime} seconds.")
        else:
            evidence.append("SA lifetimes are negotiated inside encrypted payloads (IKEv2) and are not observable; the observed session duration is reported instead.")

        return SACharacteristicsResult(
            ike_sas_count=max(ike_count, 1 if getattr(session, "ike_version", None) else 0),
            child_sas_count=max(child_count, len([s for s in spis if s.startswith("0x")])),
            observed_spis=sorted(spis),
            rekey_count=rekeys,
            sa_state=state,
            replay_protection_active=verdict in ("PROTECTED", "DEGRADED"),
            replay_verdict=verdict,
            replay_window_size=64,
            esn_enabled=None,
            esn_observable=False,
            lifetime_seconds=lifetime,
            lifetime_provenance="OBSERVED" if lifetime else "UNAVAILABLE",
            provenance="OBSERVED" if (packets or sa_rows or spis) else "UNAVAILABLE",
            replay=replay,
            evidence=evidence,
        )
