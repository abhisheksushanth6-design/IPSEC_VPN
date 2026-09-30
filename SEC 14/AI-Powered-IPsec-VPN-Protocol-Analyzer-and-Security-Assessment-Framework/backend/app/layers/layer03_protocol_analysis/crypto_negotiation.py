"""Observed IKE cryptographic negotiation (provenance: OBSERVED).

What the wire actually shows, and therefore what this module reports:

* IKEv2 — the IKE_SA_INIT *request* carries every proposal the initiator offered and
  the IKE_SA_INIT *response* carries exactly the proposal the responder selected
  (RFC 7296 §2.7). The Child SA (ESP/AH) proposals, PFS decision and transport-mode
  notification travel inside the encrypted SK payload of IKE_AUTH / CREATE_CHILD_SA
  and are NOT observable; nothing here pretends otherwise.
* IKEv1 — Phase 1 (Main / Aggressive mode) SA payloads are cleartext, including the
  authentication method and SA lifetime attributes. Quick Mode (Phase 2) is encrypted.

Everything returned is derived from decoded packets and cites packet numbers. When the
negotiation is absent from the capture the result carries provenance UNAVAILABLE.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional

from app.layers.layer03_protocol_analysis.models import IKEProposal, PacketAnalysisResult

# --------------------------------------------------------------------------- #
# Algorithm knowledge base (NIST SP 800-57 Pt.1 security-strength equivalences,
# RFC 8221 / RFC 8247 implementation status)
# --------------------------------------------------------------------------- #

# ENCR: canonical name -> (security bits, aead, deprecated)
ENCRYPTION_STRENGTH: dict[str, tuple[int, bool, bool]] = {
    "NULL": (0, False, True),
    "DES": (56, False, True),
    "DES-IV64": (56, False, True),
    "3DES": (112, False, True),        # 112-bit nominal; Sweet32 makes it SHOULD NOT (RFC 8221)
    "IDEA": (128, False, True),
    "CAST": (128, False, True),
    "BLOWFISH": (128, False, True),
    "RC5": (128, False, True),
    "CAMELLIA-CBC": (128, False, False),
    "AES-CBC": (128, False, False),
    "AES-CTR": (128, False, False),
    "AES-CCM-8": (128, True, False),
    "AES-CCM-12": (128, True, False),
    "AES-CCM-16": (128, True, False),
    "AES-GCM-8": (128, True, False),
    "AES-GCM-12": (128, True, False),
    "AES-GCM-16": (128, True, False),
    "CHACHA20-POLY1305": (256, True, False),
}

# INTEG: name -> (security bits, deprecated)
INTEGRITY_STRENGTH: dict[str, tuple[int, bool]] = {
    "NONE": (0, False),
    "AUTH_HMAC_MD5_96": (64, True),
    "AUTH_HMAC_SHA1_96": (80, True),
    "AUTH_DES_MAC": (56, True),
    "AUTH_KPDK_MD5": (64, True),
    "AUTH_AES_XCBC_96": (96, False),
    "AUTH_HMAC_SHA2_256_128": (128, False),
    "AUTH_HMAC_SHA2_384_192": (192, False),
    "AUTH_HMAC_SHA2_512_256": (256, False),
    # IKEv1 hash attribute names
    "MD5": (64, True),
    "SHA1": (80, True),
    "TIGER": (96, True),
    "SHA2-256": (128, False),
    "SHA2-384": (192, False),
    "SHA2-512": (256, False),
}

PRF_STRENGTH: dict[str, tuple[int, bool]] = {
    "PRF_HMAC_MD5": (64, True),
    "PRF_HMAC_SHA1": (80, True),
    "PRF_HMAC_TIGER": (96, True),
    "PRF_AES128_XCBC": (128, False),
    "PRF_HMAC_SHA2_256": (128, False),
    "PRF_HMAC_SHA2_384": (192, False),
    "PRF_HMAC_SHA2_512": (256, False),
    "PRF_AES128_CMAC": (128, False),
}

# DH group number -> (display name, security bits, deprecated)
DH_STRENGTH: dict[int, tuple[str, int, bool]] = {
    1: ("MODP-768 (Group 1)", 66, True),
    2: ("MODP-1024 (Group 2)", 80, True),
    5: ("MODP-1536 (Group 5)", 90, True),
    14: ("MODP-2048 (Group 14)", 112, False),
    15: ("MODP-3072 (Group 15)", 128, False),
    16: ("MODP-4096 (Group 16)", 152, False),
    17: ("MODP-6144 (Group 17)", 176, False),
    18: ("MODP-8192 (Group 18)", 200, False),
    19: ("ECP-256 (Group 19)", 128, False),
    20: ("ECP-384 (Group 20)", 192, False),
    21: ("ECP-521 (Group 21)", 256, False),
    22: ("MODP-1024/160 (Group 22)", 80, True),
    23: ("MODP-2048/224 (Group 23)", 112, True),
    24: ("MODP-2048/256 (Group 24)", 112, True),
    31: ("Curve25519 (Group 31)", 128, False),
    32: ("Curve448 (Group 32)", 224, False),
}

_GROUP_RE = re.compile(r"Group[ _]?(\d+)")


def canonical_cipher(name: str) -> tuple[str, Optional[int]]:
    """Normalise a decoded ENCR name such as 'AES-CBC_256' or '3DES-CBC' to (family, key_length)."""
    raw = (name or "").upper().strip()
    key_len: Optional[int] = None
    m = re.search(r"_(\d{2,3})$", raw)
    if m:
        key_len = int(m.group(1))
        raw = raw[: m.start()]
    if raw in ("3DES-CBC", "TRIPLEDES", "ENCR_3DES"):
        raw = "3DES"
    elif raw in ("DES-CBC", "ENCR_DES"):
        raw = "DES"
    elif raw.endswith("-CBC") and raw.split("-")[0] in ("IDEA", "CAST", "BLOWFISH", "RC5"):
        raw = raw.split("-")[0]
    if raw.startswith("AES") and key_len is None and raw in ENCRYPTION_STRENGTH:
        key_len = None  # key length not signalled (IKEv1 default is 128 for AES-CBC)
    return raw, key_len


def cipher_security_bits(family: str, key_len: Optional[int]) -> int:
    base, _aead, _dep = ENCRYPTION_STRENGTH.get(family, (0, False, True))
    if family.startswith("AES") and key_len in (128, 192, 256):
        return key_len
    return base


def is_aead(family: str) -> bool:
    return ENCRYPTION_STRENGTH.get(family, (0, False, True))[1]


def dh_group_number(display: str) -> Optional[int]:
    m = _GROUP_RE.search(display or "")
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class ProposalSummary:
    packet_number: int
    role: str                      # INITIATOR | RESPONDER
    exchange: str
    proposal_number: int
    protocol: str
    cipher: Optional[str]
    key_length: Optional[int]
    integrity: Optional[str]
    prf: Optional[str]
    dh_group: Optional[str]
    dh_group_number: Optional[int]
    esn: Optional[str]
    auth_method: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    lifetime_kilobytes: Optional[int] = None
    security_bits: int = 0         # weakest component (NIST SP 800-57 equivalence)
    deprecated_components: list[str] = field(default_factory=list)
    label: str = ""


@dataclass
class DowngradeAssessment:
    detected: bool
    best_offered_label: Optional[str]
    best_offered_bits: int
    selected_label: Optional[str]
    selected_bits: int
    reason: str


@dataclass
class NegotiatedCrypto:
    provenance: str                 # OBSERVED | UNAVAILABLE
    ike_version: Optional[str]
    cipher: Optional[str]
    key_length: Optional[int]
    integrity: Optional[str]
    prf: Optional[str]
    dh_group: Optional[str]
    dh_group_number: Optional[int]
    esn: Optional[str]
    aead: Optional[bool]
    auth_method: Optional[str]
    lifetime_seconds: Optional[int]
    lifetime_kilobytes: Optional[int]
    security_bits: Optional[int]
    selection_basis: str            # RESPONDER_SA_PAYLOAD | SINGLE_OFFERED_PROPOSAL | INITIATOR_PREFERRED_UNCONFIRMED | NONE
    selection_confirmed: bool
    selected_proposal: Optional[ProposalSummary]
    offered_proposals: list[ProposalSummary]
    downgrade: Optional[DowngradeAssessment]
    weak_offered: list[str]
    ke_dh_groups: list[int]
    ke_cross_check: Optional[str]
    cleartext_identity_observed: bool
    notify_types: list[str]
    evidence: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #


def summarize_proposal(prop: IKEProposal, packet_number: int, role: str, exchange: str) -> ProposalSummary:
    cipher: Optional[str] = None
    key_len: Optional[int] = None
    if prop.encryption_algorithms:
        cipher, key_len = canonical_cipher(prop.encryption_algorithms[0])
    if key_len is None:
        for t in prop.transforms:
            if t.key_length:
                key_len = t.key_length
                break
    integrity = prop.integrity_algorithms[0] if prop.integrity_algorithms else None
    prf = prop.prf_algorithms[0] if prop.prf_algorithms else None
    dh = prop.dh_groups[0] if prop.dh_groups else None
    dh_num = dh_group_number(dh) if dh else None
    if cipher and is_aead(cipher) and integrity in (None, "NONE"):
        integrity = "AEAD (integrated ICV)"

    bits: list[int] = []
    deprecated: list[str] = []
    if cipher:
        bits.append(cipher_security_bits(cipher, key_len))
        if ENCRYPTION_STRENGTH.get(cipher, (0, False, True))[2]:
            deprecated.append(cipher)
    if integrity and integrity in INTEGRITY_STRENGTH:
        ib, idep = INTEGRITY_STRENGTH[integrity]
        bits.append(ib)
        if idep:
            deprecated.append(integrity)
    if prf and prf in PRF_STRENGTH:
        pb, pdep = PRF_STRENGTH[prf]
        bits.append(pb)
        if pdep:
            deprecated.append(prf)
    if dh_num is not None:
        _n, db, ddep = DH_STRENGTH.get(dh_num, (dh or "", 0, True))
        bits.append(db)
        if ddep:
            deprecated.append(dh or f"Group {dh_num}")

    label_parts = [
        f"{cipher}{'-' + str(key_len) if key_len else ''}" if cipher else "ENCR:?",
        integrity or "INTEG:?",
        prf or ("PRF:n/a" if prop.protocol_name != "IKE" else "PRF:?"),
        f"DH{dh_num}" if dh_num is not None else "DH:?",
    ]
    return ProposalSummary(
        packet_number=packet_number,
        role=role,
        exchange=exchange,
        proposal_number=prop.proposal_number,
        protocol=prop.protocol_name,
        cipher=cipher,
        key_length=key_len,
        integrity=integrity,
        prf=prf,
        dh_group=dh,
        dh_group_number=dh_num,
        esn=prop.esn,
        auth_method=prop.auth_method,
        lifetime_seconds=prop.lifetime_seconds,
        lifetime_kilobytes=prop.lifetime_kilobytes,
        security_bits=min(bits) if bits else 0,
        deprecated_components=deprecated,
        label=" / ".join(label_parts),
    )


def _role(ike) -> str:
    if ike.major_version == 2:
        return "RESPONDER" if "Response" in ike.flags else "INITIATOR"
    # IKEv1: the first message of an exchange comes from the initiator; the responder
    # SPI is zero only in that first message.
    return "INITIATOR" if ike.responder_spi == "0" * 16 else "RESPONDER"


def extract_negotiated_crypto(packets: Iterable[PacketAnalysisResult]) -> NegotiatedCrypto:
    """Derive the negotiated IKE SA suite from the cleartext IKE messages of one session."""
    ike_pkts = sorted(
        (p for p in packets if p.ipsec is not None and p.ipsec.type == "IKE" and p.ipsec.ike is not None and p.parse_status == "OK"),
        key=lambda p: (p.timestamp or "", p.number),
    )
    offered: list[ProposalSummary] = []
    selected: Optional[ProposalSummary] = None
    ke_groups: list[int] = []
    notify_types: list[str] = []
    cleartext_id = False
    evidence: list[str] = []
    versions: set[str] = set()

    for p in ike_pkts:
        ike = p.ipsec.ike  # type: ignore[union-attr]
        versions.add(ike.version)
        role = _role(ike)
        exchange = ike.exchange_name
        for pl in ike.payloads:
            if pl.notify_name and pl.notify_name not in notify_types:
                notify_types.append(pl.notify_name)
            if pl.ke_dh_group is not None:
                ke_groups.append(pl.ke_dh_group)
            if ike.major_version == 2 and pl.type_number in (35, 36):
                cleartext_id = True
            if ike.major_version == 1 and pl.type_number == 5 and ike.exchange_type == 4:
                cleartext_id = True  # Aggressive Mode identities are never encrypted
        # Only IKE-SA proposals (protocol IKE/1) are ever cleartext; ESP/AH proposals in a
        # cleartext IKEv1 Quick Mode capture would also be honoured here.
        for prop in ike.proposals:
            summary = summarize_proposal(prop, p.number, role, exchange)
            if role == "RESPONDER":
                if selected is None:
                    selected = summary
                    evidence.append(f"Packet {p.number}: {exchange} response selected {summary.label}.")
            else:
                offered.append(summary)
        if role == "INITIATOR" and ike.proposals:
            evidence.append(f"Packet {p.number}: {exchange} request offered {len(ike.proposals)} proposal(s).")

    if not offered and selected is None:
        return NegotiatedCrypto(
            provenance="UNAVAILABLE", ike_version=sorted(versions)[0] if versions else None,
            cipher=None, key_length=None, integrity=None, prf=None, dh_group=None, dh_group_number=None,
            esn=None, aead=None, auth_method=None, lifetime_seconds=None, lifetime_kilobytes=None,
            security_bits=None, selection_basis="NONE", selection_confirmed=False, selected_proposal=None,
            offered_proposals=[], downgrade=None, weak_offered=[], ke_dh_groups=ke_groups, ke_cross_check=None,
            cleartext_identity_observed=cleartext_id, notify_types=notify_types,
            evidence=evidence or ["No cleartext IKE SA proposal observed in this session (IKE negotiation absent or fully encrypted)."],
        )

    if selected is not None:
        basis, confirmed = "RESPONDER_SA_PAYLOAD", True
    elif len(offered) == 1:
        selected, basis, confirmed = offered[0], "SINGLE_OFFERED_PROPOSAL", False
        evidence.append("Responder selection not captured; the single offered proposal is the only possible outcome.")
    else:
        selected, basis, confirmed = offered[0], "INITIATOR_PREFERRED_UNCONFIRMED", False
        evidence.append(f"Responder selection not captured; reporting the initiator's first-preference proposal out of {len(offered)}.")

    # Downgrade: a stronger suite was on offer but a weaker one was chosen.
    downgrade: Optional[DowngradeAssessment] = None
    if offered and confirmed:
        best = max(offered, key=lambda s: s.security_bits)
        if best.security_bits > selected.security_bits or (
            selected.deprecated_components and not best.deprecated_components
        ):
            downgrade = DowngradeAssessment(
                detected=True,
                best_offered_label=best.label, best_offered_bits=best.security_bits,
                selected_label=selected.label, selected_bits=selected.security_bits,
                reason=(
                    f"The initiator offered {best.label} ({best.security_bits}-bit strength) but the responder "
                    f"selected {selected.label} ({selected.security_bits}-bit strength)."
                ),
            )
        else:
            downgrade = DowngradeAssessment(
                detected=False, best_offered_label=best.label, best_offered_bits=best.security_bits,
                selected_label=selected.label, selected_bits=selected.security_bits,
                reason="The selected proposal is the strongest suite on offer.",
            )

    weak_offered: list[str] = []
    for s in offered:
        for comp in s.deprecated_components:
            if comp not in weak_offered:
                weak_offered.append(comp)

    ke_check: Optional[str] = None
    if ke_groups and selected.dh_group_number is not None:
        if selected.dh_group_number in ke_groups:
            ke_check = f"KE payload DH group {selected.dh_group_number} matches the selected proposal."
        else:
            ke_check = (
                f"KE payload carries DH group(s) {sorted(set(ke_groups))} while the SA proposal names group "
                f"{selected.dh_group_number}; the responder may have answered INVALID_KE_PAYLOAD."
            )
        evidence.append(ke_check)

    return NegotiatedCrypto(
        provenance="OBSERVED",
        ike_version=sorted(versions)[0] if len(versions) == 1 else ("/".join(sorted(versions)) or None),
        cipher=selected.cipher,
        key_length=selected.key_length,
        integrity=selected.integrity,
        prf=selected.prf,
        dh_group=selected.dh_group,
        dh_group_number=selected.dh_group_number,
        esn=selected.esn,
        aead=is_aead(selected.cipher) if selected.cipher else None,
        auth_method=selected.auth_method,
        lifetime_seconds=selected.lifetime_seconds,
        lifetime_kilobytes=selected.lifetime_kilobytes,
        security_bits=selected.security_bits,
        selection_basis=basis,
        selection_confirmed=confirmed,
        selected_proposal=selected,
        offered_proposals=offered,
        downgrade=downgrade,
        weak_offered=weak_offered,
        ke_dh_groups=sorted(set(ke_groups)),
        ke_cross_check=ke_check,
        cleartext_identity_observed=cleartext_id,
        notify_types=notify_types,
        evidence=evidence,
    )
