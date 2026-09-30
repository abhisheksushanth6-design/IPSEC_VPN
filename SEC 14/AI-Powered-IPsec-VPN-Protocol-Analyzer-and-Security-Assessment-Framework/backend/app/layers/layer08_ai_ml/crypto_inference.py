"""Side-channel inference of cryptographic properties (provenance: INFERRED).

The ESP header exposes nothing about the cipher, but the *framing arithmetic* of
RFC 4303 does leak the cipher family:

    ESP payload = IV | ciphertext(payload + padding + pad-length + next-header) | ICV

* CBC modes pad the plaintext to the block size, so ``(len - IV - ICV) mod block == 0``
  for every packet (block 16 for AES, 8 for 3DES/DES/Blowfish/CAST, IV == block).
* AEAD / counter modes (AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CTR) use an 8-byte IV,
  need no block padding and only keep the mandatory 4-byte alignment.

Every ESP payload is a multiple of 4, so the residue of the length modulo 16 is the only
usable signal.  AES-CBC (16-byte IV, 16-byte blocks) can never produce a payload length
that is ≡ 4 (mod 16); AEAD/CTR ciphers and 64-bit-block CBC ciphers (3DES) both can, and
their residue sets are identical — so framing separates *AES-CBC* from *everything else*
but can never tell AES-GCM from 3DES.  Two decisive outcomes exist:

* ``CBC-16`` — every one of k distinct lengths avoids residue 4; a non-CBC-16 cipher does
  that by chance with probability 0.75**k, which is reported as the residual doubt.
  Quantised frame sizes (TFC padding, fixed-size codecs) are excluded from this claim.
* ``CTR-OR-CBC-8`` — at least one length is ≡ 4 (mod 16): AES-CBC is excluded outright.

The key size is never observable.  Every result cites the packets it used.

A second signal is byte entropy: correctly encrypted payloads are indistinguishable
from random data (≈ 7.9+ bits/byte), whereas ESP-NULL (RFC 2410) or a broken keystream
shows structure (RFC 5879 heuristics).

PFS on Child SA rekeys is inferred from the *length* of CREATE_CHILD_SA messages: a KE
payload adds 264 bytes for MODP-2048 (and more for larger MODP groups), which is far
outside the size variance of a rekey without a Diffie-Hellman exchange.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult

ICV_CANDIDATES: dict[int, list[str]] = {
    8: ["AES-GCM-8 / AES-CCM-8 (64-bit ICV)"],
    12: ["AUTH_HMAC_SHA1_96", "AUTH_HMAC_MD5_96", "AUTH_AES_XCBC_96", "AES-GCM-12 / AES-CCM-12"],
    16: ["AUTH_HMAC_SHA2_256_128", "AES-GCM-16 / AES-CCM-16 / ChaCha20-Poly1305 (128-bit ICV)"],
    24: ["AUTH_HMAC_SHA2_384_192"],
    32: ["AUTH_HMAC_SHA2_512_256"],
}

# (name, iv_length, alignment, icv candidates, family description, deprecated)
FRAMING_HYPOTHESES = [
    ("CBC-16", 16, 16, [12, 16, 24, 32], "AES-CBC (128-bit block cipher, CBC mode)", False),
    ("CBC-8", 8, 8, [12, 16], "3DES / DES / Blowfish / CAST (64-bit block cipher, CBC mode)", True),
    ("AEAD-CTR", 8, 4, [8, 12, 16], "AEAD or counter mode (AES-GCM / AES-CCM / ChaCha20-Poly1305 / AES-CTR)", False),
]
# The two outcomes the arithmetic can actually distinguish (see module docstring).
HYPOTHESIS_CBC16 = "CBC-16"
HYPOTHESIS_NOT_CBC16 = "CTR-OR-CBC-8"
FAMILY_NOT_CBC16 = "AEAD / counter mode (AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CTR) or a 64-bit-block CBC cipher (3DES / DES) — identical framing"

CBC16_MAX_CHANCE = 0.05     # a CBC-16 claim needs ≥ 11 distinct lengths (0.75**11 ≈ 4.2 %)
QUANTISED_GCD = 32          # all sizes multiples of ≥ 32 bytes → padding quanta, not application sizes
QUANTISED_TOP_SHARE = 0.90  # one size ≥ 90 % of frames → fixed-size padding or codec
QUANTISED_TOP2_SHARE = 0.97 # two sizes ≥ 97 % of frames → padded to a target size plus the MTU

MIN_ENTROPY_SAMPLE = 512
ENCRYPTED_ENTROPY_FLOOR = 7.2   # bits per byte; random data is ~7.9+, structured plaintext is well below

# ICV length (bytes) implied by a negotiated integrity / AEAD transform name.
_ICV_BY_TOKEN = [
    ("SHA2_512_256", 32), ("SHA2-512-256", 32), ("SHA512", 32), ("SHA2_384_192", 24), ("SHA2-384-192", 24), ("SHA384", 24),
    ("SHA2_256_128", 16), ("SHA2-256-128", 16), ("SHA256", 16), ("SHA2_256", 16), ("SHA2-256", 16),
    ("GCM_16", 16), ("GCM-16", 16), ("CCM_16", 16), ("CHACHA", 16), ("POLY1305", 16), ("GMAC", 16),
    ("GCM_12", 12), ("GCM-12", 12), ("CCM_12", 12), ("SHA1_96", 12), ("SHA1-96", 12), ("SHA1", 12), ("MD5_96", 12), ("MD5-96", 12), ("MD5", 12), ("XCBC_96", 12), ("XCBC", 12),
    ("GCM_8", 8), ("GCM-8", 8), ("CCM_8", 8),
]


def icv_length_for(cipher: Optional[str], integrity: Optional[str]) -> Optional[int]:
    """ICV length implied by the negotiated transforms (AEAD ciphers carry their own tag length)."""
    for name in (integrity, cipher):
        token = (name or "").upper().replace(" ", "")
        if not token or token in ("AEAD", "NONE", "NULL"):
            continue
        for needle, icv in _ICV_BY_TOKEN:
            if needle in token:
                return icv
    if cipher and "GCM" in cipher.upper():
        return 16  # RFC 4106 default tag length when the transform does not spell it out
    return None


@dataclass
class ESPCryptoInference:
    provenance: str                       # INFERRED | UNAVAILABLE
    cipher_family: Optional[str]
    framing_hypothesis: Optional[str]     # CBC-16 | CBC-8 | AEAD-CTR
    block_size: Optional[int]
    iv_length: Optional[int]
    icv_length_candidates: list[int]
    integrity_candidates: list[str]
    key_length_observable: bool
    confidence: float
    packets_examined: int
    distinct_lengths: int
    hypothesis_consistency: dict[str, float]
    payload_entropy_bits: Optional[float]
    entropy_sample_bytes: int
    null_encryption_suspected: bool
    legacy_block_cipher_suspected: bool
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PFSInference:
    status: str                    # ENABLED | DISABLED | UNKNOWN
    provenance: str                # INFERRED | UNAVAILABLE
    confidence: float
    rekey_exchanges_observed: int
    message_lengths: list[int]
    evidence: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _esp_lengths(packets: Iterable[PacketAnalysisResult]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for p in packets:
        if p.ipsec is not None and p.ipsec.esp is not None and p.parse_status == "OK":
            out.append((p.number, p.ipsec.esp.payload_length))
    return out


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _esp_payload_bytes(p: PacketAnalysisResult) -> bytes:
    """Return the ESP payload bytes of a fully captured frame, or b'' if not recoverable."""
    if p.raw is None or p.raw.truncated or p.captured_length != p.original_length or p.ipsec is None or p.ipsec.esp is None:
        return b""
    frame = bytes.fromhex(p.raw.hex)
    if len(frame) != p.raw.length:
        return b""
    n = p.ipsec.esp.payload_length
    return frame[-n:] if 0 < n <= len(frame) else b""


def infer_esp_crypto(packets: Iterable[PacketAnalysisResult]) -> ESPCryptoInference:
    pkts = [p for p in packets if p.ipsec is not None and p.ipsec.esp is not None and p.parse_status == "OK"]
    lengths = _esp_lengths(pkts)
    if not lengths:
        return ESPCryptoInference(
            provenance="UNAVAILABLE", cipher_family=None, framing_hypothesis=None, block_size=None, iv_length=None,
            icv_length_candidates=[], integrity_candidates=[], key_length_observable=False, confidence=0.0,
            packets_examined=0, distinct_lengths=0, hypothesis_consistency={}, payload_entropy_bits=None,
            entropy_sample_bytes=0, null_encryption_suspected=False, legacy_block_cipher_suspected=False,
            evidence=["No ESP packets available for framing analysis."],
        )

    values = [l for _, l in lengths]
    distinct = len(set(values))
    n = len(values)
    consistency: dict[str, float] = {}
    survivors: dict[str, list[int]] = {}
    for name, iv, align, icvs, _fam, _dep in FRAMING_HYPOTHESES:
        best = 0.0
        ok_icvs: list[int] = []
        for icv in icvs:
            ok = sum(1 for l in values if l >= iv + icv + align and (l - iv - icv) % align == 0)
            frac = ok / n
            best = max(best, frac)
            if frac >= 0.98:
                ok_icvs.append(icv)
        consistency[name] = round(best, 4)
        if ok_icvs:
            survivors[name] = ok_icvs

    evidence = [f"{n} ESP packets examined with {distinct} distinct payload length(s) (packets {lengths[0][0]}–{lengths[-1][0]})."]
    family = hypothesis = None
    block = iv_len = None
    icv_cands: list[int] = []
    conf = 0.0
    legacy = False  # a 64-bit block cipher shares its framing with AEAD/CTR: never inferable from lengths alone

    # A non-AES-CBC cipher lands on residue 4 (mod 16) with probability 1/4 per independent
    # application length, so k distinct lengths that all avoid it coincide with probability 0.75**k.
    cbc16_chance = 0.75 ** distinct
    size_gcd = 0
    for v in set(values):
        size_gcd = math.gcd(size_gcd, v)
    common = Counter(values).most_common(2)
    top_share = common[0][1] / n
    top2_share = sum(c for _, c in common) / n
    quantised = size_gcd >= QUANTISED_GCD or top_share >= QUANTISED_TOP_SHARE or top2_share >= QUANTISED_TOP2_SHARE
    others = [h for h in ("AEAD-CTR", "CBC-8") if h in survivors]

    if "CBC-16" in survivors and cbc16_chance < CBC16_MAX_CHANCE and not quantised:
        hypothesis, block, iv_len = HYPOTHESIS_CBC16, 16, 16
        family = FRAMING_HYPOTHESES[0][4]
        icv_cands = survivors["CBC-16"]
        conf = min(0.92, 1.0 - cbc16_chance)
        evidence.append(
            f"All {distinct} distinct payload lengths avoid the residue 4 (mod 16) that only a non-AES-CBC cipher produces "
            f"(a coincidence with probability ≈ {cbc16_chance:.1%}): consistent with a 16-byte IV plus 16-byte block padding, i.e. AES-CBC."
        )
    elif "CBC-16" in survivors:
        names = [FRAMING_HYPOTHESES[0][4]] + [FRAMING_HYPOTHESES[i][4] for i, h in ((2, "AEAD-CTR"), (1, "CBC-8")) if h in survivors]
        family = "Indeterminate — framing consistent with: " + " | ".join(names)
        icv_cands = sorted({icv for v in survivors.values() for icv in v})
        conf = round(min(0.45, max(0.0, 1.0 - cbc16_chance) * 0.5), 3)
        if quantised:
            evidence.append(
                f"Frame sizes are quantised (the two dominant sizes cover {top2_share:.0%} of frames, common divisor {size_gcd} bytes): "
                "TFC padding or a fixed-size codec, so block alignment carries no information about the cipher."
            )
        else:
            evidence.append(
                f"Only {distinct} distinct length(s) observed (TFC padding, a fixed-size codec or a short flow); a non-AES-CBC cipher "
                f"would avoid residue 4 (mod 16) by chance with probability ≈ {cbc16_chance:.0%}, too high to claim AES-CBC."
            )
    elif others:
        hypothesis, block, iv_len = HYPOTHESIS_NOT_CBC16, None, 8
        family = FAMILY_NOT_CBC16
        icv_cands = sorted({icv for h in others for icv in survivors[h]})
        conf = 0.80 if distinct >= 3 else 0.70
        offending = sorted({v for v in set(values) if v % 16 == 4})[:4]
        evidence.append(
            f"Payload length(s) {', '.join(str(v) for v in offending)} are ≡ 4 (mod 16): a 16-byte IV with 16-byte block padding "
            "(AES-CBC) cannot produce them, so the cipher uses 8-byte IV framing — an AEAD/counter mode or a 64-bit-block CBC "
            "cipher (3DES), which are indistinguishable by length arithmetic."
        )
    else:
        evidence.append("Payload lengths do not fit any RFC 4303 framing hypothesis (truncated capture, NAT-T trailer, or non-standard framing).")

    # Entropy check on recoverable payload bytes (bounded sample).
    sample = bytearray()
    for p in pkts:
        if len(sample) >= 65536:
            break
        sample.extend(_esp_payload_bytes(p))
    entropy: Optional[float] = None
    null_suspected = False
    if len(sample) >= MIN_ENTROPY_SAMPLE:
        entropy = round(max(0.0, _shannon_entropy(bytes(sample))), 3)
        if entropy < ENCRYPTED_ENTROPY_FLOOR:
            null_suspected = True
            evidence.append(
                f"Payload byte entropy {entropy:.2f} bits/byte over {len(sample)} bytes is far below the ≈7.9 expected for ciphertext: "
                "ESP-NULL or a defective cipher is suspected (RFC 5879 heuristic)."
            )
        else:
            evidence.append(f"Payload byte entropy {entropy:.2f} bits/byte over {len(sample)} bytes is consistent with ciphertext.")

    integrity_candidates: list[str] = []
    for icv in icv_cands:
        for name in ICV_CANDIDATES.get(icv, []):
            if hypothesis == HYPOTHESIS_CBC16 and ("GCM" in name or "CCM" in name or "ChaCha" in name):
                continue
            integrity_candidates.append(name)

    return ESPCryptoInference(
        provenance="INFERRED" if family else "UNAVAILABLE",
        cipher_family=family, framing_hypothesis=hypothesis, block_size=block, iv_length=iv_len,
        icv_length_candidates=icv_cands, integrity_candidates=integrity_candidates, key_length_observable=False,
        confidence=round(conf, 3), packets_examined=n, distinct_lengths=distinct, hypothesis_consistency=consistency,
        payload_entropy_bits=entropy, entropy_sample_bytes=len(sample), null_encryption_suspected=null_suspected,
        legacy_block_cipher_suspected=legacy, evidence=evidence,
    )


# CREATE_CHILD_SA size model (bytes), IKEv2 with one proposal and one traffic selector each way:
#   header 28 + SK generic 4 + IV 8–16 + SA 44–60 + Ni 36 + TSi 24 + TSr 24 + pad + ICV 12–16 ≈ 190–235 without KE.
#   A KE payload adds 8 + public value: Curve25519 40, P-256 72, P-384 104, MODP-2048 264, MODP-3072 392.
_REKEY_WITHOUT_KE_MAX = 232
_REKEY_ECP_KE_MIN = 262
_REKEY_WITH_MODP_KE_MIN = 420
_KE_GROUP_HINTS = {2048: "MODP-2048 (Group 14) or larger", 384: "P-384 (Group 20) / P-521 (Group 21)", 256: "P-256 (Group 19) or an ECP group"}


# IKEv1 Quick Mode (RFC 2409 §5.5): HASH(1) + SA + Ni [+ KE] [+ IDci + IDcr]; the KE payload for PFS adds
# 4 + 128 (MODP-1024) … 4 + 256 (MODP-2048) bytes to messages 1 and 2.
_QM_WITHOUT_KE_MAX = 232
_QM_WITH_KE_MIN = 300

# Framing parameters (IV length, alignment, ICV candidates) admitted by each inference outcome.
_FRAMING_PARAMS: dict[str, list[tuple[int, int, list[int]]]] = {
    HYPOTHESIS_CBC16: [(16, 16, [12, 16, 24, 32])],
    HYPOTHESIS_NOT_CBC16: [(8, 4, [8, 12, 16]), (8, 8, [12, 16])],
}
_ALL_FRAMING_PARAMS = [(16, 16, [12, 16, 24, 32]), (8, 4, [8, 12, 16]), (8, 8, [12, 16])]
_MIN_ACK_SHARE = 0.05       # a bare TCP ACK is a frequent frame in any TCP-bearing flow
_MIN_ACK_COUNT = 10
_MAX_ACK_LENGTH = 128


def _ceil_to(n: int, align: int) -> int:
    return -(-n // align) * align


def _ack_lengths(params: list[tuple[int, int, list[int]]], icv_length: Optional[int]) -> tuple[set[int], set[int], set[int]]:
    """ESP payload lengths of a bare TCP ACK (20-byte header + 2-byte trailer) in transport mode, and of the
    same segment behind an inner IPv4/IPv6 header in tunnel mode, plus the absolute tunnel floor (inner IPv4 + UDP)."""
    transport: set[int] = set()
    tunnel: set[int] = set()
    floors: set[int] = set()
    for iv, align, icvs in params:
        for icv in ([icv_length] if icv_length else icvs):
            transport.add(iv + _ceil_to(20 + 2, align) + icv)
            tunnel.add(iv + _ceil_to(20 + 20 + 2, align) + icv)
            tunnel.add(iv + _ceil_to(40 + 20 + 2, align) + icv)
            floors.add(iv + _ceil_to(20 + 8 + 2, align) + icv)
    return transport, tunnel, floors


@dataclass
class ModeInference:
    mode: str                  # TRANSPORT | UNKNOWN (tunnel mode is never proven by lengths)
    provenance: str            # INFERRED | UNAVAILABLE
    confidence: float
    min_payload_length: Optional[int]
    floor_used: Optional[int]
    evidence: list[str]
    matched_length: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


def infer_transport_mode(packets: Iterable[PacketAnalysisResult], framing_hypothesis: Optional[str] = None,
                         icv_length: Optional[int] = None) -> ModeInference:
    """Infer transport mode from ESP payload *lengths* (tunnel mode can only be left undetermined).

    Transport mode omits the inner IP header, so (a) a payload shorter than any tunnel-mode packet proves
    transport mode outright, and (b) a frequent frame at ``IV + pad(22) + ICV`` — a segment of at most 22
    bytes such as a bare TCP ACK — cannot come from tunnel mode, whose smallest frequent frame is
    ``IV + pad(42) + ICV`` (inner IPv4) or ``IV + pad(62) + ICV`` (inner IPv6).  The converse does not
    hold: a frame at the tunnel-ACK size is equally a 42-byte transport segment (a G.729 RTP frame), so
    tunnel mode is never *inferred*, only left as the documented default.  When the framing hypothesis
    (and ideally the negotiated ICV length) is known the sizes rarely collide; when they collide, or the
    flow carries no small frames (voice, ICMP), the mode is reported UNKNOWN rather than guessed.
    """
    lengths = [(p.number, p.ipsec.esp.payload_length) for p in packets if p.ipsec is not None and p.ipsec.esp is not None and p.parse_status == "OK"]
    if not lengths:
        return ModeInference("UNKNOWN", "UNAVAILABLE", 0.0, None, None, ["No ESP packets available."])
    n = len(lengths)
    counts = Counter(l for _, l in lengths)
    params = _FRAMING_PARAMS.get(framing_hypothesis or "", _ALL_FRAMING_PARAMS)
    transport_acks, tunnel_acks, floors = _ack_lengths(params, icv_length)
    floor = min(floors)
    num, smallest = min(lengths, key=lambda x: x[1])
    basis = f"{framing_hypothesis or 'any'} framing" + (f", {icv_length}-byte ICV from the negotiated integrity transform" if icv_length else ", ICV length unknown")

    # (a) Absolute floor: nothing in tunnel mode can be smaller than an inner IPv4 header plus a UDP header.
    below = sum(c for l, c in counts.items() if l < floor)
    if below >= 1:
        conf = 0.75 if below >= 3 else 0.60
        return ModeInference("TRANSPORT", "INFERRED", conf, smallest, floor, [
            f"{below} ESP payload(s) are shorter than the {floor}-byte minimum a tunnel-mode packet can have ({basis}; smallest "
            f"{smallest} bytes at packet {num}); only transport mode, which omits the inner IP header, produces such frames."], smallest)

    # (b) Bare-ACK size matching on frequent small frames.
    frequent = {l: c for l, c in counts.items() if l <= _MAX_ACK_LENGTH and c >= max(_MIN_ACK_COUNT, _MIN_ACK_SHARE * n)}
    t_hits = {l: c for l, c in frequent.items() if l in transport_acks and l not in tunnel_acks}
    u_hits = {l: c for l, c in frequent.items() if l in tunnel_acks and l not in transport_acks}
    ambiguous = {l: c for l, c in frequent.items() if l in transport_acks and l in tunnel_acks}
    strong = bool(framing_hypothesis) or icv_length is not None
    if t_hits and not u_hits:
        l, c = max(t_hits.items(), key=lambda kv: kv[1])
        return ModeInference("TRANSPORT", "INFERRED", 0.80 if strong else 0.65, smallest, floor, [
            f"{c} of {n} ESP payloads ({c / n:.0%}) are exactly {l} bytes — a transport segment of at most 22 bytes (a bare TCP ACK, "
            f"a small codec frame) in transport mode ({basis}); behind an inner IP header the same segment would be "
            f"{sorted(tunnel_acks)[0]}+ bytes."], l)
    if u_hits and not t_hits:
        # A frame at the tunnel-mode ACK size is also what a 42-byte transport segment (e.g. a G.729 RTP frame)
        # produces, so it is consistent with tunnel mode without proving it: report UNKNOWN, never TUNNEL.
        l, c = max(u_hits.items(), key=lambda kv: kv[1])
        return ModeInference("UNKNOWN", "INFERRED", 0.0, smallest, floor, [
            f"{c} of {n} ESP payloads ({c / n:.0%}) are exactly {l} bytes — the size of a bare TCP ACK behind an inner IP header "
            f"({basis}), but also of a 42-byte transport-mode segment; no frame is small enough to prove transport mode, "
            "so the mode stays undetermined (tunnel remains the documented default)."], l)
    if ambiguous:
        l = max(ambiguous.items(), key=lambda kv: kv[1])[0]
        return ModeInference("UNKNOWN", "INFERRED", 0.0, smallest, floor, [
            f"The frequent {l}-byte payload fits both a transport-mode ACK and a tunnel-mode ACK under {basis}; "
            "capture the IKE negotiation (ICV length) or AH traffic to resolve the mode."], l)
    return ModeInference("UNKNOWN", "INFERRED", 0.0, smallest, floor, [
        f"Smallest ESP payload is {smallest} bytes (≥ the {floor}-byte tunnel floor) and no frequent bare-ACK-sized frame exists "
        "(voice, ICMP or UDP-only flow): the mode cannot be inferred from framing."])


def infer_pfs(packets: Iterable[PacketAnalysisResult]) -> PFSInference:
    packets = list(packets)
    ike_pkts = [p for p in packets if p.ipsec is not None and p.ipsec.ike is not None and p.parse_status == "OK"]
    rekeys = [p for p in ike_pkts if p.ipsec.ike.major_version == 2 and p.ipsec.ike.exchange_name == "CREATE_CHILD_SA"]  # type: ignore[union-attr]
    quick_modes = [p for p in ike_pkts if p.ipsec.ike.major_version == 1 and p.ipsec.ike.exchange_type == 32]  # type: ignore[union-attr]
    if not rekeys and quick_modes:
        lengths = [p.ipsec.ike.length for p in quick_modes]  # type: ignore[union-attr]
        biggest = max(lengths)
        nums = ", ".join(str(p.number) for p in quick_modes[:4])
        if biggest >= _QM_WITH_KE_MIN:
            return PFSInference("ENABLED", "INFERRED", 0.60, len(quick_modes), lengths,
                                [f"IKEv1 Quick Mode messages (packets {nums}) are {biggest} bytes: large enough to carry a KE payload (≥132 bytes for MODP-1024), indicating Phase 2 PFS."])
        if biggest <= _QM_WITHOUT_KE_MAX:
            return PFSInference("DISABLED", "INFERRED", 0.55, len(quick_modes), lengths,
                                [f"IKEv1 Quick Mode messages (packets {nums}) are only {biggest} bytes: no room for a KE payload, so Phase 2 keys derive from the Phase 1 SA without PFS."])
        return PFSInference("UNKNOWN", "INFERRED", 0.40, len(quick_modes), lengths,
                            [f"IKEv1 Quick Mode messages (packets {nums}) are {biggest} bytes: ambiguous between a KE payload and a long SA proposal list."])
    if not rekeys:
        return PFSInference(
            status="UNKNOWN", provenance="UNAVAILABLE", confidence=0.0, rekey_exchanges_observed=0, message_lengths=[],
            evidence=["No CREATE_CHILD_SA exchange observed; PFS is negotiated inside encrypted payloads and cannot be verified without a rekey in the capture."],
        )
    lengths = [p.ipsec.ike.length for p in rekeys]  # type: ignore[union-attr]
    biggest = max(lengths)
    nums = ", ".join(str(p.number) for p in rekeys[:6])
    if biggest >= _REKEY_WITH_MODP_KE_MIN:
        return PFSInference(
            status="ENABLED", provenance="INFERRED", confidence=0.75, rekey_exchanges_observed=len(rekeys), message_lengths=lengths,
            evidence=[f"CREATE_CHILD_SA messages (packets {nums}) are {biggest} bytes: large enough to carry a KE payload for {_KE_GROUP_HINTS[2048]} (≥264 bytes), so a fresh Diffie-Hellman exchange accompanies the rekey."],
        )
    if biggest >= _REKEY_ECP_KE_MIN:
        hint = _KE_GROUP_HINTS[384] if biggest >= 300 else _KE_GROUP_HINTS[256]
        return PFSInference(
            status="ENABLED", provenance="INFERRED", confidence=0.60, rekey_exchanges_observed=len(rekeys), message_lengths=lengths,
            evidence=[f"CREATE_CHILD_SA messages (packets {nums}) are {biggest} bytes: about 30–100 bytes above a rekey without key exchange, matching a KE payload for {hint}. A very long proposal list could also explain the size, hence the moderate confidence."],
        )
    if biggest <= _REKEY_WITHOUT_KE_MAX:
        return PFSInference(
            status="DISABLED", provenance="INFERRED", confidence=0.65, rekey_exchanges_observed=len(rekeys), message_lengths=lengths,
            evidence=[f"CREATE_CHILD_SA messages (packets {nums}) are only {biggest} bytes: too small to include any KE payload, so the Child SA keys derive from the IKE SA without PFS."],
        )
    return PFSInference(
        status="UNKNOWN", provenance="INFERRED", confidence=0.45, rekey_exchanges_observed=len(rekeys), message_lengths=lengths,
        evidence=[f"CREATE_CHILD_SA messages (packets {nums}) are {biggest} bytes: compatible with either a Curve25519 KE payload or a slightly longer proposal list, so PFS cannot be decided from size alone."],
    )
