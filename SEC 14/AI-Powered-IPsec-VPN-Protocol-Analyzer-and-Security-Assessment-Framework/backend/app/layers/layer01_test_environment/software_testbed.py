"""Layer 01 — Software IPsec testbed.

Generates captures of IPsec VPN sessions **without a hypervisor**: every ESP frame is built
to RFC 4303 (SPI, sequence number, IV, padding, pad-length, next-header, ICV) and really
encrypted with the profile's cipher (AES-GCM per RFC 4106, AES-CBC + HMAC per RFC 3602 /
RFC 2404 / RFC 4868, 3DES-CBC per RFC 2451, ChaCha20-Poly1305 per RFC 7634). IKE messages
follow RFC 7296 (IKEv2) or RFC 2408/2409 (IKEv1) framing with cleartext SA/KE/Nonce
payloads sized for the negotiated group, and encrypted payloads of realistic size.

Inner traffic comes from seven application models (VoIP, WhatsApp-style messaging, e-mail,
web browsing, ICMP, adaptive video streaming, other). The models are statistical — they
reproduce the packet sizes, cadences and directional patterns of the real applications —
and every generated flow is labelled, which is what the Layer 07 classifier is trained on.
The pcap files are honest about what they are: synthetic application traffic inside real
IPsec framing, produced deterministically from a seed.

When VirtualBox + strongSwan are available the VM testbed remains the primary environment;
this module is the software fallback and the dataset generator.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import random
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --------------------------------------------------------------------------- #
# Crypto specifications
# --------------------------------------------------------------------------- #

CIPHER_SPECS: Dict[str, Dict[str, Any]] = {
    "AES-256-GCM": {"family": "AES-GCM", "key_bytes": 32, "iv": 8, "icv": 16, "align": 4, "ike_id": 20, "ike_keylen": 256, "aead": True},
    "AES-128-GCM": {"family": "AES-GCM", "key_bytes": 16, "iv": 8, "icv": 16, "align": 4, "ike_id": 20, "ike_keylen": 128, "aead": True},
    "AES-256-CBC": {"family": "AES-CBC", "key_bytes": 32, "iv": 16, "icv": None, "align": 16, "ike_id": 12, "ike_keylen": 256, "aead": False},
    "AES-128-CBC": {"family": "AES-CBC", "key_bytes": 16, "iv": 16, "icv": None, "align": 16, "ike_id": 12, "ike_keylen": 128, "aead": False},
    "3DES-CBC": {"family": "3DES", "key_bytes": 24, "iv": 8, "icv": None, "align": 8, "ike_id": 3, "ike_keylen": None, "aead": False},
    "CHACHA20-POLY1305": {"family": "CHACHA20", "key_bytes": 32, "iv": 8, "icv": 16, "align": 4, "ike_id": 28, "ike_keylen": None, "aead": True},
    "NULL": {"family": "NULL", "key_bytes": 0, "iv": 0, "icv": None, "align": 4, "ike_id": 11, "ike_keylen": None, "aead": False},
}

INTEGRITY_SPECS: Dict[str, Dict[str, Any]] = {
    "AEAD": {"ike_integ_id": None, "prf_id": 5, "hash": None, "icv": None},
    "HMAC-SHA2-256": {"ike_integ_id": 12, "prf_id": 5, "hash": hashes.SHA256, "icv": 16},
    "HMAC-SHA2-384": {"ike_integ_id": 13, "prf_id": 6, "hash": hashes.SHA384, "icv": 24},
    "HMAC-SHA2-512": {"ike_integ_id": 14, "prf_id": 7, "hash": hashes.SHA512, "icv": 32},
    "HMAC-SHA1-96": {"ike_integ_id": 2, "prf_id": 2, "hash": hashes.SHA1, "icv": 12},
    "HMAC-MD5-96": {"ike_integ_id": 1, "prf_id": 1, "hash": hashes.MD5, "icv": 12},
}

# DH group -> public value length in bytes (MODP: modulus size; ECP: x||y)
DH_KE_BYTES: Dict[int, int] = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 19: 64, 20: 96, 21: 132, 31: 32}

TRAFFIC_TYPES = ["VOIP", "WHATSAPP", "EMAIL", "WEB_BROWSING", "ICMP", "VIDEO_STREAMING", "OTHER"]

ETHERTYPE_IPV4, ETHERTYPE_IPV6 = 0x0800, 0x86DD
MAC_A, MAC_B = bytes.fromhex("0800271a2b3c"), bytes.fromhex("0800274d5e6f")


# --------------------------------------------------------------------------- #
# Low-level packet builders
# --------------------------------------------------------------------------- #


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, ethertype: int, src: bytes = MAC_A, dst: bytes = MAC_B) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, proto: int, src: str, dst: str, ttl: int = 64, ident: int = 0, dscp: int = 0) -> bytes:
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, total, ident & 0xFFFF, 0x4000, ttl, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def ipv6(payload: bytes, next_header: int, src: str, dst: str, hop_limit: int = 64, ext_headers: Sequence[bytes] = (), first_ext_type: Optional[int] = None) -> bytes:
    body = b"".join(ext_headers) + payload
    nh = first_ext_type if ext_headers and first_ext_type is not None else next_header
    return struct.pack("!IHBB16s16s", 0x60000000, len(body), nh, hop_limit,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + body


def ipv6_hop_by_hop(next_header: int) -> bytes:
    # PadN option filling an 8-byte header
    return struct.pack("!BB", next_header, 0) + b"\x01\x04\x00\x00\x00\x00"


def udp(payload: bytes, sport: int, dport: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(payload: bytes, sport: int, dport: int, seq: int, ack: int, flags: int = 0x18, window: int = 65535) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0) + payload


def icmp_echo(payload: bytes, ident: int, seq: int, reply: bool = False, v6: bool = False) -> bytes:
    t = (129 if reply else 128) if v6 else (0 if reply else 8)
    header = struct.pack("!BBHHH", t, 0, 0, ident, seq)
    packet = header + payload
    return packet[:2] + struct.pack("!H", _checksum(packet)) + packet[4:]


def pcap(frames: Iterable[Tuple[bytes, float]], link_type: int = 1) -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
    for frame, ts in frames:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return bytes(out)


# --------------------------------------------------------------------------- #
# ESP / AH security associations
# --------------------------------------------------------------------------- #


class ESPSecurityAssociation:
    """One unidirectional ESP SA that really encrypts and authenticates its payloads."""

    def __init__(self, spi: int, cipher: str, integrity: str, rng: random.Random, tfc_pad_to: Optional[int] = None):
        self.spi = spi
        self.spec = CIPHER_SPECS[cipher]
        self.cipher_name = cipher
        self.integrity = integrity
        self.iseq = 0
        self.tfc_pad_to = tfc_pad_to
        self.key = bytes(rng.getrandbits(8) for _ in range(self.spec["key_bytes"]))
        self.salt = bytes(rng.getrandbits(8) for _ in range(4))
        self.auth_key = bytes(rng.getrandbits(8) for _ in range(32))
        self.rng = rng
        if self.spec["aead"]:
            self.icv = self.spec["icv"]
        else:
            self.icv = INTEGRITY_SPECS[integrity]["icv"] if integrity != "AEAD" else 0

    def next_seq(self) -> int:
        self.iseq += 1
        return self.iseq

    def encapsulate(self, plaintext: bytes, next_header: int, seq: Optional[int] = None) -> bytes:
        seq = self.next_seq() if seq is None else seq
        align = self.spec["align"]
        if self.tfc_pad_to and len(plaintext) < self.tfc_pad_to:
            # RFC 4303 §2.7: TFC padding is inserted after the payload, before the ESP trailer.
            plaintext = plaintext + bytes(self.tfc_pad_to - len(plaintext))
        pad_len = (-(len(plaintext) + 2)) % align
        pad = bytes(range(1, pad_len + 1))
        block = plaintext + pad + struct.pack("!BB", pad_len, next_header)
        header = struct.pack("!II", self.spi, seq)
        iv = bytes(self.rng.getrandbits(8) for _ in range(self.spec["iv"]))
        fam = self.spec["family"]
        if fam == "AES-GCM":
            ct = AESGCM(self.key).encrypt(self.salt + iv, block, header)  # ciphertext || 16-byte tag
            return header + iv + ct
        if fam == "CHACHA20":
            ct = ChaCha20Poly1305(self.key).encrypt(self.salt + iv, block, header)
            return header + iv + ct
        if fam == "AES-CBC":
            enc = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
            body = header + iv + enc.update(block) + enc.finalize()
        elif fam == "3DES":
            enc = Cipher(TripleDES(self.key), modes.CBC(iv)).encryptor()
            body = header + iv + enc.update(block) + enc.finalize()
        else:  # NULL
            body = header + block
        return body + self._icv(body)

    def _icv(self, data: bytes) -> bytes:
        spec = INTEGRITY_SPECS.get(self.integrity)
        if not spec or spec["hash"] is None:
            return b""
        h = spec["hash"]()
        digest = hmac.new(self.auth_key, data, {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512", "sha1": "sha1", "md5": "md5"}[h.name]).digest()
        return digest[: spec["icv"]]


class AHSecurityAssociation:
    """Unidirectional AH SA (RFC 4302): ICV over the packet with mutable fields zeroed."""

    def __init__(self, spi: int, integrity: str, rng: random.Random):
        self.spi = spi
        self.integrity = integrity
        self.icv_len = INTEGRITY_SPECS[integrity]["icv"]
        self.auth_key = bytes(rng.getrandbits(8) for _ in range(32))
        self.iseq = 0

    def header(self, next_header: int, seq: Optional[int] = None) -> bytes:
        if seq is None:
            self.iseq += 1
            seq = self.iseq
        payload_len_words = (12 + self.icv_len) // 4 - 2
        return struct.pack("!BBHII", next_header, payload_len_words, 0, self.spi, seq)

    def icv(self, covered: bytes) -> bytes:
        h = INTEGRITY_SPECS[self.integrity]["hash"]()
        return hmac.new(self.auth_key, covered, h.name).digest()[: self.icv_len]


# --------------------------------------------------------------------------- #
# IKE message builders
# --------------------------------------------------------------------------- #


def _ike_payload(next_type: int, body: bytes, critical: bool = False) -> bytes:
    return struct.pack("!BBH", next_type, 0x80 if critical else 0, 4 + len(body)) + body


def _ike_chain(payloads: List[Tuple[int, bytes]]) -> Tuple[int, bytes]:
    chain = b""
    for i, (ptype, body) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        chain += _ike_payload(nxt, body)
    return (payloads[0][0] if payloads else 0), chain


def ikev2_message(i_spi: bytes, r_spi: bytes, exchange: int, flags: int, message_id: int, payloads: List[Tuple[int, bytes]]) -> bytes:
    first, chain = _ike_chain(payloads)
    return struct.pack("!8s8sBBBBII", i_spi, r_spi, first, 0x20, exchange, flags, message_id, 28 + len(chain)) + chain


def ikev1_message(i_cookie: bytes, r_cookie: bytes, exchange: int, flags: int, payloads: List[Tuple[int, bytes]], message_id: int = 0, encrypted_len: int = 0,
                  rng: Optional[random.Random] = None) -> bytes:
    if flags & 0x01:
        body = rng.randbytes(encrypted_len) if rng is not None else os.urandom(encrypted_len)
        return struct.pack("!8s8sBBBBII", i_cookie, r_cookie, 8, 0x10, exchange, flags, message_id, 28 + len(body)) + body
    first, chain = _ike_chain(payloads)
    return struct.pack("!8s8sBBBBII", i_cookie, r_cookie, first, 0x10, exchange, flags, message_id, 28 + len(chain)) + chain


def _transform(ttype: int, tid: int, keylen: Optional[int] = None, last: bool = False) -> bytes:
    attr = struct.pack("!HH", 0x800E, keylen) if keylen else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attr), ttype, 0, tid) + attr


def ikev2_proposal(number: int, cipher: str, integrity: str, dh_group: int, last: bool = True, protocol: int = 1, spi: bytes = b"") -> bytes:
    cs, isp = CIPHER_SPECS[cipher], INTEGRITY_SPECS[integrity]
    transforms = [_transform(1, cs["ike_id"], cs["ike_keylen"])]
    if isp["ike_integ_id"] is not None:
        transforms.append(_transform(3, isp["ike_integ_id"]))
    if protocol == 1:
        transforms.append(_transform(2, isp["prf_id"]))
    transforms.append(_transform(4, dh_group, last=True))
    body = b"".join(transforms)
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(spi) + len(body), number, protocol, len(spi), len(transforms)) + spi + body


def ikev2_ke(dh_group: int, rng: random.Random) -> bytes:
    return struct.pack("!HH", dh_group, 0) + bytes(rng.getrandbits(8) for _ in range(DH_KE_BYTES.get(dh_group, 256)))


def ikev2_notify(ntype: int, data: bytes = b"") -> bytes:
    return struct.pack("!BBH", 0, 0, ntype) + data


def ikev1_transform(number: int, cipher: str, hash_name: str, dh_group: int, auth: int, lifetime: int, last: bool = True) -> bytes:
    cs = CIPHER_SPECS[cipher]
    encr = {"AES-CBC": 7, "3DES": 5, "NULL": 7}.get(cs["family"], 7)
    hsh = {"HMAC-MD5-96": 1, "HMAC-SHA1-96": 2, "HMAC-SHA2-256": 4, "HMAC-SHA2-384": 5, "HMAC-SHA2-512": 6}.get(hash_name, 2)
    attrs = struct.pack("!HH", 0x8001, encr) + struct.pack("!HH", 0x8002, hsh) + struct.pack("!HH", 0x8003, auth) + struct.pack("!HH", 0x8004, dh_group)
    attrs += struct.pack("!HH", 0x800B, 1) + struct.pack("!HH", 0x000C, 4) + struct.pack("!I", lifetime)
    if cs["ike_keylen"]:
        attrs += struct.pack("!HH", 0x800E, cs["ike_keylen"])
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), number, 1, 0) + attrs


def ikev1_sa_payload(transforms: List[bytes]) -> bytes:
    body = b"".join(transforms)
    prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(body), 1, 1, 0, len(transforms)) + body
    return struct.pack("!II", 1, 1) + prop  # DOI=IPsec, Situation=identity only


# --------------------------------------------------------------------------- #
# Profiles and ground truth
# --------------------------------------------------------------------------- #


@dataclass
class TestbedConfig:
    profile_id: str
    name: str
    mode: str                         # TUNNEL | TRANSPORT
    encryption: str                   # key of CIPHER_SPECS
    integrity: str                    # key of INTEGRITY_SPECS
    dh_group: int
    pfs_enabled: bool
    ip_version: int
    ike_version: str = "2.0"          # "2.0" | "1.0" | "1.0-aggressive"
    traffic_type: str = "WEB_BROWSING"
    protocol: str = "ESP"             # ESP | AH
    nat_traversal: bool = False
    rekey: bool = True
    weak_fallback_offer: bool = False # initiator also offers a weak proposal (downgrade surface)
    downgrade: bool = False           # responder selects the weak proposal
    tfc_padding: bool = False
    ipv6_extension_headers: bool = False
    auth_method: str = "PSK"          # IKEv1 only
    ike_lifetime_seconds: int = 28800
    duration_seconds: float = 45.0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


DEFAULT_PROFILES: List[TestbedConfig] = [
    TestbedConfig("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", "Standard Secure Gateway (Tunnel, AES-256-GCM, DH19, PFS, IPv4)", "TUNNEL", "AES-256-GCM", "AEAD", 19, True, 4,
                  traffic_type="WEB_BROWSING", description="Modern AEAD site-to-site tunnel with ephemeral ECDH."),
    TestbedConfig("PROFILE-02-TRANSPORT-AES128CBC-PFS-IPV4", "Host-to-Host Voice Tunnel (Transport, AES-128-CBC+HMAC, DH14, PFS, IPv4)", "TRANSPORT", "AES-128-CBC", "HMAC-SHA2-256", 14, True, 4,
                  traffic_type="VOIP", description="Transport-mode end-to-end session carrying 20 ms RTP voice."),
    TestbedConfig("PROFILE-03-TUNNEL-AES128GCM-NOPFS-IPV4", "Streaming Gateway (Tunnel, AES-128-GCM, DH14, PFS Disabled, IPv4)", "TUNNEL", "AES-128-GCM", "AEAD", 14, False, 4,
                  traffic_type="VIDEO_STREAMING", description="AES-GCM tunnel streaming adaptive video segments; rekeys without PFS."),
    TestbedConfig("PROFILE-04-TRANSPORT-AES256CBC-PFS-IPV6", "Next-Gen Enterprise IPv6 (Transport, AES-256-CBC+HMAC, DH20, PFS, IPv6)", "TRANSPORT", "AES-256-CBC", "HMAC-SHA2-512", 20, True, 6,
                  traffic_type="EMAIL", ipv6_extension_headers=True, description="IPv6 transport mode with Hop-by-Hop extension headers, bulk e-mail transfer."),
    TestbedConfig("PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4", "Legacy Deprecated Baseline (Tunnel, 3DES-CBC+MD5, DH2, PFS Disabled, IPv4)", "TUNNEL", "3DES-CBC", "HMAC-MD5-96", 2, False, 4,
                  ike_version="1.0-aggressive", traffic_type="ICMP", auth_method="PSK", ike_lifetime_seconds=86400 * 2,
                  description="IKEv1 Aggressive Mode with PSK, 3DES/MD5/DH2, 48 h lifetime: the vulnerability demonstration profile."),
    TestbedConfig("PROFILE-06-TUNNEL-AES256GCM-PFS-IPV6", "Government Critical Infrastructure (Tunnel, AES-256-GCM, DH21, PFS, IPv6)", "TUNNEL", "AES-256-GCM", "AEAD", 21, True, 6,
                  traffic_type="WHATSAPP", description="AES-256-GCM over IPv6 with P-521 ECDH."),
    TestbedConfig("PROFILE-07-TUNNEL-DOWNGRADE-IPV4", "Downgrade Demonstration (Tunnel, AES-256-GCM offered, 3DES selected, IPv4)", "TUNNEL", "3DES-CBC", "HMAC-SHA1-96", 5, True, 4,
                  traffic_type="OTHER", weak_fallback_offer=True, downgrade=True, description="Initiator offers AES-256-GCM/DH19 first; responder picks the 3DES/SHA-1/DH5 fallback."),
    TestbedConfig("PROFILE-08-TRANSPORT-AH-SHA256-IPV4", "Integrity-Only Link (Transport, AH HMAC-SHA2-256, DH14, IPv4)", "TRANSPORT", "NULL", "HMAC-SHA2-256", 14, True, 4,
                  traffic_type="ICMP", protocol="AH", description="AH without ESP: authenticated but cleartext data plane."),
    TestbedConfig("PROFILE-09-TUNNEL-NATT-CHACHA-IPV4", "Remote Worker NAT-T (Tunnel, ChaCha20-Poly1305, Curve25519, PFS, UDP/4500)", "TUNNEL", "CHACHA20-POLY1305", "AEAD", 31, True, 4,
                  traffic_type="WEB_BROWSING", nat_traversal=True, description="Road-warrior tunnel through NAT: IKE and ESP on UDP/4500."),
    TestbedConfig("PROFILE-10-TUNNEL-TFC-PADDED-IPV4", "TFC-Padded Voice Tunnel (Tunnel, AES-256-GCM, DH19, PFS, fixed 1200-byte frames)", "TUNNEL", "AES-256-GCM", "AEAD", 19, True, 4,
                  traffic_type="VOIP", tfc_padding=True, description="Same voice traffic as profile 02 but with RFC 4303 §2.7 TFC padding to a fixed size."),
]


def profile_by_id(profile_id: str) -> Optional[TestbedConfig]:
    return next((p for p in DEFAULT_PROFILES if p.profile_id == profile_id), None)


# --------------------------------------------------------------------------- #
# Application traffic models
# --------------------------------------------------------------------------- #


@dataclass
class InnerPacket:
    t: float                 # seconds from flow start
    uplink: bool             # client -> server
    transport: str           # udp | tcp | icmp
    payload_len: int
    sport: int = 0
    dport: int = 0
    flags: int = 0x18
    icmp_seq: int = 0
    reply: bool = False


@dataclass
class TrafficModelResult:
    packets: List[InnerPacket]
    label: str
    parameters: Dict[str, Any] = field(default_factory=dict)


def _gauss(rng: random.Random, mu: float, sigma: float, lo: float = 0.0) -> float:
    return max(lo, rng.gauss(mu, sigma))


def model_voip(rng: random.Random, duration: float) -> TrafficModelResult:
    codec = rng.choice(["G.711", "G.711", "G.729", "OPUS"])
    ptime = 0.020
    base = {"G.711": 160, "G.729": 20, "OPUS": 60}[codec]
    vad = rng.random() < 0.45
    jitter_ms = rng.uniform(0.2, 1.2)
    sport, dport = rng.randint(16384, 32767) & ~1, rng.randint(16384, 32767) & ~1
    pkts: List[InnerPacket] = []
    t = 0.0
    talker_a = True
    spurt_end = rng.uniform(1.0, 4.0)
    while t < duration:
        for uplink in (True, False):
            active = (uplink == talker_a) or not vad
            if active:
                size = base + 12 if codec != "OPUS" else rng.randint(40, 110) + 12
                pkts.append(InnerPacket(t + _gauss(rng, 0.0, jitter_ms / 1000.0), uplink, "udp", size, sport, dport))
            elif int(t / 0.160) != int((t - ptime) / 0.160):
                pkts.append(InnerPacket(t + _gauss(rng, 0.0, jitter_ms / 1000.0), uplink, "udp", 12 + 2, sport, dport))  # SID frame
        t += ptime
        if vad and t >= spurt_end:
            talker_a = not talker_a
            spurt_end = t + rng.uniform(0.8, 4.0)
    return TrafficModelResult(pkts, "VOIP", {"codec": codec, "vad": vad, "jitter_ms": round(jitter_ms, 2)})


def model_icmp(rng: random.Random, duration: float) -> TrafficModelResult:
    interval = rng.choice([1.0, 1.0, 1.0, 0.5, 0.2, 2.0])
    payload = rng.choice([56, 56, 56, 32, 100, 1000])
    rtt = rng.uniform(0.002, 0.060)
    ident = rng.randint(1, 65535)
    pkts: List[InnerPacket] = []
    n = max(6, int(duration / interval))
    for i in range(n):
        t = i * interval + _gauss(rng, 0.0, 0.004)
        pkts.append(InnerPacket(t, True, "icmp", payload, icmp_seq=i + 1))
        if rng.random() > 0.03:  # occasional loss
            pkts.append(InnerPacket(t + rtt + _gauss(rng, 0.0, 0.003), False, "icmp", payload, icmp_seq=i + 1, reply=True))
    return TrafficModelResult(pkts, "ICMP", {"interval": interval, "payload": payload, "ident": ident})


def _bulk_train(rng: random.Random, pkts: List[InnerPacket], t: float, total_bytes: int, downlink: bool, rate_bps: float, sport: int, dport: int, mss: int = 1400) -> float:
    sent = 0
    n = 0
    while sent < total_bytes:
        size = min(mss, total_bytes - sent)
        pkts.append(InnerPacket(t, not downlink, "tcp", size, sport, dport))
        sent += size
        n += 1
        t += size * 8 / rate_bps + _gauss(rng, 0.0, 0.0002)
        if n % 2 == 0:
            pkts.append(InnerPacket(t + rng.uniform(0.0005, 0.004), downlink, "tcp", 0, dport, sport, flags=0x10))
    return t


def model_email(rng: random.Random, duration: float) -> TrafficModelResult:
    fetch = rng.random() < 0.55           # IMAP fetch (downlink) vs SMTP submission (uplink)
    sport, dport = rng.randint(49152, 65535), (993 if fetch else 587)
    pkts: List[InnerPacket] = []
    t = 0.0
    for _ in range(rng.randint(5, 10)):   # TLS + protocol handshake, command/response
        pkts.append(InnerPacket(t, True, "tcp", rng.randint(60, 260), sport, dport)); t += rng.uniform(0.02, 0.15)
        pkts.append(InnerPacket(t, False, "tcp", rng.randint(60, 320), dport, sport)); t += rng.uniform(0.02, 0.20)
    size = int(rng.lognormvariate(11.5, 1.2))            # ~100 KB median, up to a few MB
    size = max(15_000, min(size, 3_000_000))
    t = _bulk_train(rng, pkts, t, size, downlink=fetch, rate_bps=rng.uniform(4e6, 40e6), sport=sport, dport=dport)
    for _ in range(rng.randint(2, 4)):
        t += rng.uniform(0.02, 0.3)
        pkts.append(InnerPacket(t, rng.random() < 0.5, "tcp", rng.randint(40, 120), sport, dport))
    return TrafficModelResult(pkts, "EMAIL", {"operation": "IMAP_FETCH" if fetch else "SMTP_SUBMIT", "message_bytes": size})


def model_web(rng: random.Random, duration: float) -> TrafficModelResult:
    sport, dport = rng.randint(49152, 65535), 443
    pkts: List[InnerPacket] = []
    t = 0.0
    pages = 0
    while t < duration:
        pages += 1
        n_obj = rng.randint(4, 18)
        for _ in range(n_obj):
            pkts.append(InnerPacket(t, True, "tcp", rng.randint(300, 900), sport, dport))
            t += rng.uniform(0.005, 0.05)
            obj = int(rng.lognormvariate(9.5, 1.3))          # objects from ~1 KB to ~200 KB
            obj = max(600, min(obj, 400_000))
            t = _bulk_train(rng, pkts, t + rng.uniform(0.01, 0.08), obj, downlink=True, rate_bps=rng.uniform(5e6, 60e6), sport=sport, dport=dport)
        t += rng.uniform(2.5, 15.0)  # think time
    return TrafficModelResult(pkts, "WEB_BROWSING", {"pages": pages})


def model_whatsapp(rng: random.Random, duration: float) -> TrafficModelResult:
    sport, dport = rng.randint(49152, 65535), rng.choice([443, 5222])
    pkts: List[InnerPacket] = []
    t = 0.0
    next_keepalive = rng.uniform(15.0, 40.0)
    media = 0
    while t < duration:
        if t >= next_keepalive:
            pkts.append(InnerPacket(t, True, "tcp", rng.randint(30, 80), sport, dport))
            pkts.append(InnerPacket(t + rng.uniform(0.03, 0.12), False, "tcp", rng.randint(30, 80), dport, sport))
            next_keepalive = t + rng.uniform(25.0, 45.0)
        gap = rng.expovariate(1.0 / rng.uniform(4.0, 12.0))
        t += gap
        outgoing = rng.random() < 0.5
        if rng.random() < 0.06:  # media attachment
            media += 1
            size = rng.randint(40_000, 400_000)
            t = _bulk_train(rng, pkts, t, size, downlink=not outgoing, rate_bps=rng.uniform(3e6, 30e6), sport=sport, dport=dport)
        else:
            for _ in range(rng.randint(1, 3)):
                pkts.append(InnerPacket(t, outgoing, "tcp", rng.randint(90, 600), sport, dport))
                t += rng.uniform(0.02, 0.15)
                pkts.append(InnerPacket(t, not outgoing, "tcp", rng.randint(40, 120), dport, sport))
                t += rng.uniform(0.05, 0.4)
    return TrafficModelResult(pkts, "WHATSAPP", {"media_transfers": media})


def model_video(rng: random.Random, duration: float) -> TrafficModelResult:
    sport, dport = rng.randint(49152, 65535), 443
    seg = rng.choice([2.0, 4.0, 6.0])
    bitrate = rng.uniform(0.4e6, 2.5e6)   # SD–HD adaptive ladders; keeps a 60 s capture well under the 25 MB upload limit
    line_rate = rng.uniform(15e6, 60e6)
    pkts: List[InnerPacket] = []
    t = 0.0
    # manifest + startup burst
    pkts.append(InnerPacket(t, True, "tcp", rng.randint(300, 700), sport, dport)); t += 0.05
    t = _bulk_train(rng, pkts, t, rng.randint(2_000, 8_000), True, line_rate, sport, dport)
    for i in range(rng.randint(2, 4)):
        pkts.append(InnerPacket(t, True, "tcp", rng.randint(300, 600), sport, dport))
        t = _bulk_train(rng, pkts, t + 0.02, int(bitrate * seg / 8), True, line_rate, sport, dport)
    segments = 0
    while t < duration:
        t += seg + _gauss(rng, 0.0, 0.08)
        if rng.random() < 0.15:
            bitrate *= rng.choice([0.6, 1.5])
            bitrate = max(0.3e6, min(bitrate, 3.0e6))
        pkts.append(InnerPacket(t, True, "tcp", rng.randint(300, 600), sport, dport))
        t = _bulk_train(rng, pkts, t + rng.uniform(0.01, 0.05), int(bitrate * seg / 8), True, line_rate, sport, dport)
        segments += 1
    return TrafficModelResult(pkts, "VIDEO_STREAMING", {"segment_seconds": seg, "bitrate_bps": int(bitrate), "segments": segments})


def model_other(rng: random.Random, duration: float) -> TrafficModelResult:
    kind = rng.choice(["ssh_interactive", "sftp_upload", "dns_like", "background_sync", "database"])
    pkts: List[InnerPacket] = []
    t = 0.0
    sport = rng.randint(49152, 65535)
    if kind == "ssh_interactive":
        while t < duration:
            t += rng.uniform(0.05, 0.6)
            pkts.append(InnerPacket(t, True, "tcp", rng.randint(36, 100), sport, 22))
            pkts.append(InnerPacket(t + rng.uniform(0.01, 0.05), False, "tcp", rng.randint(36, 200), 22, sport))
    elif kind == "sftp_upload":
        t = _bulk_train(rng, pkts, 0.2, rng.randint(200_000, 3_000_000), downlink=False, rate_bps=rng.uniform(2e6, 30e6), sport=sport, dport=22)
    elif kind == "dns_like":
        while t < duration:
            t += rng.uniform(0.3, 3.0)
            pkts.append(InnerPacket(t, True, "udp", rng.randint(30, 80), sport, 53))
            pkts.append(InnerPacket(t + rng.uniform(0.005, 0.05), False, "udp", rng.randint(60, 300), 53, sport))
    elif kind == "database":
        while t < duration:
            t += rng.uniform(0.01, 0.2)
            pkts.append(InnerPacket(t, True, "tcp", rng.randint(60, 400), sport, 5432))
            t += rng.uniform(0.002, 0.03)
            for _ in range(rng.randint(1, 6)):
                pkts.append(InnerPacket(t, False, "tcp", rng.randint(200, 1400), 5432, sport)); t += rng.uniform(0.0005, 0.005)
    else:  # background sync: mixed small/large both ways
        while t < duration:
            t += rng.uniform(0.2, 4.0)
            if rng.random() < 0.3:
                t = _bulk_train(rng, pkts, t, rng.randint(5_000, 120_000), downlink=rng.random() < 0.5, rate_bps=rng.uniform(2e6, 20e6), sport=sport, dport=443)
            else:
                pkts.append(InnerPacket(t, rng.random() < 0.5, "tcp", rng.randint(60, 700), sport, 443))
    return TrafficModelResult(pkts, "OTHER", {"kind": kind})


TRAFFIC_MODELS = {
    "VOIP": model_voip, "ICMP": model_icmp, "EMAIL": model_email, "WEB_BROWSING": model_web,
    "WHATSAPP": model_whatsapp, "VIDEO_STREAMING": model_video, "OTHER": model_other,
}


# --------------------------------------------------------------------------- #
# Capture generation
# --------------------------------------------------------------------------- #


@dataclass
class GeneratedCapture:
    pcap_bytes: bytes
    ground_truth: Dict[str, Any]
    packet_count: int
    filename: str


class SoftwareTestbed:
    """Builds a complete IPsec session capture (IKE + data plane) for one configuration."""

    def __init__(self, config: TestbedConfig, seed: int = 1, start_time: float = 1_700_000_000.0, traffic_type: Optional[str] = None,
                 duration: Optional[float] = None):
        self.cfg = config
        self.seed = seed
        self.rng = random.Random(f"{config.profile_id}|{seed}")
        self.t0 = start_time
        self.traffic_type = traffic_type or config.traffic_type
        self.duration = duration or config.duration_seconds
        v6 = config.ip_version == 6
        # Outer (gateway or host) addresses and inner hosts
        if v6:
            self.outer_a, self.outer_b = "2001:db8:1::10", "2001:db8:2::20"
            self.inner_a, self.inner_b = "fd00:10::100", "fd00:20::200"
        else:
            self.outer_a, self.outer_b = "203.0.113.10", "198.51.100.20"
            self.inner_a, self.inner_b = "10.10.1.100", "10.20.2.200"
        if config.mode == "TRANSPORT":
            self.inner_a, self.inner_b = self.outer_a, self.outer_b
        self.frames: List[Tuple[bytes, float]] = []
        self.ike_spi_i = bytes(self.rng.getrandbits(8) for _ in range(8))
        self.ike_spi_r = bytes(self.rng.getrandbits(8) for _ in range(8))
        self.spis: List[int] = []

    # ---- helpers --------------------------------------------------------------------------

    def _emit(self, ip_packet: bytes, ts: float) -> None:
        et = ETHERTYPE_IPV6 if self.cfg.ip_version == 6 else ETHERTYPE_IPV4
        self.frames.append((ethernet(ip_packet, et), ts))

    def _outer(self, payload: bytes, proto: int, src: str, dst: str, ident: int = 0) -> bytes:
        if self.cfg.ip_version == 6:
            if self.cfg.ipv6_extension_headers:
                return ipv6(payload, proto, src, dst, ext_headers=[ipv6_hop_by_hop(proto)], first_ext_type=0)
            return ipv6(payload, proto, src, dst)
        return ipv4(payload, proto, src, dst, ident=ident)

    def _ike_udp(self, msg: bytes, from_a: bool, ts: float) -> None:
        src, dst = (self.outer_a, self.outer_b) if from_a else (self.outer_b, self.outer_a)
        if self.cfg.nat_traversal:
            self._emit(self._outer(udp(b"\x00\x00\x00\x00" + msg, 4500, 4500), 17, src, dst), ts)
        else:
            self._emit(self._outer(udp(msg, 500, 500), 17, src, dst), ts)

    # ---- IKE -----------------------------------------------------------------------------

    def _ikev2(self, t: float) -> float:
        cfg, rng = self.cfg, self.rng
        strong = ("AES-256-GCM", "AEAD", 19)
        proposals: List[Tuple[str, str, int]] = []
        if cfg.weak_fallback_offer:
            proposals.append(strong)
        proposals.append((cfg.encryption if cfg.protocol == "ESP" else "AES-256-GCM", cfg.integrity if cfg.protocol == "ESP" else "AEAD", cfg.dh_group))
        sa_req = b"".join(ikev2_proposal(i + 1, c, h, g, last=(i == len(proposals) - 1)) for i, (c, h, g) in enumerate(proposals))
        chosen = proposals[-1] if cfg.downgrade or not cfg.weak_fallback_offer else proposals[0]
        chosen_idx = proposals.index(chosen) + 1
        sa_resp = ikev2_proposal(chosen_idx, *chosen)
        nat_notifies = [(41, ikev2_notify(16388, bytes(20))), (41, ikev2_notify(16389, bytes(20)))]
        req = ikev2_message(self.ike_spi_i, bytes(8), 34, 0x08, 0, [(33, sa_req), (34, ikev2_ke(chosen[2], rng)), (40, rng.randbytes(32))] + nat_notifies + [(41, ikev2_notify(16430))])
        self._ike_udp(req, True, t); t += rng.uniform(0.010, 0.040)
        resp = ikev2_message(self.ike_spi_i, self.ike_spi_r, 34, 0x20, 0, [(33, sa_resp), (34, ikev2_ke(chosen[2], rng)), (40, rng.randbytes(32))] + nat_notifies + [(38, rng.randbytes(24))])
        self._ike_udp(resp, False, t); t += rng.uniform(0.020, 0.080)
        # IKE_AUTH: everything inside SK; size ≈ IDi + AUTH + SA + TSi + TSr (+ USE_TRANSPORT_MODE)
        auth_len = 260 if rng.random() < 0.5 else 68
        sk_len = 12 + auth_len + 60 + 24 + 24 + (8 if cfg.mode == "TRANSPORT" else 0) + 16
        self._ike_udp(ikev2_message(self.ike_spi_i, self.ike_spi_r, 35, 0x08, 1, [(46, rng.randbytes(sk_len))]), True, t); t += rng.uniform(0.020, 0.120)
        self._ike_udp(ikev2_message(self.ike_spi_i, self.ike_spi_r, 35, 0x20, 1, [(46, rng.randbytes(sk_len - 16))]), False, t); t += rng.uniform(0.005, 0.030)
        self.ground_truth_ike = {"selected_proposal": {"cipher": chosen[0], "integrity": chosen[1], "dh_group": chosen[2]}, "offered": proposals}
        return t

    def _ikev2_rekey(self, t: float) -> float:
        cfg, rng = self.cfg, self.rng
        ke = 8 + DH_KE_BYTES.get(cfg.dh_group, 256) if cfg.pfs_enabled else 0
        sk_len = 16 + 60 + 36 + ke + 24 + 24 + 12
        self._ike_udp(ikev2_message(self.ike_spi_i, self.ike_spi_r, 36, 0x08, 2, [(46, rng.randbytes(sk_len))]), True, t); t += rng.uniform(0.010, 0.060)
        self._ike_udp(ikev2_message(self.ike_spi_i, self.ike_spi_r, 36, 0x20, 2, [(46, rng.randbytes(sk_len))]), False, t); t += rng.uniform(0.005, 0.030)
        return t

    def _ikev1(self, t: float) -> float:
        cfg, rng = self.cfg, self.rng
        auth = {"PSK": 1, "RSA-SIG": 3, "XAUTH-PSK": 65001}.get(cfg.auth_method, 1)
        transforms = [ikev1_transform(1, cfg.encryption if cfg.protocol == "ESP" else "AES-256-CBC", cfg.integrity if cfg.integrity != "AEAD" else "HMAC-SHA2-256", cfg.dh_group, auth, cfg.ike_lifetime_seconds)]
        sa = ikev1_sa_payload(transforms)
        ke_len = DH_KE_BYTES.get(cfg.dh_group, 128)
        if cfg.ike_version == "1.0-aggressive":
            # Aggressive Mode: SA, KE, Nonce, ID in the clear (RFC 2409 §5.4)
            ident = struct.pack("!BBH", 3, 0, 0) + b"vpn-client.example.org"
            self._ike_udp(ikev1_message(self.ike_spi_i, bytes(8), 4, 0, [(1, sa), (4, rng.randbytes(ke_len)), (10, rng.randbytes(20)), (5, ident)]), True, t); t += rng.uniform(0.02, 0.08)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 4, 0, [(1, sa), (4, rng.randbytes(ke_len)), (10, rng.randbytes(20)), (5, ident), (8, rng.randbytes(16 if "MD5" in cfg.integrity else 20))]), False, t); t += rng.uniform(0.02, 0.08)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 4, 0x01, [], encrypted_len=40, rng=rng), True, t); t += rng.uniform(0.01, 0.05)
        else:
            # Main Mode: 1-2 SA, 3-4 KE + Nonce, 5-6 encrypted ID/HASH
            self._ike_udp(ikev1_message(self.ike_spi_i, bytes(8), 2, 0, [(1, sa), (13, rng.randbytes(16))]), True, t); t += rng.uniform(0.02, 0.08)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 2, 0, [(1, sa), (13, rng.randbytes(16))]), False, t); t += rng.uniform(0.02, 0.08)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 2, 0, [(4, rng.randbytes(ke_len)), (10, rng.randbytes(20))]), True, t); t += rng.uniform(0.02, 0.08)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 2, 0, [(4, rng.randbytes(ke_len)), (10, rng.randbytes(20))]), False, t); t += rng.uniform(0.02, 0.08)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 2, 0x01, [], encrypted_len=56, rng=rng), True, t); t += rng.uniform(0.01, 0.05)
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 2, 0x01, [], encrypted_len=56, rng=rng), False, t); t += rng.uniform(0.01, 0.05)
        # Quick Mode (Phase 2) is encrypted; with PFS the first two messages carry a KE payload (RFC 2409 §5.5)
        mid = rng.randint(1, 0xFFFFFFF)
        qm_len = 184 + ((ke_len + 4) if cfg.pfs_enabled else 0)
        for i, from_a in enumerate((True, False, True)):
            self._ike_udp(ikev1_message(self.ike_spi_i, self.ike_spi_r, 32, 0x01, [], message_id=mid, encrypted_len=(qm_len if i < 2 else 56), rng=rng), from_a, t); t += rng.uniform(0.01, 0.05)
        self.ground_truth_ike = {"selected_proposal": {"cipher": cfg.encryption, "integrity": cfg.integrity, "dh_group": cfg.dh_group}, "auth_method": cfg.auth_method, "lifetime_seconds": cfg.ike_lifetime_seconds}
        return t

    # ---- data plane -----------------------------------------------------------------------

    def _inner_packet(self, ip: InnerPacket) -> Tuple[bytes, int]:
        """Return (bytes, next_header) for the payload that goes inside ESP/AH."""
        v6 = self.cfg.ip_version == 6
        src, dst = (self.inner_a, self.inner_b) if ip.uplink else (self.inner_b, self.inner_a)
        payload = bytes(self.rng.getrandbits(8) for _ in range(min(ip.payload_len, 64))) + bytes(max(0, ip.payload_len - 64))
        if ip.transport == "udp":
            seg, proto = udp(payload, ip.sport, ip.dport), 17
        elif ip.transport == "tcp":
            seq = self.rng.randint(1, 2**31)
            seg, proto = tcp(payload, ip.sport, ip.dport, seq, seq + 1, ip.flags), 6
        else:
            seg, proto = icmp_echo(payload, 0x1234, ip.icmp_seq, reply=ip.reply, v6=v6), (58 if v6 else 1)
        if self.cfg.mode == "TRANSPORT":
            return seg, proto
        inner = ipv6(seg, proto, src, dst) if v6 else ipv4(seg, proto, src, dst, ident=self.rng.randint(1, 65535))
        return inner, (41 if v6 else 4)

    def _esp_pair(self) -> Tuple[ESPSecurityAssociation, ESPSecurityAssociation]:
        spi_a, spi_b = self.rng.randint(0x10000, 0xFFFFFFFF), self.rng.randint(0x10000, 0xFFFFFFFF)
        self.spis += [spi_a, spi_b]
        tfc = 1200 if self.cfg.tfc_padding else None
        return (ESPSecurityAssociation(spi_a, self.cfg.encryption, self.cfg.integrity, self.rng, tfc),
                ESPSecurityAssociation(spi_b, self.cfg.encryption, self.cfg.integrity, self.rng, tfc))

    def _emit_data(self, pkts: List[InnerPacket], t_base: float, rekey_at: Optional[float]) -> None:
        cfg = self.cfg
        if cfg.protocol == "AH":
            ah_a = AHSecurityAssociation(self.rng.randint(0x10000, 0xFFFFFFFF), cfg.integrity if cfg.integrity != "AEAD" else "HMAC-SHA2-256", self.rng)
            ah_b = AHSecurityAssociation(self.rng.randint(0x10000, 0xFFFFFFFF), cfg.integrity if cfg.integrity != "AEAD" else "HMAC-SHA2-256", self.rng)
            self.spis += [ah_a.spi, ah_b.spi]
            for ip in pkts:
                inner, nh = self._inner_packet(ip)
                sa = ah_a if ip.uplink else ah_b
                src, dst = (self.outer_a, self.outer_b) if ip.uplink else (self.outer_b, self.outer_a)
                hdr = sa.header(nh)
                icv = sa.icv(hdr + inner)
                self._emit(self._outer(hdr + icv + inner, 51, src, dst, ident=self.rng.randint(1, 65535)), t_base + ip.t)
            return
        sa_a, sa_b = self._esp_pair()
        rekeyed = False
        for ip in pkts:
            if rekey_at is not None and not rekeyed and ip.t >= rekey_at:
                self._ikev2_rekey(t_base + ip.t - 0.002) if cfg.ike_version == "2.0" else None
                sa_a, sa_b = self._esp_pair()
                rekeyed = True
            inner, nh = self._inner_packet(ip)
            sa = sa_a if ip.uplink else sa_b
            src, dst = (self.outer_a, self.outer_b) if ip.uplink else (self.outer_b, self.outer_a)
            esp = sa.encapsulate(inner, nh)
            if cfg.nat_traversal:
                self._emit(self._outer(udp(esp, 4500, 4500), 17, src, dst, ident=self.rng.randint(1, 65535)), t_base + ip.t)
            else:
                self._emit(self._outer(esp, 50, src, dst, ident=self.rng.randint(1, 65535)), t_base + ip.t)

    # ---- entry point ----------------------------------------------------------------------

    def generate(self, include_ike: bool = True, include_delete: bool = True) -> GeneratedCapture:
        cfg = self.cfg
        t = self.t0
        self.ground_truth_ike: Dict[str, Any] = {}
        if include_ike:
            t = self._ikev1(t) if cfg.ike_version.startswith("1") else self._ikev2(t)
        t_data = t + self.rng.uniform(0.05, 0.4)
        model = TRAFFIC_MODELS[self.traffic_type](self.rng, self.duration)
        pkts = sorted(model.packets, key=lambda p: p.t)
        rekey_at = (self.duration * self.rng.uniform(0.45, 0.7)) if (cfg.rekey and include_ike and cfg.ike_version == "2.0" and cfg.protocol == "ESP") else None
        self._emit_data(pkts, t_data, rekey_at)
        t_end = t_data + (pkts[-1].t if pkts else 0.0)
        if include_ike and include_delete and cfg.ike_version == "2.0":
            t_end += self.rng.uniform(0.2, 1.5)
            self._ike_udp(ikev2_message(self.ike_spi_i, self.ike_spi_r, 37, 0x08, 3, [(46, self.rng.randbytes(40))]), True, t_end)
            self._ike_udp(ikev2_message(self.ike_spi_i, self.ike_spi_r, 37, 0x20, 3, [(46, self.rng.randbytes(24))]), False, t_end + 0.02)
        self.frames.sort(key=lambda f: f[1])
        data = pcap(self.frames)
        capture_id = hashlib.sha256(data).hexdigest()
        cs = CIPHER_SPECS[cfg.encryption]
        truth = {
            "profile_id": cfg.profile_id, "profile_name": cfg.name, "seed": self.seed, "capture_id": capture_id,
            "ike_version": cfg.ike_version.split("-")[0] if include_ike else None, "ike_exchange_mode": ("AGGRESSIVE" if cfg.ike_version == "1.0-aggressive" else ("MAIN" if cfg.ike_version.startswith("1") else "IKE_SA_INIT/IKE_AUTH")) if include_ike else None,
            "ipsec_protocol": cfg.protocol, "mode": cfg.mode, "ip_version": cfg.ip_version, "nat_traversal": cfg.nat_traversal,
            "encryption": cfg.encryption, "cipher_family": cs["family"], "key_length": cs["key_bytes"] * 8 if cs["key_bytes"] else None,
            "aead": cs["aead"], "integrity": cfg.integrity, "dh_group": cfg.dh_group, "pfs_enabled": cfg.pfs_enabled,
            "rekey_observed": rekey_at is not None, "tfc_padding": cfg.tfc_padding, "downgrade": cfg.downgrade, "weak_fallback_offer": cfg.weak_fallback_offer,
            "traffic_type": model.label, "traffic_parameters": model.parameters, "duration_seconds": self.duration,
            "spis": [f"0x{s:08x}" for s in self.spis], "ike": self.ground_truth_ike, "ike_included": include_ike,
            "generator": "software_testbed", "synthetic": True,
            "note": "Application traffic is model-generated; IPsec framing and encryption are real (RFC 4303 / RFC 4106 / RFC 3602 / RFC 7296).",
        }
        name = f"testbed_{cfg.profile_id.lower()}_{model.label.lower()}_s{self.seed}.pcap"
        return GeneratedCapture(data, truth, len(self.frames), name)


def generate_capture(profile_id: str, seed: int = 1, traffic_type: Optional[str] = None, duration: Optional[float] = None,
                     include_ike: bool = True) -> GeneratedCapture:
    cfg = profile_by_id(profile_id)
    if cfg is None:
        raise ValueError(f"Unknown testbed profile '{profile_id}'")
    return SoftwareTestbed(cfg, seed=seed, traffic_type=traffic_type, duration=duration).generate(include_ike=include_ike)


def ground_truth_json(capture: GeneratedCapture) -> str:
    return json.dumps(capture.ground_truth, indent=2, sort_keys=True)
