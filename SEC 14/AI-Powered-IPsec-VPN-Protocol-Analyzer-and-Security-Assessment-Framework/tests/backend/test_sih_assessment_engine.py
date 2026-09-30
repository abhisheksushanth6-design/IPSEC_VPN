"""Regression tests for the SIH 26160 analysis engine additions.

Covers the software testbed (real RFC 4303 ESP framing + real encryption, registered ground truth), the
cleartext negotiation extractor, proposal-downgrade detection, ESP framing / PFS / transport-mode
inference with their "never confidently wrong" guarantees, per-SPI replay analysis, the what-if
remediation simulator, the published compliance profiles, the traffic-aware metadata exposure, the
threat matrix and the PDF report section.
"""

from __future__ import annotations

import base64
import json
import re
import struct
import zlib
from typing import List, Optional, Tuple

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from app.db.base import SessionLocal
from app.layers.layer01_test_environment.software_testbed import DEFAULT_PROFILES, TRAFFIC_TYPES, generate_capture, profile_by_id
from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer03_protocol_analysis.crypto_negotiation import extract_negotiated_crypto
from app.layers.layer04_sa_lifecycle.replay_analysis import analyze_replay
from app.layers.layer08_ai_ml.crypto_inference import infer_esp_crypto, infer_pfs, infer_transport_mode
from app.layers.layer08_ai_ml.dataset_builder import META_COLUMNS, TRAINING_PROFILES, features_from_pcap
from app.layers.layer08_ai_ml.traffic_classifier import _MODEL_PATH, FEATURE_NAMES, TrafficClassifier
from app.layers.layer09_vulnerability_engine.compliance_profiles import evaluate_profiles
from app.layers.layer09_vulnerability_engine.rules import ALL_RULES
from app.models.ipsec_session import IPsecSession
from app.services.packet_service import packet_service

# What each decisive framing outcome may stand for: AES-CBC is separable, everything with an 8-byte IV is not.
FAMILY_BY_HYPOTHESIS = {"CBC-16": {"AES-CBC"}, "CTR-OR-CBC-8": {"AES-GCM", "CHACHA20", "3DES"}}


# --------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------

def _family(encryption: str) -> str:
    enc = encryption.upper()
    if enc.startswith("AES") and "GCM" in enc:
        return "AES-GCM"
    if enc.startswith("AES"):
        return "AES-CBC"
    if enc.startswith("3DES"):
        return "3DES"
    if enc.startswith("CHACHA"):
        return "CHACHA20"
    return "NULL"


def _key_bits(encryption: str) -> Optional[int]:
    m = re.search(r"AES-(\d+)", encryption.upper())
    return int(m.group(1)) if m else None


def _load(client: TestClient, cap) -> Tuple[str, str]:
    resp = client.post("/api/packets/upload", files={"file": (cap.filename, cap.pcap_bytes, "application/octet-stream")})
    assert resp.status_code == 201, resp.text
    client.post("/api/sessions/discover")
    client.post("/api/sas/discover")
    capture_id = packet_service.capture_id
    with SessionLocal() as db:
        rows = db.scalars(select(IPsecSession).where(IPsecSession.capture_id == capture_id)).all()
    assert rows, "no session discovered for the loaded capture"
    return max(rows, key=lambda s: s.packet_count).id, capture_id


def _duplicate_records(pcap: bytes, every: int = 7) -> bytes:
    """Append every N-th pcap record a second time — a replayed ESP frame with the same sequence number."""
    magic = struct.unpack("<I", pcap[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    out = bytearray(pcap[:24])
    pos, idx = 24, 0
    while pos + 16 <= len(pcap):
        _, _, incl, _ = struct.unpack(endian + "IIII", pcap[pos:pos + 16])
        record = pcap[pos:pos + 16 + incl]
        out += record
        idx += 1
        if idx % every == 0:
            out += record
        pos += 16 + incl
    return bytes(out)


def _pdf_text(pdf: bytes) -> str:
    """Concatenate the literal strings of every content stream (ReportLab: ASCII85 + Flate encoded)."""
    chunks: List[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        raw = m.group(1).strip()
        try:
            data = base64.a85decode(raw if raw.startswith(b"<~") else b"<~" + raw, adobe=True)
        except ValueError:
            data = raw
        try:
            data = zlib.decompress(data)
        except zlib.error:
            pass
        chunks.extend(s.decode("latin-1") for s in re.findall(rb"\((.*?)(?<!\\)\)", data))
    return " ".join(chunks)


# --------------------------------------------------------------------------------------------------
# software testbed
# --------------------------------------------------------------------------------------------------

def test_software_testbed_covers_problem_statement_matrix() -> None:
    """The profiles span tunnel/transport, AES-128/256, GCM/CBC+HMAC, DH groups, PFS on/off, IPv4/IPv6 and IKEv1/v2."""
    assert {p.mode for p in DEFAULT_PROFILES} == {"TUNNEL", "TRANSPORT"}
    assert {"AES-GCM", "AES-CBC", "3DES", "CHACHA20"} <= {_family(p.encryption) for p in DEFAULT_PROFILES}
    assert {128, 256} <= {_key_bits(p.encryption) for p in DEFAULT_PROFILES if _key_bits(p.encryption)}
    assert {p.pfs_enabled for p in DEFAULT_PROFILES} == {True, False}
    assert {p.ip_version for p in DEFAULT_PROFILES} == {4, 6}
    assert {p.ike_version.split("-")[0] for p in DEFAULT_PROFILES} == {"1.0", "2.0"}
    assert len({p.dh_group for p in DEFAULT_PROFILES}) >= 4
    assert any(p.protocol == "AH" for p in DEFAULT_PROFILES)
    assert any(p.nat_traversal for p in DEFAULT_PROFILES) and any(p.tfc_padding for p in DEFAULT_PROFILES)
    assert set(TRAFFIC_TYPES) == {"VOIP", "WHATSAPP", "EMAIL", "WEB_BROWSING", "ICMP", "VIDEO_STREAMING", "OTHER"}


def test_generated_capture_is_deterministic_and_parses() -> None:
    a = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=11, duration=8.0)
    b = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=11, duration=8.0)
    c = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=12, duration=8.0)
    assert a.pcap_bytes == b.pcap_bytes
    assert a.pcap_bytes != c.pcap_bytes
    _, results = analyze_capture(a.pcap_bytes)
    assert {"IKE", "ESP"} <= {r.protocol for r in results}
    assert a.ground_truth["encryption"].startswith("AES-256")
    assert a.ground_truth["pfs_enabled"] is True
    assert a.ground_truth["cipher_family"] == "AES-GCM"
    assert a.packet_count == len(results)


def test_testbed_api_generates_loads_and_registers_ground_truth(client: TestClient) -> None:
    profiles = client.get("/api/environment/testbed-profiles").json()
    software = [p for p in profiles if p.get("software_testbed")]
    assert {p["id"] for p in software} == {p.profile_id for p in DEFAULT_PROFILES}

    resp = client.post("/api/environment/simulate-profile/PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4?seed=5&duration=12")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["packets_loaded"] > 0
    assert body["sessions_discovered"] >= 1
    assert body["ground_truth"]["encryption"].startswith("3DES")
    capture_id = body["capture_id"]

    truth = client.get(f"/api/environment/ground-truth/{capture_id}")
    assert truth.status_code == 200
    assert truth.json()["profile_id"] == "PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4"
    assert truth.json()["pfs_enabled"] is False

    listed = client.get("/api/environment/generated-captures").json()
    assert any(item["capture_id"] == capture_id for item in listed)
    assert client.get("/api/environment/ground-truth/does-not-exist").status_code == 404
    assert client.post("/api/environment/simulate-profile/NO-SUCH-PROFILE").status_code == 404


# --------------------------------------------------------------------------------------------------
# negotiation extraction, downgrade detection, inference guarantees
# --------------------------------------------------------------------------------------------------

def test_negotiated_crypto_is_extracted_from_cleartext_ikev2_and_ikev1() -> None:
    _, v2 = analyze_capture(generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=21, duration=6.0).pcap_bytes)
    nego = extract_negotiated_crypto(v2)
    assert nego.provenance == "OBSERVED"
    assert nego.selection_basis == "RESPONDER_SA_PAYLOAD"
    assert nego.selection_confirmed is True
    assert "GCM" in nego.cipher.upper() and nego.key_length == 256
    assert nego.dh_group_number == 19
    assert nego.downgrade is None or nego.downgrade.detected is False
    assert nego.security_bits >= 128
    assert nego.ke_dh_groups == [19] or 19 in nego.ke_dh_groups

    _, v1 = analyze_capture(generate_capture("PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4", seed=22, duration=6.0).pcap_bytes)
    old = extract_negotiated_crypto(v1)
    assert old.provenance == "OBSERVED"
    assert old.ike_version.startswith("1")
    assert "3DES" in old.cipher.upper()
    assert old.dh_group_number == 2
    assert old.lifetime_seconds is not None and old.lifetime_seconds > 0
    assert old.security_bits <= 112


def test_proposal_downgrade_is_detected_with_weak_offered_transforms() -> None:
    _, pkts = analyze_capture(generate_capture("PROFILE-07-TUNNEL-DOWNGRADE-IPV4", seed=23, duration=6.0).pcap_bytes)
    nego = extract_negotiated_crypto(pkts)
    assert nego.downgrade is not None and nego.downgrade.detected is True
    assert nego.downgrade.best_offered_bits > nego.downgrade.selected_bits
    assert nego.downgrade.reason
    assert len(nego.offered_proposals) >= 2
    assert nego.weak_offered


@pytest.mark.parametrize("profile", [p.profile_id for p in DEFAULT_PROFILES if p.protocol == "ESP"])
def test_esp_framing_inference_is_never_confidently_wrong(profile: str) -> None:
    cfg = profile_by_id(profile)
    assert cfg is not None
    cap = generate_capture(profile, seed=31, duration=25.0, include_ike=False, traffic_type="WEB_BROWSING")
    _, pkts = analyze_capture(cap.pcap_bytes)
    inf = infer_esp_crypto(pkts)
    assert inf.provenance in ("INFERRED", "UNAVAILABLE")
    assert inf.null_encryption_suspected is False, "real encryption must not look like ESP-NULL"
    if inf.confidence >= 0.50:
        assert _family(cfg.encryption) in FAMILY_BY_HYPOTHESIS[inf.framing_hypothesis], (
            f"{profile}: decisive hypothesis {inf.framing_hypothesis} contradicts ground truth {cfg.encryption}")


def test_esp_framing_inference_is_decisive_for_cbc_and_aead_web_flows() -> None:
    """With enough distinct frame sizes the framing arithmetic separates CBC-16 from AEAD/CTR framing."""
    _, cbc = analyze_capture(generate_capture("PROFILE-02-TRANSPORT-AES128CBC-PFS-IPV4", seed=33, duration=30.0, include_ike=False, traffic_type="WEB_BROWSING").pcap_bytes)
    _, gcm = analyze_capture(generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=33, duration=30.0, include_ike=False, traffic_type="WEB_BROWSING").pcap_bytes)
    a, b = infer_esp_crypto(cbc), infer_esp_crypto(gcm)
    assert a.framing_hypothesis == "CBC-16" and a.confidence >= 0.50
    assert b.framing_hypothesis == "CTR-OR-CBC-8" and b.confidence >= 0.50
    assert b.legacy_block_cipher_suspected is False, "3DES cannot be told from AEAD by framing, so it must not be claimed"
    assert a.payload_entropy_bits is None or a.payload_entropy_bits > 7.0


def test_esp_framing_inference_abstains_on_tfc_padded_frames() -> None:
    """Quantised (TFC-padded) frame sizes carry no cipher information and must not yield a decisive call."""
    _, pkts = analyze_capture(generate_capture("PROFILE-10-TUNNEL-TFC-PADDED-IPV4", seed=31, duration=25.0, include_ike=False, traffic_type="WEB_BROWSING").pcap_bytes)
    inf = infer_esp_crypto(pkts)
    assert inf.framing_hypothesis is None
    assert inf.confidence < 0.50
    assert any("TFC padding" in e for e in inf.evidence)


def test_esp_null_is_flagged_by_low_payload_entropy() -> None:
    cap = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=32, duration=10.0, include_ike=False, traffic_type="EMAIL")
    _, pkts = analyze_capture(cap.pcap_bytes)
    # Overwrite every ESP payload with a low-entropy pattern — what ESP-NULL carrying text looks like.
    pattern = bytes([0x41, 0x42, 0x43, 0x0A])
    for p in pkts:
        if p.ipsec is not None and p.ipsec.esp is not None and p.raw is not None and not p.raw.truncated:
            frame = bytes.fromhex(p.raw.hex)
            n = p.ipsec.esp.payload_length
            if 0 < n <= len(frame):
                filler = (pattern * (n // 4 + 1))[:n]
                p.raw.hex = (frame[:-n] + filler).hex()
    inf = infer_esp_crypto(pkts)
    assert inf.payload_entropy_bits is not None and inf.payload_entropy_bits < 3.0
    assert inf.null_encryption_suspected is True


@pytest.mark.parametrize("profile,expect", [("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", True), ("PROFILE-03-TUNNEL-AES128GCM-NOPFS-IPV4", False),
                                            ("PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4", False)])
def test_pfs_inference_never_contradicts_ground_truth(profile: str, expect: bool) -> None:
    _, pkts = analyze_capture(generate_capture(profile, seed=41, duration=40.0).pcap_bytes)
    pfs = infer_pfs(pkts)
    assert pfs.status in ("ENABLED", "DISABLED", "UNKNOWN")
    if pfs.status != "UNKNOWN":
        assert (pfs.status == "ENABLED") is expect
        assert pfs.provenance == "INFERRED"
        assert pfs.evidence


def test_transport_mode_inference_from_bare_ack_sizes() -> None:
    """Bare TCP ACKs sit at IV+pad(22)+ICV in transport mode and IV+pad(42)+ICV behind an inner IPv4 header."""
    _, transport = analyze_capture(generate_capture("PROFILE-02-TRANSPORT-AES128CBC-PFS-IPV4", seed=51, duration=20.0, include_ike=False, traffic_type="WEB_BROWSING").pcap_bytes)
    _, tunnel = analyze_capture(generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=51, duration=20.0, include_ike=False, traffic_type="WEB_BROWSING").pcap_bytes)
    t = infer_transport_mode(transport, infer_esp_crypto(transport).framing_hypothesis)
    u = infer_transport_mode(tunnel, infer_esp_crypto(tunnel).framing_hypothesis)
    assert t.mode == "TRANSPORT" and t.confidence >= 0.60 and t.provenance == "INFERRED"
    assert t.matched_length == 64  # 16-byte IV + 32 (22 padded to the block) + 16-byte ICV
    # Tunnel mode is never *proven* by lengths (a 42-byte transport segment has the same size as a tunnel ACK).
    assert u.mode == "UNKNOWN" and u.confidence == 0.0
    assert u.matched_length == 68  # 8-byte IV + 44 (42 padded to 4) + 16-byte ICV: consistent with tunnel, not proof
    assert "inner IP header" in u.evidence[0]

    # A tunnel-mode voice flow has no frame small enough to be a transport segment: UNKNOWN, not a guess.
    _, voice = analyze_capture(generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=52, duration=20.0, include_ike=False, traffic_type="VOIP").pcap_bytes)
    v = infer_transport_mode(voice, "CTR-OR-CBC-8")
    assert v.mode == "UNKNOWN" and v.confidence == 0.0
    # A transport-mode voice flow may or may not carry ≤ 22-byte codec frames, but it is never called TUNNEL.
    _, tvoice = analyze_capture(generate_capture("PROFILE-02-TRANSPORT-AES128CBC-PFS-IPV4", seed=52, duration=20.0, include_ike=False, traffic_type="VOIP").pcap_bytes)
    assert infer_transport_mode(tvoice, "CBC-16").mode in ("TRANSPORT", "UNKNOWN")

    # A 32-byte ICV (HMAC-SHA2-512-256) makes the transport ACK collide with a 16-byte-ICV tunnel ACK (both 80
    # bytes): ambiguous without the negotiation, resolved once the negotiated ICV length is supplied.
    _, sha512 = analyze_capture(generate_capture("PROFILE-04-TRANSPORT-AES256CBC-PFS-IPV6", seed=53, duration=20.0, include_ike=False, traffic_type="WEB_BROWSING").pcap_bytes)
    assert infer_transport_mode(sha512, "CBC-16").mode == "UNKNOWN"
    resolved = infer_transport_mode(sha512, "CBC-16", icv_length=32)
    assert resolved.mode == "TRANSPORT" and resolved.matched_length == 80


def test_icv_length_from_transform_names() -> None:
    from app.layers.layer08_ai_ml.crypto_inference import icv_length_for

    assert icv_length_for("AES-GCM", "AEAD") == 16
    assert icv_length_for("AES-CBC", "HMAC-SHA1-96") == 12
    assert icv_length_for("AES-CBC", "AUTH_HMAC_SHA2_256_128") == 16
    assert icv_length_for("AES-CBC", "HMAC-SHA2-512-256") == 32
    assert icv_length_for(None, None) is None


def test_replay_analysis_per_spi_detects_duplicates() -> None:
    clean = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=61, duration=15.0, include_ike=False, traffic_type="VOIP").pcap_bytes
    _, pkts = analyze_capture(clean)
    good = analyze_replay(pkts)
    assert good.verdict == "PROTECTED"
    assert good.total_duplicates == 0
    assert len(good.streams) >= 1
    assert good.sender_counter_integrity == "VERIFIED"
    assert good.esn_observable is False

    _, replayed = analyze_capture(_duplicate_records(clean, every=7))
    bad = analyze_replay(replayed)
    assert bad.verdict == "REPLAY_INDICATORS"
    assert bad.total_duplicates >= 1
    assert bad.sender_counter_integrity == "VIOLATED"


# --------------------------------------------------------------------------------------------------
# API-level behaviour: assessment, what-if, compliance, metadata, threat matrix, reports
# --------------------------------------------------------------------------------------------------

def test_replay_indicators_surface_as_finding_and_threat(client: TestClient) -> None:
    cap = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=62, duration=15.0, include_ike=False, traffic_type="VOIP")
    cap.pcap_bytes = _duplicate_records(cap.pcap_bytes, every=5)
    session_id, _ = _load(client, cap)
    sa = client.get(f"/api/security-assessment/comprehensive/{session_id}").json()
    assert sa["replay_protection"]["verdict"] == "REPLAY_INDICATORS"
    assert sa["replay_protection"]["duplicates_count"] >= 1
    assert any(f.get("rule_id") == "RULE-SA-004" for f in sa["explainable_findings"])
    tm = client.get(f"/api/threat-matrix/session/{session_id}").json()
    replay_threats = [t for t in tm["threats"] if "replay" in t.get("name", "").lower()]
    assert replay_threats and replay_threats[0]["status"] in ("VULNERABLE", "DETECTED")


def test_downgrade_capture_yields_rule_crypto_006(client: TestClient) -> None:
    cap = generate_capture("PROFILE-07-TUNNEL-DOWNGRADE-IPV4", seed=71, duration=20.0)
    session_id, _ = _load(client, cap)
    ai = client.get(f"/api/traffic-analysis/comprehensive/{session_id}").json()
    assert ai["crypto_configuration"]["downgrade"]["detected"] is True
    sa = client.get(f"/api/security-assessment/comprehensive/{session_id}").json()
    ids = [f.get("rule_id") for f in sa["explainable_findings"]]
    assert ids.count("RULE-CRYPTO-006") == 1


def test_ah_transport_mode_is_observed(client: TestClient) -> None:
    cap = generate_capture("PROFILE-08-TRANSPORT-AH-SHA256-IPV4", seed=81, duration=15.0)
    session_id, _ = _load(client, cap)
    ai = client.get(f"/api/traffic-analysis/comprehensive/{session_id}").json()
    mode = ai["vpn_mode_identification"]
    assert mode["mode"] == "TRANSPORT"
    assert mode["provenance"] == "OBSERVED"
    assert mode["confidence"] >= 0.90
    assert "AH" in ai["protocol_identification"]["protocol_type"].upper()


def test_what_if_simulator_rescoring(client: TestClient) -> None:
    cap = generate_capture("PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4", seed=91, duration=20.0)
    session_id, _ = _load(client, cap)

    resp = client.post(f"/api/security-assessment/what-if/{session_id}",
                       json={"cipher": "AES-GCM-256", "dh_group": 19, "pfs_enabled": True, "ike_version": "2.0", "integrity": "AEAD", "prf": "SHA2-256"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["baseline"]["crypto_grade"] == "F"
    assert body["simulated"]["crypto_grade"] in ("A+", "A")
    assert body["simulated"]["overall_security_score"] > body["baseline"]["overall_security_score"] + 15
    assert body["delta"]["overall_security_score"] == pytest.approx(
        body["simulated"]["overall_security_score"] - body["baseline"]["overall_security_score"], abs=0.11)
    assert len(body["simulated"]["violations"]) < len(body["baseline"]["violations"])
    assert set(body["overrides_applied"]) >= {"cipher", "dh_group", "pfs_enabled", "ike_version"}
    assert body["simulated"]["profiles"]["IETF-BASELINE"] in ("COMPLIANT", "PARTIALLY_COMPLIANT")

    # Nothing was written back: the stored session still carries the observed suite.
    sa = client.get(f"/api/security-assessment/comprehensive/{session_id}").json()
    assert sa["cryptographic_strength"]["grade"] == "F"

    assert client.post(f"/api/security-assessment/what-if/{session_id}", json={"ike_version": "3.0"}).status_code == 422
    assert client.post("/api/security-assessment/what-if/NOPE", json={"pfs_enabled": True}).status_code == 404


def test_compliance_profiles_unit() -> None:
    strong = {"cipher": "AES-GCM", "key_length": 256, "integrity": "AEAD", "prf": "HMAC-SHA2-384", "dh_group_number": 20,
              "dh_group": "Group 20 (ECP-384)", "pfs_enabled": True, "pfs_provenance": "INFERRED", "ike_version": "2.0",
              "crypto_provenance": "OBSERVED", "esp_family": None, "esp_null_suspected": False, "esp_legacy_block_suspected": False}
    results = {r.profile_id: r for r in evaluate_profiles(strong)}
    assert set(results) == {"IETF-BASELINE", "NIST-SP800-77R1", "CNSA-1.0"}
    assert results["CNSA-1.0"].status == "COMPLIANT"
    assert results["IETF-BASELINE"].status == "COMPLIANT"
    assert results["NIST-SP800-77R1"].status == "COMPLIANT"

    weak = dict(strong, cipher="3DES", key_length=168, integrity="HMAC-MD5-96", prf="HMAC-MD5", dh_group_number=2,
                dh_group="Group 2 (MODP-1024)", pfs_enabled=False, ike_version="1.0")
    weak_results = {r.profile_id: r for r in evaluate_profiles(weak)}
    assert all(r.status == "NON_COMPLIANT" for r in weak_results.values())
    assert any(c.status == "FAIL" for c in weak_results["IETF-BASELINE"].checks)

    unknown = dict(strong, cipher=None, key_length=None, integrity=None, prf=None, dh_group_number=None, dh_group=None,
                   pfs_enabled=None, pfs_provenance="UNAVAILABLE", crypto_provenance="UNAVAILABLE", ike_version=None)
    unknown_results = {r.profile_id: r for r in evaluate_profiles(unknown)}
    assert all(r.status == "NOT_ASSESSABLE" for r in unknown_results.values())
    assert all(r.coverage == 0.0 for r in unknown_results.values())


def test_metadata_exposure_is_traffic_aware(client: TestClient) -> None:
    cap = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=101, duration=20.0, include_ike=False, traffic_type="VOIP")
    session_id, capture_id = _load(client, cap)
    client.get(f"/api/traffic-analysis/comprehensive/{session_id}")  # stores the traffic prediction
    sa = client.get(f"/api/security-assessment/comprehensive/{session_id}").json()
    meta = sa["metadata_exposure"]
    assert meta["exposure_level"] in ("LOW", "MEDIUM", "HIGH")
    ctx = meta.get("traffic_context") or {}
    if ctx.get("applied"):
        assert ctx["traffic_type"] == "VOIP"
        assert ctx["attack_classes"]
    me = client.get(f"/api/metadata-exposure/session/{session_id}")
    assert me.status_code == 200
    assert client.get(f"/api/metadata-exposure/evaluate/{capture_id}").status_code == 200


def test_reports_include_security_assessment_engine_section(client: TestClient) -> None:
    cap = generate_capture("PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4", seed=111, duration=15.0)
    session_id, _ = _load(client, cap)
    client.get(f"/api/security-assessment/comprehensive/{session_id}")

    for report_type, min_pages in (("TECHNICAL", 6), ("EXECUTIVE", 3)):
        gen = client.post("/api/reports/generate", json={"report_type": report_type})
        assert gen.status_code in (200, 201), gen.text
        body = gen.json()
        assert body["page_count"] >= min_pages
        pdf = client.get(f"/api/reports/{body['id']}/download")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")
        text = _pdf_text(pdf.content)
        assert "Security Assessment Engine" in text
        assert "SECURITY SCORE" in text
        assert "3DES" in text


# --------------------------------------------------------------------------------------------------
# dataset / model provenance
# --------------------------------------------------------------------------------------------------

def test_dataset_features_come_from_the_deployed_pipeline() -> None:
    cap = generate_capture("PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4", seed=121, duration=10.0, traffic_type="EMAIL")
    flow, packet_count = features_from_pcap(cap.pcap_bytes)
    feats = dict(zip(FEATURE_NAMES, flow.vector()))
    assert len(feats) == len(FEATURE_NAMES) == 22
    assert feats["packet_count"] > 0 and packet_count > 0
    assert flow.provenance == "PACKETS"
    assert set(TRAINING_PROFILES) < {p.profile_id for p in DEFAULT_PROFILES}
    assert "traffic_type" in META_COLUMNS


def test_supervised_bundle_matches_feature_vector_and_metrics_are_honest() -> None:
    loaded = TrafficClassifier.get_supervised_model()
    assert loaded is not None
    _, feature_names, version = loaded
    assert list(feature_names) == list(FEATURE_NAMES)
    assert version

    metrics = json.loads((_MODEL_PATH.parent / "traffic_metrics.json").read_text(encoding="utf-8"))
    assert metrics["feature_vector_version"] == "2.0"
    assert "held_out_configuration" in metrics
    assert metrics["held_out_configuration"]["accuracy"] <= metrics["test_accuracy"] + 1e-9
    assert "No real user traffic" in metrics["dataset"]["provenance"]


def test_rule_registry_contains_the_new_rules() -> None:
    ids = {rule.rule_id for rule in ALL_RULES}
    assert {"RULE-CRYPTO-006", "RULE-CRYPTO-007", "RULE-CRYPTO-008", "RULE-SA-004"} <= ids
