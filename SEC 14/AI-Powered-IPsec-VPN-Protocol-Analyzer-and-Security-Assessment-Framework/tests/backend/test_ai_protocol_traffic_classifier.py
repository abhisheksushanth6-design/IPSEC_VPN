"""Unit and integration tests for Layer 07 AI-Based Protocol & Traffic Classification.

Validates SIH Problem Statement 26160 requirements:
A. IPsec Protocol Identification
B. IKE Identification (version, exchanges, SPIs)
C. VPN Mode Identification (Tunnel vs Transport) — with provenance
D. Cryptographic Configuration Identification (AES-128, AES-256, AES-GCM, DH, PFS) — with provenance
E. Security Association Characteristics
F. Encrypted Traffic Classification (VoIP, WhatsApp, Web, Email, ICMP, Video, Other)
G. Calibrated AI Confidence Scores that drop when evidence is missing

Traffic flows come from the software testbed (real RFC 4303 ESP framing, real encryption) with seeds
that were never used to build the training dataset, so these are held-out samples of the deployed model.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import synthetic_traffic_generator as STG
from app.db.base import SessionLocal
from app.layers.layer01_test_environment.software_testbed import TRAFFIC_TYPES, generate_capture
from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer08_ai_ml.traffic_classifier import FEATURE_NAMES, FlowFeatures, TrafficClassifier
from app.models.ipsec_session import IPsecSession
from app.services.packet_service import packet_service

HELD_OUT_SEED = 90001
PROFILE = "PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4"


@pytest.mark.parametrize("traffic_type", TRAFFIC_TYPES)
def test_ai_traffic_classification_all_sih_categories(traffic_type: str) -> None:
    """Every SIH traffic category is recognised on a held-out testbed flow, from packets alone."""
    cap = generate_capture(PROFILE, seed=HELD_OUT_SEED, traffic_type=traffic_type, include_ike=False)
    _, results = analyze_capture(cap.pcap_bytes)
    flow = FlowFeatures.from_packets(results)

    assert flow.provenance == "PACKETS"
    assert len(flow.vector()) == len(FEATURE_NAMES) == 22

    pred = TrafficClassifier.classify(flow)
    assert pred.predicted_type == traffic_type
    assert pred.abstained is False
    assert pred.confidence >= 0.50
    assert pred.model_version is not None, "the supervised bundle must be loaded, not the rules alone"
    assert sum(pred.probabilities.values()) == pytest.approx(1.0, abs=0.01)
    assert set(pred.probabilities) == set(TRAFFIC_TYPES)
    assert pred.explanations, "each prediction carries an explanation trail"


def test_classifier_abstains_without_data_plane_packets() -> None:
    """No ESP/AH packets → no guess: the classifier abstains instead of fabricating a class."""
    empty = FlowFeatures.from_packets([], session_id="S-EMPTY")
    assert empty.packet_count == 0
    pred = TrafficClassifier.classify(empty)
    assert pred.abstained is True
    assert pred.predicted_type == "OTHER"
    assert pred.confidence == 0.0


def test_uncertainty_gate_weights_rules_up_when_model_is_unsure() -> None:
    """The ensemble weight of the physical-signature rules rises as the model's top probability falls."""
    assert TrafficClassifier._rule_weight(0.95) == TrafficClassifier.RULE_WEIGHT_WITH_MODEL
    assert TrafficClassifier._rule_weight(0.40) == TrafficClassifier.RULE_WEIGHT_MODEL_UNSURE
    mid = TrafficClassifier._rule_weight(0.65)
    assert TrafficClassifier.RULE_WEIGHT_WITH_MODEL < mid < TrafficClassifier.RULE_WEIGHT_MODEL_UNSURE


def _load(client: TestClient, filename: str, pcap: bytes) -> str:
    resp = client.post("/api/packets/upload", files={"file": (filename, pcap, "application/octet-stream")})
    assert resp.status_code == 201, resp.text
    client.post("/api/sessions/discover")
    client.post("/api/sas/discover")
    with SessionLocal() as db:
        rows = db.scalars(select(IPsecSession).where(IPsecSession.capture_id == packet_service.capture_id)).all()
    assert rows
    return max(rows, key=lambda s: s.packet_count).id


def test_ai_protocol_traffic_comprehensive_analysis_esp_only(client: TestClient) -> None:
    """ESP-only capture: the engine identifies IPsec and the traffic, and says what it cannot see."""
    session_id = _load(client, "voip_test.pcap", STG.timed_pcap(STG.build_voip_traffic(count=40)))

    res = client.get(f"/api/traffic-analysis/comprehensive/{session_id}")
    assert res.status_code == 200
    data = res.json()

    # A. Protocol identification is read from the wire.
    assert data["protocol_identification"]["is_ipsec"] is True
    assert data["protocol_identification"]["confidence"] >= 0.90
    assert data["protocol_identification"]["provenance"] == "OBSERVED"
    assert len(data["protocol_identification"]["evidence"]) > 0

    # B. No IKE in the capture → not detected, not invented.
    assert data["ike_identification"]["detected"] is False
    assert data["ike_identification"]["provenance"] == "UNAVAILABLE"

    # C. Mode: ESP hides the inner header, so TUNNEL is an ASSUMED default with a low confidence.
    mode = data["vpn_mode_identification"]
    assert mode["mode"] in ("TUNNEL", "TRANSPORT")
    assert mode["provenance"] in ("ASSUMED", "INFERRED")
    assert mode["confidence"] < 0.80

    # D. Crypto: nothing negotiated in cleartext → INFERRED from ESP framing or UNAVAILABLE, never a fabricated suite.
    crypto = data["crypto_configuration"]
    assert crypto["provenance"] in ("INFERRED", "UNAVAILABLE")
    assert crypto["confidence"] < 0.70
    assert crypto["pfs"]["status"] == "UNKNOWN"

    # E. SA characteristics come from the observed SPIs and sequence numbers.
    assert "observed_spis" in data["sa_characteristics"]
    assert data["sa_characteristics"]["replay_protection_active"] is True

    # F. Traffic classification still works on the data plane alone.
    assert data["traffic_classification"]["predicted_type"] == "VOIP"
    assert data["traffic_classification"]["confidence"] >= 0.70

    # G. Overall confidence reflects the missing evidence instead of claiming certainty.
    assert 0.30 <= data["overall_ai_confidence"] < 0.90
    assert "confidence_breakdown" in data


def test_ai_protocol_traffic_comprehensive_analysis_with_ike(client: TestClient) -> None:
    """IKEv2 + ESP capture from the testbed: IKE, cipher suite and DH group are OBSERVED with high confidence."""
    cap = generate_capture(PROFILE, seed=HELD_OUT_SEED + 1, duration=30.0)
    session_id = _load(client, cap.filename, cap.pcap_bytes)
    truth = cap.ground_truth

    data = client.get(f"/api/traffic-analysis/comprehensive/{session_id}").json()

    ike = data["ike_identification"]
    assert ike["detected"] is True
    assert ike["provenance"] == "OBSERVED"
    assert str(ike["version"]).startswith("2")
    assert ike["initiator_spi"]

    crypto = data["crypto_configuration"]
    assert crypto["provenance"] == "OBSERVED"
    assert crypto["confidence"] >= 0.85
    assert "GCM" in crypto["cipher"].upper()
    assert crypto["key_size_bits"] == 256
    assert "19" in crypto["dh_group"]
    assert crypto["downgrade"]["detected"] is False
    assert crypto["pfs"]["status"] != "DISABLED", "a PFS-enabled profile must never be reported as DISABLED"

    assert data["traffic_classification"]["predicted_type"] == truth["traffic_type"]
    assert data["overall_ai_confidence"] >= 0.75
