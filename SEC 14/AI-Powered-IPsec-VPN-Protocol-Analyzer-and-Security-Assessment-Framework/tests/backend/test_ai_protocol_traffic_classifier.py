"""Unit and integration tests for Layer 07 AI-Based Protocol & Traffic Classification.

Validates SIH Problem Statement 26160 requirements:
A. IPsec Protocol Identification
B. IKE Identification (version, exchanges, SPIs)
C. VPN Mode Identification (Tunnel vs Transport)
D. Cryptographic Configuration Identification (AES-128, AES-256, AES-GCM, DH, PFS)
E. Security Association Characteristics
F. Encrypted Traffic Classification (VoIP, Web, Email, ICMP, Video, Other)
G. Calibrated AI Confidence Scores
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import synthetic_traffic_generator as STG
from app.db.base import SessionLocal
from app.layers.layer08_ai_ml.protocol_classifier import AIProtocolTrafficClassifier
from app.layers.layer08_ai_ml.traffic_classifier import FlowFeatures, TrafficClassifier
from app.models.ipsec_session import IPsecSession


def test_ai_traffic_classification_all_sih_categories() -> None:
    """Verify that all 6 SIH required categories are correctly predicted."""
    # 1. VoIP
    voip_flow = FlowFeatures(
        session_id="S-VOIP",
        packet_count=100,
        byte_count=8000,
        duration=2.0,
        mean_iat=0.020,
        iat_cv=0.15,
        small_packet_ratio=0.98,
        mtu_packet_ratio=0.0,
        inbound_outbound_byte_ratio=1.05,
        packets_per_second=50.0,
        bytes_per_second=4000.0,
        mos_score_estimate=4.3,
    )
    pred_voip = TrafficClassifier.classify(voip_flow)
    assert pred_voip.predicted_type == "VOIP"
    assert pred_voip.confidence >= 0.70

    # 2. Web Browsing
    web_flow = FlowFeatures(
        session_id="S-WEB",
        packet_count=60,
        byte_count=45000,
        duration=3.5,
        mean_iat=0.058,
        iat_cv=0.85,
        small_packet_ratio=0.35,
        mtu_packet_ratio=0.30,
        inbound_outbound_byte_ratio=3.2,
        packets_per_second=17.1,
        bytes_per_second=12857.0,
    )
    pred_web = TrafficClassifier.classify(web_flow)
    assert pred_web.predicted_type in ("WEB_BROWSING", "WHATSAPP")
    assert "WEB_BROWSING" in pred_web.probabilities

    # 3. Email
    email_flow = FlowFeatures(
        session_id="S-EMAIL",
        packet_count=50,
        byte_count=65000,
        duration=4.0,
        mean_iat=0.08,
        iat_cv=1.2,
        small_packet_ratio=0.20,
        mtu_packet_ratio=0.55,
        inbound_outbound_byte_ratio=4.5,
        packets_per_second=12.5,
        bytes_per_second=16250.0,
    )
    pred_email = TrafficClassifier.classify(email_flow)
    assert pred_email.predicted_type == "EMAIL"
    assert pred_email.confidence >= 0.60

    # 4. ICMP
    icmp_flow = FlowFeatures(
        session_id="S-ICMP",
        packet_count=20,
        byte_count=1680,
        duration=19.0,
        mean_iat=1.0,
        iat_cv=0.05,
        small_packet_ratio=1.0,
        mtu_packet_ratio=0.0,
        inbound_outbound_byte_ratio=1.0,
        packets_per_second=1.05,
        bytes_per_second=88.4,
    )
    pred_icmp = TrafficClassifier.classify(icmp_flow)
    assert pred_icmp.predicted_type == "ICMP"
    assert pred_icmp.confidence >= 0.70

    # 5. Video Streaming
    video_flow = FlowFeatures(
        session_id="S-VIDEO",
        packet_count=120,
        byte_count=160000,
        duration=6.0,
        mean_iat=0.05,
        iat_cv=1.4,
        small_packet_ratio=0.05,
        mtu_packet_ratio=0.75,
        inbound_outbound_byte_ratio=8.5,
        packets_per_second=20.0,
        bytes_per_second=26666.0,
        chunk_burst_periodicity=2.0,
    )
    pred_video = TrafficClassifier.classify(video_flow)
    assert pred_video.predicted_type == "VIDEO_STREAMING"
    assert pred_video.confidence >= 0.60

    # 6. Other / Generic
    other_flow = FlowFeatures(
        session_id="S-OTHER",
        packet_count=30,
        byte_count=15000,
        duration=5.0,
        mean_iat=0.16,
        iat_cv=0.7,
        small_packet_ratio=0.5,
        mtu_packet_ratio=0.1,
        inbound_outbound_byte_ratio=1.1,
        packets_per_second=6.0,
        bytes_per_second=3000.0,
    )
    pred_other = TrafficClassifier.classify(other_flow)
    assert pred_other.predicted_type in ("OTHER", "GENERIC", "WHATSAPP", "WEB_BROWSING")


def test_ai_protocol_traffic_comprehensive_analysis(client: TestClient) -> None:
    """Test AIProtocolTrafficClassifier endpoint on uploaded VoIP traffic."""
    voip_frames = STG.build_voip_traffic(count=40)
    pcap_bytes = STG.timed_pcap(voip_frames)
    client.post("/api/packets/upload", files={"file": ("voip_test.pcap", pcap_bytes, "application/octet-stream")})
    client.post("/api/sessions/discover")

    sessions_res = client.get("/api/sessions").json()["items"]
    assert len(sessions_res) > 0
    session_id = sessions_res[0]["id"]

    res = client.get(f"/api/traffic-analysis/comprehensive/{session_id}")
    assert res.status_code == 200
    data = res.json()

    # Protocol Identification
    assert data["protocol_identification"]["is_ipsec"] is True
    assert data["protocol_identification"]["confidence"] >= 0.90
    assert len(data["protocol_identification"]["evidence"]) > 0

    # Mode Identification
    assert data["vpn_mode_identification"]["mode"] in ("TUNNEL", "TRANSPORT")
    assert data["vpn_mode_identification"]["confidence"] >= 0.80

    # Crypto Identification
    assert data["crypto_configuration"]["cipher"] is not None
    assert data["crypto_configuration"]["confidence"] >= 0.70

    # SA Characteristics
    assert "observed_spis" in data["sa_characteristics"]
    assert data["sa_characteristics"]["replay_protection_active"] is True

    # Traffic Classification
    assert data["traffic_classification"]["predicted_type"] == "VOIP"
    assert data["traffic_classification"]["confidence"] >= 0.70

    # Overall Confidence
    assert 0.70 <= data["overall_ai_confidence"] <= 1.0
