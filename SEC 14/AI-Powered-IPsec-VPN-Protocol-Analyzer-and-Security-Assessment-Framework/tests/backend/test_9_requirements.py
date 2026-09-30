"""Automated Test Suite for All 9 Advanced Requirements.

Validates:
1. Transport Mode (AH next header, IKEv2 USE_TRANSPORT_MODE, Session ipsec_mode, RuleTransportModeExposure)
2. IPv6 Communication (IPv6 extension header decoding, ip_version, RuleIPv6ExtensionHeaderRisk)
3. VoIP Traffic Analysis (20ms cadence, small symmetric frames, G.107 MOS estimate, AI classification)
4. WhatsApp-type Traffic Analysis (burstiness, keepalive gaps, low pps, AI classification)
5. E-Mail Traffic Analysis (command-response handshake + bulk train, AI classification)
6. Video-Streaming Traffic Analysis (periodic chunk downloads, heavy downlink asymmetry, MTU packets)
7. AI Traffic-Type Prediction Inside ESP (probabilities, confidence, explainability, API endpoints)
8. Metadata Exposure Assessment (5 leak vectors, TFC padding check, recommendations, API endpoints)
9. Standalone Threat Matrix (10 threats mapped to MITRE ATT&CK & NIST SP 800-77, compliance score, API endpoints)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import json
import packet_builders as B
import synthetic_traffic_generator as STG
from app.api.router import api_router
from app.db.base import SessionLocal
from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer08_ai_ml.traffic_classifier import FlowFeatures, TrafficClassifier, TrafficClassificationService
from app.layers.layer09_vulnerability_engine.metadata_exposure import MetadataExposureService
from app.layers.layer09_vulnerability_engine.rules.protocol_rules import (
    RuleIPv6ExtensionHeaderRisk,
    RuleTFCMissingPadding,
    RuleTransportModeExposure,
)
from app.layers.layer09_vulnerability_engine.threat_matrix import THREAT_DEFINITIONS, ThreatMatrixService
from app.models.ipsec_session import IPsecSession
from app.models.metadata_exposure import MetadataExposureRow
from app.models.threat_matrix import ThreatMatrixRow
from app.models.traffic_classification import TrafficClassificationRow
from app.services.packet_service import packet_service
from app.services.session_service import session_service


# ==============================================================================
# Requirement 1: Transport Mode
# ==============================================================================

def test_requirement_1_transport_mode_decoding_and_session(client: TestClient) -> None:
    """Validate Transport mode detection in AH, IKEv2 USE_TRANSPORT_MODE, session ipsec_mode, and exposure rule."""
    # 1. AH packet with inner UDP
    ah_frames = STG.build_transport_mode_ah_frames(count=4)
    pcap_bytes = STG.timed_pcap(ah_frames)
    _, results = analyze_capture(pcap_bytes)

    assert len(results) == 4
    for r in results:
        assert r.ipsec is not None
        assert r.ipsec.encapsulation_mode == "TRANSPORT"
        assert r.protocol == "AH"

    # 2. IKEv2 exchange with USE_TRANSPORT_MODE notify (16391)
    ike_frames = STG.build_ikev2_transport_exchange()
    ike_pcap = B.pcap(ike_frames)
    _, ike_results = analyze_capture(ike_pcap)
    assert len(ike_results) == 2
    for r in ike_results:
        assert r.ipsec is not None and r.ipsec.ike is not None
        notify_types = [p.notify_type for p in r.ipsec.ike.payloads if p.type_number == 41]
        assert 16391 in notify_types

    # 3. Ingest through packet_service and session_service
    client.post("/api/packets/upload", files={"file": ("transport.pcap", pcap_bytes, "application/octet-stream")})
    client.post("/api/sessions/discover")

    sessions = client.get("/api/sessions").json()["items"]
    transport_sessions = [s for s in sessions if s.get("ipsec_mode") == "TRANSPORT"]
    assert len(transport_sessions) >= 1
    session_id = transport_sessions[0]["id"]

    # 4. Vulnerability engine RuleTransportModeExposure
    with SessionLocal() as db:
        session_row = db.get(IPsecSession, session_id)
        assert session_row is not None
        rule = RuleTransportModeExposure()
        vuln = rule.evaluate_session(session_row, [])
        assert vuln is not None
        assert vuln.rule_id == "RULE-PROTO-004"
        assert vuln.severity == "MEDIUM"


# ==============================================================================
# Requirement 2: IPv6 Communication
# ==============================================================================

def test_requirement_2_ipv6_extension_headers_and_rule(client: TestClient) -> None:
    """Validate IPv6 extension header parsing, ip_version tracking, and RuleIPv6ExtensionHeaderRisk."""
    # 1. Build IPv6 frames with Hop-by-Hop and Routing headers
    ipv6_frames = STG.build_ipv6_esp_with_ext_headers(count=6)
    pcap_bytes = STG.timed_pcap(ipv6_frames)
    _, results = analyze_capture(pcap_bytes)

    assert len(results) == 6
    for r in results:
        assert r.ip.version == 6
        assert "Hop-by-Hop Options" in r.ip.extension_headers
        assert any("Routing" in h for h in r.ip.extension_headers)
        assert r.protocol == "ESP"

    # 2. Ingest through pipeline
    client.post("/api/packets/upload", files={"file": ("ipv6_ext.pcap", pcap_bytes, "application/octet-stream")})
    client.post("/api/sessions/discover")

    sessions = client.get("/api/sessions").json()["items"]
    ipv6_sessions = [s for s in sessions if s.get("ip_version") in (6, "IPv6") or "6" in str(s.get("ip_version"))]
    assert len(ipv6_sessions) >= 1
    session_id = ipv6_sessions[0]["id"]

    # 3. Test RuleIPv6ExtensionHeaderRisk
    with SessionLocal() as db:
        session_row = db.get(IPsecSession, session_id)
        assert session_row is not None
        rule = RuleIPv6ExtensionHeaderRisk()
        vuln = rule.evaluate_session(session_row, results)
        assert vuln is not None
        assert vuln.rule_id == "RULE-PROTO-005"
        assert vuln.severity == "MEDIUM"
        assert "Hop-by-Hop Options" in vuln.description


# ==============================================================================
# Requirement 3: VoIP Traffic Analysis (20ms Cadence, MOS Score)
# ==============================================================================

def test_requirement_3_voip_analysis_and_mos() -> None:
    """Validate VoIP pattern extraction: 20ms interval, small packet ratio, high MOS score, and AI classification."""
    voip_frames = STG.build_voip_traffic(count=80)
    pcap_bytes = STG.timed_pcap(voip_frames)
    _, results = analyze_capture(pcap_bytes)

    assert len(results) == 80

    # Build flow features directly
    flow = FlowFeatures.from_packets(results)
    assert flow.packet_count == 80
    assert flow.small_packet_ratio >= 0.95
    assert flow.mtu_packet_ratio <= 0.05
    assert flow.iat_coefficient_of_variation < 0.40  # Tight 20ms cadence
    assert flow.mos_score_estimate >= 4.0  # Quality VoIP MOS > 4.0

    # Test Classifier
    classifier = TrafficClassifier()
    pred = classifier.classify(flow)
    assert pred.predicted_type == "VOIP"
    assert pred.confidence >= 0.70
    assert pred.probabilities["VOIP"] > 0.60
    assert "20ms" in pred.explanation.lower() or "cadence" in pred.explanation.lower() or "mos" in pred.explanation.lower()


# ==============================================================================
# Requirement 4: WhatsApp-type Traffic Analysis (Bursts + Keepalives)
# ==============================================================================

def test_requirement_4_whatsapp_traffic_analysis() -> None:
    """Validate WhatsApp-type pattern: conversational bursts, idle keepalive gaps, low pps, AI classification."""
    wa_frames = STG.build_whatsapp_traffic(burst_count=5, packets_per_burst=4)
    pcap_bytes = STG.timed_pcap(wa_frames)
    _, results = analyze_capture(pcap_bytes)

    assert len(results) == 20

    flow = FlowFeatures.from_packets(results)
    assert flow.packet_count == 20
    assert flow.small_packet_ratio >= 0.70
    assert flow.iat_coefficient_of_variation > 1.0  # High variance due to idle gaps
    assert flow.packets_per_second < 10.0  # Low overall pps

    classifier = TrafficClassifier()
    pred = classifier.classify(flow)
    assert pred.predicted_type == "WHATSAPP"
    assert pred.confidence >= 0.60
    assert pred.probabilities["WHATSAPP"] > 0.50
    assert "conversational" in pred.explanation.lower() or "burst" in pred.explanation.lower()


# ==============================================================================
# Requirement 5: E-Mail Traffic Analysis (Command-Response + Bulk Train)
# ==============================================================================

def test_requirement_5_email_traffic_analysis() -> None:
    """Validate E-Mail pattern: two-phase handshake and bulk unidirectional MTU train, AI classification."""
    email_frames = STG.build_email_traffic(bulk_packet_count=35)
    pcap_bytes = STG.timed_pcap(email_frames)
    _, results = analyze_capture(pcap_bytes)

    assert len(results) >= 40

    flow = FlowFeatures.from_packets(results)
    assert flow.packet_count >= 40
    assert flow.mtu_packet_ratio > 0.40  # Bulk train contains MTU packets
    assert flow.direction_asymmetry > 0.40  # Bulk transfer is primarily in one direction

    classifier = TrafficClassifier()
    pred = classifier.classify(flow)
    assert pred.predicted_type == "EMAIL"
    assert pred.confidence >= 0.60
    assert pred.probabilities["EMAIL"] > 0.50
    assert "email" in pred.explanation.lower() or "bulk" in pred.explanation.lower() or "handshake" in pred.explanation.lower()


# ==============================================================================
# Requirement 6: Video-Streaming Traffic Analysis (Periodic Chunks + Asymmetry)
# ==============================================================================

def test_requirement_6_video_streaming_traffic_analysis() -> None:
    """Validate Video-Streaming pattern: periodic chunk bursts, downlink asymmetry, MTU packets, AI classification."""
    video_frames = STG.build_video_streaming_traffic(chunk_count=4, packets_per_chunk=25)
    pcap_bytes = STG.timed_pcap(video_frames)
    _, results = analyze_capture(pcap_bytes)

    assert len(results) >= 100

    flow = FlowFeatures.from_packets(results)
    assert flow.packet_count >= 100
    assert flow.mtu_packet_ratio > 0.40
    assert flow.chunk_burst_periodicity is not None
    assert 1.0 <= flow.chunk_burst_periodicity <= 3.0  # Periodic chunk bursts detected ~1.5s apart

    classifier = TrafficClassifier()
    pred = classifier.classify(flow)
    assert pred.predicted_type == "VIDEO_STREAMING"
    assert pred.confidence >= 0.60
    assert pred.probabilities["VIDEO_STREAMING"] > 0.50
    assert "video" in pred.explanation.lower() or "chunk" in pred.explanation.lower()


# ==============================================================================
# Requirement 7: AI Traffic-Type Prediction Pipeline & API
# ==============================================================================

def test_requirement_7_ai_traffic_classification_service_and_api(client: TestClient) -> None:
    """Validate TrafficClassificationService end-to-end and REST API endpoints."""
    # Upload VoIP pcap
    voip_frames = STG.build_voip_traffic(count=50)
    pcap_bytes = STG.timed_pcap(voip_frames)
    client.post("/api/packets/upload", files={"file": ("voip_ai.pcap", pcap_bytes, "application/octet-stream")})
    client.post("/api/sessions/discover")

    sessions = client.get("/api/sessions").json()["items"]
    assert len(sessions) > 0
    target_id = sessions[0]["id"]

    # Test classify via service
    with SessionLocal() as db:
        session = db.get(IPsecSession, target_id)
        assert session is not None
        svc = TrafficClassificationService(db)
        classification = svc.classify_session(session)
        assert classification is not None
        assert classification.session_id == target_id
        assert classification.traffic_type == "VOIP"
        assert classification.confidence >= 0.50
        probs = json.loads(classification.probabilities_json)
        assert len(probs) == 5
        assert sum(probs.values()) == pytest.approx(1.0, abs=0.01)

    # Test REST API GET /api/traffic-analysis/session/{session_id}
    resp = client.get(f"/api/traffic-analysis/session/{target_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == target_id
    assert data["traffic_type"] == "VOIP"
    assert "mos_score_estimate" in data["features"]

    # Test REST API GET /api/traffic-analysis/distribution
    dist_resp = client.get("/api/traffic-analysis/distribution")
    assert dist_resp.status_code == 200
    dist_data = dist_resp.json()
    assert "VOIP" in dist_data["distribution"]
    assert dist_data["total_classified"] >= 1


# ==============================================================================
# Requirement 8: Metadata Exposure Assessment Pipeline & API
# ==============================================================================

def test_requirement_8_metadata_exposure_assessment_and_api(client: TestClient) -> None:
    """Validate Metadata Exposure assessment across 5 leak vectors, TFC rule, and REST API."""
    # Upload video pcap (has high length variability and no TFC padding)
    video_frames = STG.build_video_streaming_traffic(chunk_count=3, packets_per_chunk=15)
    pcap_bytes = STG.timed_pcap(video_frames)
    client.post("/api/packets/upload", files={"file": ("metadata_exp.pcap", pcap_bytes, "application/octet-stream")})
    client.post("/api/sessions/discover")

    sessions = client.get("/api/sessions").json()["items"]
    target_id = sessions[0]["id"]

    # Assess metadata exposure via service
    with SessionLocal() as db:
        session = db.get(IPsecSession, target_id)
        assert session is not None
        svc = MetadataExposureService(db)
        report = svc.assess_session(session)
        assert report is not None
        assert report.session_id == target_id
        assert 0.0 <= report.overall_score <= 100.0
        assert 0.0 <= report.spi_leakage_score <= 100.0
        assert 0.0 <= report.packet_length_leakage_score <= 100.0
        assert 0.0 <= report.timing_leakage_score <= 100.0
        assert 0.0 <= report.topology_leakage_score <= 100.0
        recs = json.loads(report.recommendations_json)
        assert len(recs) > 0

    # Test RuleTFCMissingPadding
    packets = packet_service.all_packets()
    rule = RuleTFCMissingPadding()
    with SessionLocal() as db:
        session_row = db.get(IPsecSession, target_id)
        assert session_row is not None
        vuln = rule.evaluate_session(session_row, packets)
        assert vuln is not None
        assert vuln.rule_id == "RULE-PROTO-006"

    # Test REST API GET /api/metadata-exposure/session/{session_id}
    resp = client.get(f"/api/metadata-exposure/session/{target_id}")
    assert resp.status_code == 200
    assert resp.json()["overall_score"] == pytest.approx(report.overall_score, abs=0.1)

    # Test REST API GET /api/metadata-exposure/summary
    sum_resp = client.get("/api/metadata-exposure/summary")
    assert sum_resp.status_code == 200
    assert sum_resp.json()["total_assessed"] >= 1


# ==============================================================================
# Requirement 9: Standalone Threat Matrix Pipeline & API
# ==============================================================================

def test_requirement_9_standalone_threat_matrix_and_api(client: TestClient) -> None:
    """Validate Standalone Threat Matrix: 10 threats, MITRE/NIST mapping, compliance score, and REST API."""
    sessions = client.get("/api/sessions").json()["items"]
    assert len(sessions) > 0
    target_id = sessions[0]["id"]

    # Evaluate threats via service
    with SessionLocal() as db:
        session = db.get(IPsecSession, target_id)
        assert session is not None
        svc = ThreatMatrixService(db)
        matrix = svc.get_by_capture(session.capture_id)
        summary = svc.get_summary(session.capture_id)
        assert len(matrix) == 10  # All 10 standalone threats evaluated
        assert 0.0 <= summary["compliance_score"] <= 100.0

        for entry in matrix:
            assert entry.matrix_id.startswith("TM-IPSEC-")
            assert entry.mitre_technique_id.startswith("T")
            assert entry.status in ("DETECTED", "VULNERABLE", "MITIGATED", "NOT_APPLICABLE")
            assert len(entry.remediation) > 0

    # Test REST API GET /api/threat-matrix/threats (Catalog)
    cat_resp = client.get("/api/threat-matrix/threats")
    assert cat_resp.status_code == 200
    catalog = cat_resp.json()
    assert len(catalog) == 10
    threat_ids = [t["matrix_id"] for t in catalog]
    assert "TM-IPSEC-001" in threat_ids
    assert "TM-IPSEC-008" in threat_ids
    assert "TM-IPSEC-010" in threat_ids

    # Test REST API GET /api/threat-matrix/session/{session_id}
    eval_resp = client.get(f"/api/threat-matrix/session/{target_id}")
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["session_id"] == target_id
    assert len(eval_data["threats"]) == 10

    # Test REST API GET /api/threat-matrix/summary
    sum_resp = client.get("/api/threat-matrix/summary")
    assert sum_resp.status_code == 200
    assert sum_resp.json()["total_threats"] == 10
