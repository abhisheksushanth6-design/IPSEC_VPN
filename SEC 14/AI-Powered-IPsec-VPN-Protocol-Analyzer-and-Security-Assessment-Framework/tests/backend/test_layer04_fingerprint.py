"""Layer 04: SA Lifecycle & Session Fingerprinting Test Suite.

Verifies:
- Correlation of IKE, ESP, and AH packets into logical VPN sessions
- Stable, deterministic SHA-256 fingerprint generation
- Change sensitivity / tamper-evidence of the session signature
- Inactivity gap session boundary separation
- Layer 04 service self-verification reporting READY
- FastAPI endpoints (/api/sessions/fingerprints, /api/sessions/fingerprints/{id})
- Dynamic Layer 4 READY reporting in /api/system/status
"""

from __future__ import annotations

import io
import pytest

from packet_builders import ah, esp, ethernet, ikev2, ipv4, pcap, udp

from app.layers.layer03_protocol_analysis.models import (
    ESPLayer,
    IKELayer,
    IKEProposal,
    IKETransform,
    IPLayer,
    IPsecAnalysis,
    PacketAnalysisResult,
)
from app.layers.layer04_sa_lifecycle.models import (
    SessionFingerprintComponents,
    VPNSessionFingerprint,
)
from app.layers.layer04_sa_lifecycle.service import (
    Layer04Service,
    get_layer04_service,
)
from app.layers.layer04_sa_lifecycle.session_correlator import (
    correlate_sessions_and_fingerprint,
)


def _build_test_ike_esp_packets() -> list[PacketAnalysisResult]:
    """Helper to synthesize IKE and ESP packets belonging to one VPN session."""
    p1 = PacketAnalysisResult(
        id="pkt-1",
        number=1,
        timestamp="1700000000.0",
        length=200,
        source="192.168.10.1",
        destination="192.168.20.1",
        protocol="IKE",
        ip=IPLayer(version=4, source="192.168.10.1", destination="192.168.20.1", protocol_number=17, protocol_name="UDP", total_length=200, ttl=64),
        ipsec=IPsecAnalysis(
            type="IKE",
            ike=IKELayer(
                version="IKEv2",
                major_version=2,
                minor_version=0,
                exchange_type=34,
                exchange_name="IKE_SA_INIT",
                initiator_spi="0102030405060708",
                responder_spi="0000000000000000",
                message_id=0,
                flags=["Initiator"],
                proposals=[
                    IKEProposal(
                        proposal_number=1,
                        protocol_id=1,
                        protocol_name="IKE",
                        encryption_algorithms=["AES-CBC-256"],
                        integrity_algorithms=["HMAC-SHA2-256-128"],
                        prf_algorithms=["PRF_HMAC_SHA2_256"],
                        dh_groups=["2048-bit MODP (Group 14)"],
                    )
                ],
            ),
        ),
    )
    p2 = PacketAnalysisResult(
        id="pkt-2",
        number=2,
        timestamp="1700000001.0",
        length=140,
        source="192.168.10.1",
        destination="192.168.20.1",
        protocol="ESP",
        ip=IPLayer(version=4, source="192.168.10.1", destination="192.168.20.1", protocol_number=50, protocol_name="ESP", total_length=140, ttl=64),
        ipsec=IPsecAnalysis(
            type="ESP",
            esp=ESPLayer(
                spi="0x12345678",
                sequence_number=1,
                payload_length=100,
            ),
        ),
    )
    p3 = PacketAnalysisResult(
        id="pkt-3",
        number=3,
        timestamp="1700000002.0",
        length=140,
        source="192.168.20.1",
        destination="192.168.10.1",
        protocol="ESP",
        ip=IPLayer(version=4, source="192.168.20.1", destination="192.168.10.1", protocol_number=50, protocol_name="ESP", total_length=140, ttl=64),
        ipsec=IPsecAnalysis(
            type="ESP",
            esp=ESPLayer(
                spi="0x87654321",
                sequence_number=1,
                payload_length=100,
            ),
        ),
    )
    return [p1, p2, p3]


# =============================================================================
# Unit Tests: Correlation & Fingerprinting
# =============================================================================

def test_session_correlation_single_session() -> None:
    packets = _build_test_ike_esp_packets()
    sessions = correlate_sessions_and_fingerprint(packets, capture_id="test_cap")

    assert len(sessions) == 1
    s = sessions[0]
    assert s.initiator_ip == "192.168.10.1"
    assert s.responder_ip == "192.168.20.1"
    assert s.endpoint_pair == ["192.168.10.1", "192.168.20.1"]
    assert "IKE" in s.protocols
    assert "ESP" in s.protocols
    assert s.total_packets == 3
    assert s.ike_packets == 1
    assert s.esp_packets == 2
    assert s.total_bytes == 480
    assert s.duration_seconds == 2.0
    assert "0x12345678" in s.child_sa_spis
    assert "0x87654321" in s.child_sa_spis
    assert s.state == "ACTIVE"


def test_session_fingerprint_determinism() -> None:
    packets = _build_test_ike_esp_packets()
    runs_1 = correlate_sessions_and_fingerprint(packets, capture_id="cap_a")
    runs_2 = correlate_sessions_and_fingerprint(packets, capture_id="cap_a")

    assert len(runs_1) == 1
    assert len(runs_2) == 1

    fp1 = runs_1[0]
    fp2 = runs_2[0]

    assert fp1.fingerprint == fp2.fingerprint
    assert len(fp1.fingerprint) == 64
    assert fp1.short_signature == fp1.fingerprint[:16]
    assert fp1.short_signature == fp2.short_signature


def test_session_fingerprint_change_sensitivity() -> None:
    """Modifying session properties must produce a different cryptographic signature."""
    packets_a = _build_test_ike_esp_packets()
    packets_b = _build_test_ike_esp_packets()

    # Change ESP SPI in packets_b
    assert packets_b[1].ipsec and packets_b[1].ipsec.esp
    packets_b[1].ipsec.esp.spi = "0x99999999"

    sessions_a = correlate_sessions_and_fingerprint(packets_a, capture_id="cap")
    sessions_b = correlate_sessions_and_fingerprint(packets_b, capture_id="cap")

    assert sessions_a[0].fingerprint != sessions_b[0].fingerprint


def test_inactivity_gap_splits_sessions() -> None:
    """Packets separated by > 300 seconds must be split into separate sessions."""
    packets = _build_test_ike_esp_packets()

    # Add 4th packet with timestamp 1000s later
    p4 = PacketAnalysisResult(
        id="pkt-4",
        number=4,
        timestamp="1700001000.0",
        length=140,
        source="192.168.10.1",
        destination="192.168.20.1",
        protocol="ESP",
        ip=IPLayer(version=4, source="192.168.10.1", destination="192.168.20.1", protocol_number=50, protocol_name="ESP", total_length=140, ttl=64),
        ipsec=IPsecAnalysis(
            type="ESP",
            esp=ESPLayer(spi="0x12345678", sequence_number=2, payload_length=100),
        ),
    )
    packets.append(p4)

    sessions = correlate_sessions_and_fingerprint(packets, capture_id="split_cap")
    assert len(sessions) == 2


# =============================================================================
# Unit Tests: Layer 4 Service & Status
# =============================================================================

def test_layer04_self_verification_and_ready_status() -> None:
    svc = Layer04Service()
    verified = svc.verify_engine()
    assert verified is True, "Layer 04 engine self-verification failed"
    assert svc.get_layer_status() == "READY"


# =============================================================================
# Integration Tests: FastAPI Endpoints
# =============================================================================

def test_fastapi_session_fingerprints_endpoints(client) -> None:
    # 1. Generate synthetic pcap with IKE and ESP packets
    f1 = ethernet(ipv4(udp(ikev2(), 500, 500), proto=17, src="192.168.10.1", dst="192.168.20.1"))
    f2 = ethernet(ipv4(esp(spi=0x12345678, seq=1), proto=50, src="192.168.10.1", dst="192.168.20.1"))
    pcap_data = pcap([f1, f2])

    # Upload capture
    upload_res = client.post(
        "/api/packets/upload",
        files={"file": ("test_layer4.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
    )
    assert upload_res.status_code == 201

    # Test GET /api/sessions/fingerprints
    res = client.get("/api/sessions/fingerprints")
    assert res.status_code == 200
    data = res.json()
    assert "total_sessions" in data
    assert data["total_sessions"] >= 1
    assert data["status"] == "READY"

    sessions = data["sessions"]
    assert len(sessions) >= 1
    s = sessions[0]
    assert "fingerprint" in s
    assert len(s["fingerprint"]) == 64
    assert "short_signature" in s
    assert "endpoint_pair" in s
    assert "protocols" in s

    # Test GET /api/sessions/fingerprints/{session_id}
    res_detail = client.get(f"/api/sessions/fingerprints/{s['session_id']}")
    assert res_detail.status_code == 200
    assert res_detail.json()["session_id"] == s["session_id"]

    # Test Layer 4 in GET /api/system/status
    res_sys = client.get("/api/system/status")
    assert res_sys.status_code == 200
    sys_data = res_sys.json()
    layer4 = next(l for l in sys_data["architecture_layers"] if l["number"] == 4)
    assert layer4["status"] == "READY"
