"""Layer 3: IPsec/IKE/ESP Protocol Analysis Test Suite.

Verifies:
- IKE negotiation and proposal parsing (IKEv1 and IKEv2 algorithms)
- ESP/AH streams, SPI tracking, sequence analysis (replays, seq=0, gaps)
- Tunnel endpoint discovery and traffic aggregation
- Protocol anomaly detection (weak crypto, seq replay, seq zero, cleartext)
- Layer 3 system status self-verification reporting READY
- FastAPI endpoints (/api/packets/protocol-analysis, /anomalies, /streams, /tunnel-endpoints, /ike-proposals)
"""

from __future__ import annotations

import io
import struct
import pytest

from packet_builders import ah, esp, ethernet, ikev2, ipv4, pcap, udp

from app.layers.layer03_protocol_analysis.ike import decode_ike_proposals
from app.layers.layer03_protocol_analysis.models import (
    IPLayer,
    IPsecAnalysis,
    PacketAnalysisResult,
    ESPLayer,
    IKELayer,
    IKEProposal,
    IKETransform,
)
from app.layers.layer03_protocol_analysis.protocol_engine import analyze_protocol_telemetry
from app.layers.layer03_protocol_analysis.service import (
    ProtocolAnalysisService,
    get_protocol_analysis_service,
)


def _build_ikev2_proposal_bytes(
    proposal_num: int = 1,
    protocol_id: int = 1,  # IKE
    spi: bytes = b"",
    transforms: list[tuple[int, int, int]] | None = None,  # (t_type, t_id, attr_val)
) -> bytes:
    """Helper to construct raw IKEv2 SA payload containing proposals and transforms."""
    if transforms is None:
        # ENCR: AES-CBC (12) with key length 256, PRF: HMAC-SHA2-256 (5), INTEG: AUTH_HMAC_SHA2_256_128 (12), DH: 2048-bit MODP (14)
        transforms = [
            (1, 12, 256),  # ENCR AES-CBC-256
            (2, 5, 0),     # PRF HMAC-SHA2-256
            (3, 12, 0),    # INTEG SHA2-256-128
            (4, 14, 0),    # DH Group 14
        ]

    # Build transform bytes
    t_data = bytearray()
    for idx, (t_type, t_id, key_len) in enumerate(transforms):
        is_last_t = 0 if idx == len(transforms) - 1 else 3
        if key_len > 0:
            # Attribute: AF=1 (TV), Type=14 (Key Length), Value=key_len
            attr_bytes = struct.pack("!HH", 0x800E, key_len)
            t_buf = struct.pack("!BBHBBH", is_last_t, 0, 8 + len(attr_bytes), t_type, 0, t_id) + attr_bytes
        else:
            t_buf = struct.pack("!BBHBBH", is_last_t, 0, 8, t_type, 0, t_id)
        t_data.extend(t_buf)

    # Proposal header:
    # 1B last (0 = last proposal), 1B res, 2B prop len, 1B prop num, 1B proto id, 1B spi size, 1B num transforms
    prop_len = 8 + len(spi) + len(t_data)
    prop_hdr = struct.pack("!BBHBBBB", 0, 0, prop_len, proposal_num, protocol_id, len(spi), len(transforms))
    return prop_hdr + spi + bytes(t_data)


# =============================================================================
# Unit Tests: IKE Proposal & Transform Decoding
# =============================================================================

def test_ikev2_proposal_decoding() -> None:
    sa_bytes = _build_ikev2_proposal_bytes()
    proposals = decode_ike_proposals(sa_bytes, is_v2=True)

    assert len(proposals) == 1
    p = proposals[0]
    assert p.proposal_number == 1
    assert p.protocol_name == "IKE"
    assert len(p.transforms) == 4

    assert any("AES" in enc for enc in p.encryption_algorithms)
    assert any("SHA2_256" in prf for prf in p.prf_algorithms)
    assert any("14" in dh or "2048" in dh for dh in p.dh_groups)


def test_ikev2_weak_proposal_anomaly() -> None:
    # Build proposal with 3DES (3) and MD5 (1)
    weak_transforms = [
        (1, 3, 0),  # ENCR_3DES
        (2, 1, 0),  # PRF_HMAC_MD5
        (3, 1, 0),  # AUTH_HMAC_MD5_96
        (4, 2, 0),  # MODP 1024 (Group 2)
    ]
    sa_bytes = _build_ikev2_proposal_bytes(transforms=weak_transforms)
    proposals = decode_ike_proposals(sa_bytes, is_v2=True)

    assert len(proposals) == 1
    p = proposals[0]
    assert any("3DES" in enc for enc in p.encryption_algorithms)

    # Create dummy packet analysis result
    pkt = PacketAnalysisResult(
        id="test-1",
        number=1,
        timestamp="100.0",
        length=200,
        source="192.168.1.1",
        destination="192.168.1.2",
        protocol="IKE",
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
                proposals=proposals,
            ),
        ),
    )

    report = analyze_protocol_telemetry([pkt], capture_id="test-weak")
    assert report.total_packets_analyzed == 1
    assert len(report.anomalies) >= 1
    weak_anomalies = [a for a in report.anomalies if a.anomaly_type == "WEAK_CRYPTO_PROPOSAL"]
    assert len(weak_anomalies) >= 1
    assert weak_anomalies[0].severity == "HIGH"


# =============================================================================
# Unit Tests: ESP Stream & Sequence Analysis
# =============================================================================

def test_esp_stream_tracking_and_sequence_anomalies() -> None:
    """Test sequence replay, sequence zero, and gap detection."""
    packets = []
    # Seq 0: anomaly
    packets.append(PacketAnalysisResult(
        id="esp-0", number=1, timestamp="1.0", length=120,
        source="10.0.0.1", destination="10.0.0.2", protocol="ESP",
        ip=IPLayer(version=4, source="10.0.0.1", destination="10.0.0.2", protocol_number=50, protocol_name="ESP", total_length=120, ttl=64),
        ipsec=IPsecAnalysis(type="ESP", esp=ESPLayer(spi="0x11223344", sequence_number=0, payload_length=80, encrypted=True, authentication_data="")),
    ))
    # Seq 1: normal
    packets.append(PacketAnalysisResult(
        id="esp-1", number=2, timestamp="1.1", length=120,
        source="10.0.0.1", destination="10.0.0.2", protocol="ESP",
        ip=IPLayer(version=4, source="10.0.0.1", destination="10.0.0.2", protocol_number=50, protocol_name="ESP", total_length=120, ttl=64),
        ipsec=IPsecAnalysis(type="ESP", esp=ESPLayer(spi="0x11223344", sequence_number=1, payload_length=80, encrypted=True, authentication_data="")),
    ))
    # Seq 1 again: replay
    packets.append(PacketAnalysisResult(
        id="esp-2", number=3, timestamp="1.2", length=120,
        source="10.0.0.1", destination="10.0.0.2", protocol="ESP",
        ip=IPLayer(version=4, source="10.0.0.1", destination="10.0.0.2", protocol_number=50, protocol_name="ESP", total_length=120, ttl=64),
        ipsec=IPsecAnalysis(type="ESP", esp=ESPLayer(spi="0x11223344", sequence_number=1, payload_length=80, encrypted=True, authentication_data="")),
    ))
    # Seq 200: large gap
    packets.append(PacketAnalysisResult(
        id="esp-3", number=4, timestamp="1.3", length=120,
        source="10.0.0.1", destination="10.0.0.2", protocol="ESP",
        ip=IPLayer(version=4, source="10.0.0.1", destination="10.0.0.2", protocol_number=50, protocol_name="ESP", total_length=120, ttl=64),
        ipsec=IPsecAnalysis(type="ESP", esp=ESPLayer(spi="0x11223344", sequence_number=5000, payload_length=80, encrypted=True, authentication_data="")),
    ))

    report = analyze_protocol_telemetry(packets, capture_id="stream-test")

    assert len(report.ipsec_streams) == 1
    stream = report.ipsec_streams[0]
    assert stream.spi == "0x11223344"
    assert stream.packet_count == 4
    assert stream.min_sequence == 0
    assert stream.max_sequence == 5000
    assert stream.sequence_replays >= 1
    assert stream.sequence_zero_count >= 1
    assert stream.sequence_gaps >= 1

    # Check anomalies
    anomaly_types = {a.anomaly_type for a in report.anomalies}
    assert "SEQ_ZERO" in anomaly_types
    assert "SEQ_REPLAY" in anomaly_types
    assert "SEQ_GAP_LARGE" in anomaly_types


# =============================================================================
# Unit Tests: Tunnel Endpoint Discovery
# =============================================================================

def test_tunnel_endpoint_discovery() -> None:
    packets = [
        PacketAnalysisResult(
            id="p1", number=1, timestamp="1.0", length=100,
            source="192.168.10.1", destination="192.168.20.1", protocol="ESP",
            ipsec=IPsecAnalysis(type="ESP", esp=ESPLayer(spi="0xAAAA1111", sequence_number=1, payload_length=60, encrypted=True, authentication_data="")),
        ),
        PacketAnalysisResult(
            id="p2", number=2, timestamp="2.0", length=100,
            source="192.168.20.1", destination="192.168.10.1", protocol="ESP",
            ipsec=IPsecAnalysis(type="ESP", esp=ESPLayer(spi="0xBBBB2222", sequence_number=1, payload_length=60, encrypted=True, authentication_data="")),
        ),
    ]

    report = analyze_protocol_telemetry(packets, capture_id="endpoints-test")
    assert len(report.tunnel_endpoints) == 1
    te = report.tunnel_endpoints[0]
    assert set([te.local_endpoint, te.remote_endpoint]) == {"192.168.10.1", "192.168.20.1"}
    assert te.total_packets == 2
    assert "0xAAAA1111" in te.child_sa_spis or "0xBBBB2222" in te.child_sa_spis


# =============================================================================
# Unit Tests: Layer 3 Self-Verification & Service Status
# =============================================================================

def test_layer03_self_verification_and_ready_status() -> None:
    svc = ProtocolAnalysisService()
    verified = svc.verify_engine()
    assert verified is True, "Engine self-verification failed"
    assert svc.get_layer_status() == "READY"


# =============================================================================
# Integration Tests: FastAPI Endpoints
# =============================================================================

def test_fastapi_protocol_analysis_endpoints(client) -> None:
    # 1. Generate synthetic pcap with IKE and ESP packets using packet_builders
    f1 = ethernet(ipv4(udp(ikev2(), 500, 500), proto=17, src="192.168.10.1", dst="192.168.20.1"))
    f2 = ethernet(ipv4(esp(spi=0x12345678, seq=1), proto=50, src="192.168.10.1", dst="192.168.20.1"))
    pcap_data = pcap([f1, f2])

    # Upload capture
    upload_res = client.post(
        "/api/packets/upload",
        files={"file": ("test_layer3.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
    )
    assert upload_res.status_code == 201

    # Test GET /api/packets/protocol-analysis
    res = client.get("/api/packets/protocol-analysis")
    assert res.status_code == 200
    data = res.json()
    assert "total_packets_analyzed" in data
    assert data["total_packets_analyzed"] == 2
    assert "ipsec_streams" in data
    assert "tunnel_endpoints" in data
    assert "anomalies" in data
    assert data["status"] == "READY"

    # Test GET /api/packets/anomalies
    res_anomalies = client.get("/api/packets/anomalies")
    assert res_anomalies.status_code == 200
    assert isinstance(res_anomalies.json(), list)

    # Test GET /api/packets/streams
    res_streams = client.get("/api/packets/streams")
    assert res_streams.status_code == 200
    streams = res_streams.json()
    assert isinstance(streams, list)
    assert len(streams) >= 1
    assert any(s["spi"].lower() == "0x12345678" for s in streams)

    # Test GET /api/packets/tunnel-endpoints
    res_te = client.get("/api/packets/tunnel-endpoints")
    assert res_te.status_code == 200
    te = res_te.json()
    assert isinstance(te, list)
    assert len(te) >= 1

    # Test GET /api/packets/ike-proposals
    res_prop = client.get("/api/packets/ike-proposals")
    assert res_prop.status_code == 200
    assert isinstance(res_prop.json(), list)

    # Test Layer 3 in GET /api/system/status
    res_sys = client.get("/api/system/status")
    assert res_sys.status_code == 200
    sys_data = res_sys.json()
    layer3 = next(l for l in sys_data["architecture_layers"] if l["number"] == 3)
    assert layer3["status"] == "READY"
