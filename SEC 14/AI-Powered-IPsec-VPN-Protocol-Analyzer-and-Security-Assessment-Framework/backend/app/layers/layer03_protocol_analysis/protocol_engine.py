"""Deep protocol telemetry and anomaly analysis engine for Layer 03.

Analyzes IKE negotiation exchanges, proposals, and cryptographic transforms,
tracks ESP and AH traffic streams with SPI and sequence number progression,
discovers tunnel endpoints, and identifies deterministic protocol anomalies.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from app.layers.layer03_protocol_analysis.models import (
    IPsecStreamSummary,
    PacketAnalysisResult,
    ProtocolAnomaly,
    ProtocolAnalysisReport,
    TunnelEndpointSummary,
)

WEAK_CIPHERS = {"DES", "DES-IV64", "DES-CBC", "3DES", "3DES-CBC", "RC5", "IDEA", "BLOWFISH", "NULL"}
WEAK_HASHES = {"MD5", "AUTH_HMAC_MD5_96", "SHA1", "AUTH_HMAC_SHA1_96"}
WEAK_GROUPS = {"MODP-768 (Group 1)", "MODP-1024 (Group 2)", "Group 1", "Group 2"}


def analyze_protocol_telemetry(
    packets: list[PacketAnalysisResult],
    capture_id: Optional[str] = None,
) -> ProtocolAnalysisReport:
    """Analyze parsed packets to derive IKE negotiation, ESP/AH streams, endpoints, and anomalies."""
    ike_packets = [p for p in packets if p.ipsec and p.ipsec.type == "IKE" and p.ipsec.ike]
    esp_packets = [p for p in packets if p.ipsec and p.ipsec.type == "ESP" and p.ipsec.esp]
    ah_packets = [p for p in packets if p.ipsec and p.ipsec.type == "AH" and p.ipsec.ah]

    anomalies: list[ProtocolAnomaly] = []

    # 1. Analyze IKE Negotiation & Cryptographic Proposals
    ike_summary: dict[str, Any] = {
        "total_ike_messages": len(ike_packets),
        "exchanges": [],
        "sessions": [],
        "proposals": [],
        "initiator_spis": list({p.ipsec.ike.initiator_spi for p in ike_packets if p.ipsec and p.ipsec.ike}),
        "responder_spis": list({p.ipsec.ike.responder_spi for p in ike_packets if p.ipsec and p.ipsec.ike and p.ipsec.ike.responder_spi != "00" * 8}),
    }

    proposals_seen: list[dict[str, Any]] = []
    ike_sessions_map: dict[str, list[PacketAnalysisResult]] = defaultdict(list)

    for p in ike_packets:
        assert p.ipsec and p.ipsec.ike
        ike = p.ipsec.ike
        session_key = f"{ike.initiator_spi}:{ike.responder_spi}"
        ike_sessions_map[session_key].append(p)

        ike_summary["exchanges"].append({
            "packet_number": p.number,
            "version": ike.version,
            "exchange_name": ike.exchange_name,
            "message_id": ike.message_id,
            "initiator_spi": ike.initiator_spi,
            "responder_spi": ike.responder_spi,
            "flags": ike.flags,
            "payloads": [pl.name for pl in ike.payloads],
            "proposal_count": len(ike.proposals),
            "timestamp": p.timestamp,
        })

        # Check for NO_PROPOSAL_CHOSEN notify errors
        for pl in ike.payloads:
            if pl.notify_type == 14 or (pl.notify_name and "NO_PROPOSAL_CHOSEN" in pl.notify_name):
                anomalies.append(
                    ProtocolAnomaly(
                        id=uuid.uuid4().hex,
                        anomaly_type="NO_PROPOSAL_CHOSEN",
                        severity="HIGH",
                        packet_number=p.number,
                        spi=ike.initiator_spi,
                        source_ip=p.source,
                        destination_ip=p.destination,
                        description=f"IKE peer rejected proposal: NO_PROPOSAL_CHOSEN in packet {p.number}",
                        evidence={"exchange": ike.exchange_name, "message_id": ike.message_id},
                    )
                )

        # Inspect Proposals & Algorithms
        for prop in ike.proposals:
            prop_dict = {
                "packet_number": p.number,
                "proposal_number": prop.proposal_number,
                "protocol": prop.protocol_name,
                "spi": prop.spi,
                "encryption": prop.encryption_algorithms,
                "integrity": prop.integrity_algorithms,
                "prf": prop.prf_algorithms,
                "dh_groups": prop.dh_groups,
                "esn": prop.esn,
            }
            proposals_seen.append(prop_dict)

            # Check for Insecure/Weak Cryptography Proposals
            weak_reasons = []
            for enc in prop.encryption_algorithms:
                if any(w in enc for w in WEAK_CIPHERS):
                    weak_reasons.append(f"Deprecated encryption cipher: {enc}")
            for hsh in prop.integrity_algorithms:
                if any(w in hsh for w in WEAK_HASHES):
                    weak_reasons.append(f"Weak integrity hash: {hsh}")
            for grp in prop.dh_groups:
                if any(w in grp for w in WEAK_GROUPS):
                    weak_reasons.append(f"Insecure Diffie-Hellman group: {grp}")

            if weak_reasons:
                anomalies.append(
                    ProtocolAnomaly(
                        id=uuid.uuid4().hex,
                        anomaly_type="WEAK_CRYPTO_PROPOSAL",
                        severity="HIGH",
                        packet_number=p.number,
                        spi=prop.spi or ike.initiator_spi,
                        source_ip=p.source,
                        destination_ip=p.destination,
                        description=f"Weak cryptographic algorithm offered: {'; '.join(weak_reasons)}",
                        evidence=prop_dict,
                    )
                )

    ike_summary["proposals"] = proposals_seen

    # 2. Track ESP & AH Streams with SPI and Sequence Progression
    stream_map: dict[tuple[str, str, str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "packets": [],
            "total_bytes": 0,
            "sequences": [],
            "nat_traversal": False,
            "encapsulation_mode": "TUNNEL",
        }
    )

    for p in esp_packets:
        assert p.ipsec and p.ipsec.esp
        esp = p.ipsec.esp
        key = (esp.spi, "ESP", p.source, p.destination)
        s = stream_map[key]
        s["packets"].append(p)
        s["total_bytes"] += p.length
        s["sequences"].append((p.number, esp.sequence_number))
        s["nat_traversal"] = p.ipsec.nat_traversal
        s["encapsulation_mode"] = p.ipsec.encapsulation_mode

    for p in ah_packets:
        assert p.ipsec and p.ipsec.ah
        ah = p.ipsec.ah
        key = (ah.spi, "AH", p.source, p.destination)
        s = stream_map[key]
        s["packets"].append(p)
        s["total_bytes"] += p.length
        s["sequences"].append((p.number, ah.sequence_number))
        s["encapsulation_mode"] = p.ipsec.encapsulation_mode

    ipsec_streams: list[IPsecStreamSummary] = []
    established_spis: set[str] = set()

    for (spi, proto, src, dst), data in stream_map.items():
        established_spis.add(spi.lower())
        seq_records = data["sequences"]
        raw_seqs = [seq for _, seq in seq_records]

        min_seq = min(raw_seqs) if raw_seqs else 0
        max_seq = max(raw_seqs) if raw_seqs else 0

        # Sequence Replay and Gap Detection
        seen_seqs: set[int] = set()
        replays = 0
        gaps = 0
        zero_count = 0
        prev_seq: Optional[int] = None

        for pkt_num, seq in seq_records:
            # Check for Sequence 0 (RFC 4303 §3.3.3: Illegal sequence number)
            if seq == 0:
                zero_count += 1
                anomalies.append(
                    ProtocolAnomaly(
                        id=uuid.uuid4().hex,
                        anomaly_type="SEQ_ZERO",
                        severity="HIGH",
                        packet_number=pkt_num,
                        spi=spi,
                        source_ip=src,
                        destination_ip=dst,
                        description=f"Illegal sequence number 0 encountered on {proto} SPI {spi} in packet {pkt_num}",
                        evidence={"spi": spi, "protocol": proto, "packet_number": pkt_num},
                    )
                )

            # Check for Replay
            if seq in seen_seqs and seq != 0:
                replays += 1
                anomalies.append(
                    ProtocolAnomaly(
                        id=uuid.uuid4().hex,
                        anomaly_type="SEQ_REPLAY",
                        severity="HIGH",
                        packet_number=pkt_num,
                        spi=spi,
                        source_ip=src,
                        destination_ip=dst,
                        description=f"Sequence replay detected: seq={seq} duplicated on {proto} SPI {spi} in packet {pkt_num}",
                        evidence={"spi": spi, "sequence_number": seq, "packet_number": pkt_num},
                    )
                )
            seen_seqs.add(seq)

            # Check for Large Jumps / Gaps (> 1000)
            if prev_seq is not None and seq > prev_seq + 1:
                gaps += 1
                if seq - prev_seq > 1000:
                    anomalies.append(
                        ProtocolAnomaly(
                            id=uuid.uuid4().hex,
                            anomaly_type="SEQ_GAP_LARGE",
                            severity="MEDIUM",
                            packet_number=pkt_num,
                            spi=spi,
                            source_ip=src,
                            destination_ip=dst,
                            description=f"Large sequence gap on {proto} SPI {spi}: jumped from {prev_seq} to {seq} (gap of {seq - prev_seq})",
                            evidence={"spi": spi, "previous_seq": prev_seq, "current_seq": seq},
                        )
                    )
            prev_seq = seq

        ipsec_streams.append(
            IPsecStreamSummary(
                spi=spi,
                protocol=proto,  # type: ignore[arg-type]
                source_ip=src,
                destination_ip=dst,
                packet_count=len(data["packets"]),
                total_bytes=data["total_bytes"],
                min_sequence=min_seq,
                max_sequence=max_seq,
                sequence_gaps=gaps,
                sequence_replays=replays,
                sequence_zero_count=zero_count,
                nat_traversal=data["nat_traversal"],
                encapsulation_mode=data["encapsulation_mode"],
            )
        )

    # 3. Tunnel Endpoint Discovery
    endpoint_map: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "protocols": set(),
            "spis": set(),
            "total_packets": 0,
            "total_bytes": 0,
            "modes": set(),
            "ike_count": 0,
        }
    )

    for p in packets:
        if p.ipsec and p.source and p.destination:
            pair = tuple(sorted([p.source, p.destination]))
            ep = endpoint_map[pair]
            ep["protocols"].add(p.ipsec.type)
            ep["total_packets"] += 1
            ep["total_bytes"] += p.length
            ep["modes"].add(p.ipsec.encapsulation_mode)
            if p.ipsec.type == "IKE":
                ep["ike_count"] += 1
            if p.ipsec.esp:
                ep["spis"].add(p.ipsec.esp.spi)
            if p.ipsec.ah:
                ep["spis"].add(p.ipsec.ah.spi)

    tunnel_endpoints: list[TunnelEndpointSummary] = []
    active_tunnel_pairs: set[tuple[str, str]] = set()

    for (ep1, ep2), ep_data in endpoint_map.items():
        proto_str = "/".join(sorted(ep_data["protocols"]))
        mode_str = "/".join(sorted(ep_data["modes"])) or "TUNNEL"
        tunnel_endpoints.append(
            TunnelEndpointSummary(
                local_endpoint=ep1,
                remote_endpoint=ep2,
                protocol=proto_str,
                ike_sa_count=ep_data["ike_count"],
                child_sa_spis=sorted(list(ep_data["spis"])),
                total_packets=ep_data["total_packets"],
                total_bytes=ep_data["total_bytes"],
                encapsulation_mode=mode_str,
            )
        )
        active_tunnel_pairs.add((ep1, ep2))
        active_tunnel_pairs.add((ep2, ep1))

    # 4. Cleartext Leakage Anomaly Detection
    # If unencrypted non-IPsec IP traffic travels between endpoints that have an active IPsec tunnel
    for p in packets:
        if not p.ipsec and p.protocol in ("TCP", "UDP") and p.source != "—" and p.destination != "—":
            if (p.source, p.destination) in active_tunnel_pairs:
                anomalies.append(
                    ProtocolAnomaly(
                        id=uuid.uuid4().hex,
                        anomaly_type="CLEARTEXT_LEAK",
                        severity="HIGH",
                        packet_number=p.number,
                        spi=None,
                        source_ip=p.source,
                        destination_ip=p.destination,
                        description=(
                            f"Cleartext packet ({p.protocol}) detected between active IPsec tunnel endpoints "
                            f"{p.source} → {p.destination} in packet {p.number}"
                        ),
                        evidence={"protocol": p.protocol, "length": p.length, "info": p.info},
                    )
                )

    # 5. Packet Structural Anomaly Detection
    for p in packets:
        if p.parse_status != "OK":
            anomalies.append(
                ProtocolAnomaly(
                    id=uuid.uuid4().hex,
                    anomaly_type="TRUNCATED_PACKET",
                    severity="MEDIUM",
                    packet_number=p.number,
                    spi=None,
                    source_ip=p.source,
                    destination_ip=p.destination,
                    description=f"Malformed packet in capture: {p.parse_error or 'Truncated header'}",
                    evidence={"parse_status": p.parse_status, "affected_protocol": p.parse_affected_protocol},
                )
            )

    protocol_counts: dict[str, int] = {
        "IKE": len(ike_packets),
        "ESP": len(esp_packets),
        "AH": len(ah_packets),
        "TCP": sum(1 for p in packets if p.protocol == "TCP"),
        "UDP": sum(1 for p in packets if p.protocol == "UDP"),
        "ICMP": sum(1 for p in packets if p.protocol == "ICMP"),
        "OTHER": sum(1 for p in packets if p.protocol not in ("IKE", "ESP", "AH", "TCP", "UDP", "ICMP")),
    }

    return ProtocolAnalysisReport(
        capture_id=capture_id,
        total_packets_analyzed=len(packets),
        ipsec_packets=len(ike_packets) + len(esp_packets) + len(ah_packets),
        ike_summary=ike_summary,
        ipsec_streams=ipsec_streams,
        tunnel_endpoints=tunnel_endpoints,
        anomalies=anomalies,
        protocol_counts=protocol_counts,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
        status="READY",
    )
