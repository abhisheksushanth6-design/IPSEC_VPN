"""Scapy PCAP Reader for Layer 02 — Packet Capture & Data Collection.

Provides high-performance parsing of PCAP/PCAPNG streams and files using Scapy,
extracting packet counts, detailed protocol detection (IKE, ESP, AH, TCP, UDP, ICMP),
source and destination IP addresses (IPv4 & IPv6), port numbers, and conversation pairs.
"""

from __future__ import annotations

import io
import logging
import os
import struct
import time
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Optional, Union

# Suppress Scapy runtime and cryptography deprecation noise during import and runtime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

with warnings.catch_warnings():
    warnings.filterwarnings("ignore")
    from scapy.all import conf, PcapReader, rdpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    try:
        from scapy.layers.ipsec import ESP, AH
    except Exception:
        ESP = None  # type: ignore[assignment]
        AH = None   # type: ignore[assignment]
    try:
        from scapy.layers.isakmp import ISAKMP
    except Exception:
        ISAKMP = None  # type: ignore[assignment]

conf.verb = 0

logger = logging.getLogger(__name__)


@dataclass
class ScapyPacketRecord:
    """Detailed summary of a single captured packet."""
    packet_number: int
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str  # IKE, ESP, AH, TCP, UDP, ICMP, ICMPv6, OTHER
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    length: int = 0
    summary: str = ""
    is_ipsec: bool = False


@dataclass
class ScapyConversationRecord:
    """Aggregated bidirectional traffic between two IP endpoints."""
    source_ip: str
    destination_ip: str
    packet_count: int
    total_bytes: int
    protocols: list[str] = field(default_factory=list)


@dataclass
class ScapyCaptureSummary:
    """Comprehensive summary of a parsed PCAP capture."""
    filename: str
    file_size_bytes: int
    total_packets: int
    ike_packets: int
    esp_packets: int
    ah_packets: int
    other_packets: int
    protocol_counts: dict[str, int]
    source_ips: list[str]
    destination_ips: list[str]
    all_ips: list[str]
    conversations: list[ScapyConversationRecord]
    packets: list[ScapyPacketRecord]
    analysis_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "file_size_bytes": self.file_size_bytes,
            "total_packets": self.total_packets,
            "ike_packets": self.ike_packets,
            "esp_packets": self.esp_packets,
            "ah_packets": self.ah_packets,
            "other_packets": self.other_packets,
            "protocol_counts": self.protocol_counts,
            "source_ips": self.source_ips,
            "destination_ips": self.destination_ips,
            "all_ips": self.all_ips,
            "conversations": [asdict(c) for c in self.conversations],
            "packets": [asdict(p) for p in self.packets],
            "analysis_duration_seconds": self.analysis_duration_seconds,
        }


class ScapyPcapReader:
    """Engine for reading PCAP data and extracting network / IPsec telemetry."""

    @staticmethod
    def _detect_protocol(pkt: Any) -> tuple[str, Optional[int], Optional[int], bool]:
        """Classify packet protocol, ports, and whether it belongs to IPsec."""
        proto = "OTHER"
        sport: Optional[int] = None
        dport: Optional[int] = None
        is_ipsec = False

        # 1. Check IP layer protocols
        has_ip = pkt.haslayer(IP)
        has_ipv6 = pkt.haslayer(IPv6)

        ip_layer = pkt[IP] if has_ip else (pkt[IPv6] if has_ipv6 else None)
        next_proto_num = None

        if ip_layer is not None:
            if has_ip:
                next_proto_num = getattr(ip_layer, "proto", None)
            elif has_ipv6:
                next_proto_num = getattr(ip_layer, "nh", None)

        # 2. ESP Protocol (IP Proto 50 or Scapy ESP layer)
        if next_proto_num == 50 or (ESP is not None and pkt.haslayer(ESP)):
            return "ESP", None, None, True

        # 3. AH Protocol (IP Proto 51 or Scapy AH layer)
        if next_proto_num == 51 or (AH is not None and pkt.haslayer(AH)):
            return "AH", None, None, True

        # 4. Check Transport Layers (UDP / TCP)
        if pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            sport = getattr(udp_layer, "sport", None)
            dport = getattr(udp_layer, "dport", None)

            # Check for IKE (Port 500)
            if sport == 500 or dport == 500:
                return "IKE", sport, dport, True

            # Check for NAT-Traversal UDP 4500 (can be IKE Non-ESP marker or ESP)
            if sport == 4500 or dport == 4500:
                payload = bytes(udp_layer.payload)
                if len(payload) >= 4:
                    # Non-ESP Marker (4 zero bytes) -> IKE
                    if payload[:4] == b"\x00\x00\x00\x00":
                        return "IKE", sport, dport, True
                    # Non-zero first 4 bytes is SPI -> NAT-T ESP
                    return "ESP", sport, dport, True
                if ISAKMP is not None and pkt.haslayer(ISAKMP):
                    return "IKE", sport, dport, True
                return "ESP", sport, dport, True

            # Check for ISAKMP layer on arbitrary ports
            if ISAKMP is not None and pkt.haslayer(ISAKMP):
                return "IKE", sport, dport, True

            proto = "UDP"

        elif pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            sport = getattr(tcp_layer, "sport", None)
            dport = getattr(tcp_layer, "dport", None)
            proto = "TCP"

        elif pkt.haslayer(ICMP) or (has_ipv6 and pkt.haslayer("ICMPv6")):
            proto = "ICMP" if pkt.haslayer(ICMP) else "ICMPv6"

        return proto, sport, dport, is_ipsec

    @classmethod
    def parse(
        cls,
        source: Union[bytes, str, Path, BinaryIO],
        filename: str = "capture.pcap",
        max_packets: int = 20000,
    ) -> ScapyCaptureSummary:
        """Parse PCAP bytes, file path, or file stream with Scapy."""
        start_time = time.perf_counter()
        stream: Any = None
        file_size = 0

        if isinstance(source, (str, Path)):
            path_str = str(source)
            if not os.path.isfile(path_str):
                raise FileNotFoundError(f"PCAP file not found: {path_str}")
            file_size = os.path.getsize(path_str)
            filename = os.path.basename(path_str)
            stream = path_str
        elif isinstance(source, bytes):
            file_size = len(source)
            if file_size < 24:
                raise ValueError("Uploaded file is too small to be a valid PCAP header (minimum 24 bytes).")
            stream = io.BytesIO(source)
        elif hasattr(source, "read"):
            data = source.read()
            file_size = len(data)
            if file_size < 24:
                raise ValueError("Uploaded stream is too small to be a valid PCAP header.")
            stream = io.BytesIO(data)
        else:
            raise TypeError("Source must be bytes, file path, or readable stream.")

        packet_records: list[ScapyPacketRecord] = []
        protocol_counts: dict[str, int] = {
            "IKE": 0,
            "ESP": 0,
            "AH": 0,
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "OTHER": 0,
        }
        unique_src_ips: set[str] = set()
        unique_dst_ips: set[str] = set()
        conversations_map: dict[tuple[str, str], dict[str, Any]] = {}

        try:
            with PcapReader(stream) as reader:
                for idx, pkt in enumerate(reader, start=1):
                    if idx > max_packets:
                        logger.info("Reached maximum packet processing limit (%d)", max_packets)
                        break

                    # 1. Extract IP addresses
                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"

                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                    elif pkt.haslayer(IPv6):
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst
                    else:
                        # Non-IP frames (e.g. ARP, raw link-layer)
                        if pkt.haslayer("ARP"):
                            src_ip = getattr(pkt["ARP"], "psrc", "0.0.0.0")
                            dst_ip = getattr(pkt["ARP"], "pdst", "0.0.0.0")
                        else:
                            src_ip = getattr(pkt, "src", "0.0.0.0")
                            dst_ip = getattr(pkt, "dst", "0.0.0.0")

                    if src_ip and src_ip != "0.0.0.0":
                        unique_src_ips.add(src_ip)
                    if dst_ip and dst_ip != "0.0.0.0":
                        unique_dst_ips.add(dst_ip)

                    # 2. Extract Protocol & Ports
                    proto, sport, dport, is_ipsec = cls._detect_protocol(pkt)

                    # Update protocol counts
                    if proto in protocol_counts:
                        protocol_counts[proto] += 1
                    else:
                        protocol_counts["OTHER"] += 1

                    # 3. Timestamps & Length
                    pkt_ts = float(getattr(pkt, "time", 0.0))
                    pkt_len = len(pkt)
                    pkt_summary = pkt.summary() if hasattr(pkt, "summary") else f"{src_ip} -> {dst_ip} ({proto})"

                    packet_records.append(
                        ScapyPacketRecord(
                            packet_number=idx,
                            timestamp=pkt_ts,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            protocol=proto,
                            source_port=sport,
                            destination_port=dport,
                            length=pkt_len,
                            summary=pkt_summary,
                            is_ipsec=is_ipsec,
                        )
                    )

                    # 4. Aggregated conversation
                    conv_key = (src_ip, dst_ip)
                    if conv_key not in conversations_map:
                        conversations_map[conv_key] = {
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "packet_count": 0,
                            "total_bytes": 0,
                            "protocols": set(),
                        }
                    conversations_map[conv_key]["packet_count"] += 1
                    conversations_map[conv_key]["total_bytes"] += pkt_len
                    conversations_map[conv_key]["protocols"].add(proto)

        except Exception as exc:
            if not packet_records:
                logger.error("Scapy PCAP parsing failed completely: %s", exc)
                raise ValueError(f"Unable to parse PCAP file: {exc}") from exc
            logger.warning("Scapy reached end of stream with partial records (%d parsed): %s", len(packet_records), exc)

        # Build final conversation records
        conversations: list[ScapyConversationRecord] = [
            ScapyConversationRecord(
                source_ip=c["source_ip"],
                destination_ip=c["destination_ip"],
                packet_count=c["packet_count"],
                total_bytes=c["total_bytes"],
                protocols=sorted(list(c["protocols"])),
            )
            for c in sorted(conversations_map.values(), key=lambda x: x["packet_count"], reverse=True)
        ]

        total_pkts = len(packet_records)
        ike_cnt = protocol_counts.get("IKE", 0)
        esp_cnt = protocol_counts.get("ESP", 0)
        ah_cnt = protocol_counts.get("AH", 0)
        other_cnt = total_pkts - (ike_cnt + esp_cnt + ah_cnt)

        all_ips = sorted(list(unique_src_ips.union(unique_dst_ips)))
        duration = round(time.perf_counter() - start_time, 4)

        return ScapyCaptureSummary(
            filename=filename,
            file_size_bytes=file_size,
            total_packets=total_pkts,
            ike_packets=ike_cnt,
            esp_packets=esp_cnt,
            ah_packets=ah_cnt,
            other_packets=max(0, other_cnt),
            protocol_counts=protocol_counts,
            source_ips=sorted(list(unique_src_ips)),
            destination_ips=sorted(list(unique_dst_ips)),
            all_ips=all_ips,
            conversations=conversations,
            packets=packet_records,
            analysis_duration_seconds=duration,
        )


def parse_pcap_with_scapy(
    source: Union[bytes, str, Path, BinaryIO],
    filename: str = "capture.pcap",
    max_packets: int = 20000,
) -> ScapyCaptureSummary:
    """Convenience function for Layer 02 Scapy parsing."""
    return ScapyPcapReader.parse(source, filename=filename, max_packets=max_packets)
