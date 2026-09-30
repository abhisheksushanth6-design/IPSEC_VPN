"""Layer 02 — Packet Capture & Data Collection.

Provides hypervisor-level live packet capture via VirtualBox NIC tracing,
real-time PCAP packet counting, and automatic ingestion into Layer 03.
"""

from app.layers.layer02_packet_capture.capture_engine import (
    VBoxCaptureEngine,
    count_pcap_packets,
)
from app.layers.layer02_packet_capture.scapy_reader import (
    ScapyCaptureSummary,
    ScapyConversationRecord,
    ScapyPacketRecord,
    ScapyPcapReader,
    parse_pcap_with_scapy,
)
from app.layers.layer02_packet_capture.service import (
    LiveCaptureService,
    get_live_capture_service,
)

LAYER_NUMBER = 2
LAYER_NAME = "Packet Capture & Data Collection"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "LiveCaptureService",
    "get_live_capture_service",
    "VBoxCaptureEngine",
    "count_pcap_packets",
    "ScapyCaptureSummary",
    "ScapyConversationRecord",
    "ScapyPacketRecord",
    "ScapyPcapReader",
    "parse_pcap_with_scapy",
]

