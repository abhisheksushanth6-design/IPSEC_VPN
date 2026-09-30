"""Layer 03 Service and Verification State.

Orchestrates deep protocol analysis, verification of Layer 03 decoding engines,
and supplies dynamic layer status reporting (reporting READY when verified).
"""

from __future__ import annotations

import logging
import struct
import threading
from typing import Optional

from app.layers.layer03_protocol_analysis.analyzer import analyze_frame
from app.layers.layer03_protocol_analysis.capture_reader import Record
from app.layers.layer03_protocol_analysis.models import (
    PacketAnalysisResult,
    ProtocolAnalysisReport,
)
from app.layers.layer03_protocol_analysis.protocol_engine import analyze_protocol_telemetry

logger = logging.getLogger(__name__)


class ProtocolAnalysisService:
    """Service managing Layer 03 Protocol Analysis engine and health status."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._verified: bool = False
        self._last_report: Optional[ProtocolAnalysisReport] = None
        self._verify_lock = threading.Lock()

    def verify_engine(self) -> bool:
        """Run self-test on core decoders to guarantee engine integrity."""
        with self._verify_lock:
            if self._verified:
                return True
            try:
                # 1. Build minimal valid IPv4 + UDP + IKEv2 test frame
                # Ethernet (14) + IPv4 (20) + UDP (8) + IKE (28)
                mac_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 56, 1, 0, 64, 17, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
                udp_hdr = struct.pack("!HHHH", 500, 500, 36, 0)
                ike_hdr = struct.pack("!8s8sBBBBII", b"\x01"*8, b"\x00"*8, 0, 0x20, 34, 0x08, 0, 28)
                test_frame = mac_hdr + ip_hdr + udp_hdr + ike_hdr

                rec = Record(timestamp=1700000000.0, captured_length=len(test_frame), original_length=len(test_frame), frame=test_frame)
                res = analyze_frame(1, rec, 1)

                if res.parse_status != "OK" or res.protocol != "IKE":
                    logger.error("Layer 03 self-verification failed: status=%s, proto=%s", res.parse_status, res.protocol)
                    return False

                # 2. Test ESP native frame
                esp_hdr = struct.pack("!II", 0x12345678, 1) + b"\x00" * 16
                ip_esp = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 44, 1, 0, 64, 50, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
                esp_frame = mac_hdr + ip_esp + esp_hdr
                rec_esp = Record(timestamp=1700000001.0, captured_length=len(esp_frame), original_length=len(esp_frame), frame=esp_frame)
                res_esp = analyze_frame(1, rec_esp, 2)

                if res_esp.parse_status != "OK" or res_esp.protocol != "ESP":
                    logger.error("Layer 03 ESP self-verification failed: status=%s, proto=%s", res_esp.parse_status, res_esp.protocol)
                    return False

                self._verified = True
                logger.info("Layer 03 Protocol Analysis engine verified successfully (status: READY)")
                return True

            except Exception as exc:
                logger.exception("Layer 03 Protocol Analysis self-test failed: %s", exc)
                return False

    def get_layer_status(self) -> str:
        """Derive dynamic Layer 03 status. Returns READY when verified."""
        if self.verify_engine():
            return "READY"
        return "NOT INITIALIZED"

    def analyze(
        self,
        packets: list[PacketAnalysisResult],
        capture_id: Optional[str] = None,
    ) -> ProtocolAnalysisReport:
        """Perform deep protocol telemetry analysis across given packets."""
        # Ensure engine is verified
        self.verify_engine()
        report = analyze_protocol_telemetry(packets, capture_id=capture_id)
        with self._lock:
            self._last_report = report
        return report

    def get_last_report(self) -> Optional[ProtocolAnalysisReport]:
        """Return the most recent protocol analysis report."""
        with self._lock:
            return self._last_report


# Singleton accessor
_instance: Optional[ProtocolAnalysisService] = None


def get_protocol_analysis_service() -> ProtocolAnalysisService:
    global _instance
    if _instance is None:
        _instance = ProtocolAnalysisService()
    return _instance
