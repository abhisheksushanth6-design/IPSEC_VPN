"""Layer 04 Service: SA Lifecycle & Session Fingerprinting.

Provides self-verification for Layer 04 status, orchestrates session correlation,
and manages deterministic session fingerprints.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from app.layers.layer03_protocol_analysis.models import (
    ESPLayer,
    IKELayer,
    IPLayer,
    IPsecAnalysis,
    PacketAnalysisResult,
)
from app.layers.layer04_sa_lifecycle.models import VPNSessionFingerprint
from app.layers.layer04_sa_lifecycle.session_correlator import (
    correlate_sessions_and_fingerprint,
)

logger = logging.getLogger(__name__)


class Layer04Service:
    """Service managing Layer 04 SA Lifecycle, Session Correlation & Fingerprinting."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._verify_lock = threading.Lock()
        self._verified: bool = False
        self._last_sessions: list[VPNSessionFingerprint] = []

    def verify_engine(self) -> bool:
        """Execute automated self-test on session correlation and fingerprint determinism."""
        with self._verify_lock:
            if self._verified:
                return True
            try:
                # 1. Synthesize minimal IKE and ESP packets
                p1 = PacketAnalysisResult(
                    id="test-p1",
                    number=1,
                    timestamp="1700000000.0",
                    length=150,
                    source="192.168.1.10",
                    destination="192.168.1.20",
                    protocol="IKE",
                    ip=IPLayer(version=4, source="192.168.1.10", destination="192.168.1.20", protocol_number=17, protocol_name="UDP", total_length=150, ttl=64),
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
                        ),
                    ),
                )
                p2 = PacketAnalysisResult(
                    id="test-p2",
                    number=2,
                    timestamp="1700000001.0",
                    length=120,
                    source="192.168.1.10",
                    destination="192.168.1.20",
                    protocol="ESP",
                    ip=IPLayer(version=4, source="192.168.1.10", destination="192.168.1.20", protocol_number=50, protocol_name="ESP", total_length=120, ttl=64),
                    ipsec=IPsecAnalysis(
                        type="ESP",
                        esp=ESPLayer(
                            spi="0x12345678",
                            sequence_number=1,
                            payload_length=80,
                        ),
                    ),
                )

                # 2. Correlate and test determinism
                runs_1 = correlate_sessions_and_fingerprint([p1, p2], capture_id="verify_1")
                runs_2 = correlate_sessions_and_fingerprint([p1, p2], capture_id="verify_1")

                if len(runs_1) != 1 or len(runs_2) != 1:
                    logger.error("Layer 04 verification failed: Expected 1 session, got %d", len(runs_1))
                    return False

                s1 = runs_1[0]
                s2 = runs_2[0]

                if s1.fingerprint != s2.fingerprint or len(s1.fingerprint) != 64:
                    logger.error("Layer 04 verification failed: Fingerprint non-deterministic or invalid length")
                    return False

                if s1.total_packets != 2 or s1.esp_packets != 1 or s1.ike_packets != 1:
                    logger.error("Layer 04 verification failed: Packet counts incorrect")
                    return False

                self._verified = True
                return True
            except Exception as e:
                logger.error("Layer 04 self-verification error: %s", e, exc_info=True)
                return False

    def get_layer_status(self) -> str:
        """Report Layer 04 status dynamically based on verification outcome."""
        return "READY" if self.verify_engine() else "NOT INITIALIZED"

    def correlate_capture(
        self,
        packets: list[PacketAnalysisResult],
        capture_id: str = "default",
    ) -> list[VPNSessionFingerprint]:
        """Correlate capture packets into sessions with stable fingerprints."""
        sessions = correlate_sessions_and_fingerprint(packets, capture_id=capture_id)
        with self._lock:
            self._last_sessions = sessions
        return sessions

    def get_sessions(self) -> list[VPNSessionFingerprint]:
        with self._lock:
            return list(self._last_sessions)

    def get_session_by_id(self, session_id: str) -> Optional[VPNSessionFingerprint]:
        with self._lock:
            for s in self._last_sessions:
                if s.session_id == session_id or s.short_signature == session_id or s.fingerprint == session_id:
                    return s
        return None


_layer04_service: Optional[Layer04Service] = None
_service_lock = threading.Lock()


def get_layer04_service() -> Layer04Service:
    global _layer04_service
    with _service_lock:
        if _layer04_service is None:
            _layer04_service = Layer04Service()
        return _layer04_service
