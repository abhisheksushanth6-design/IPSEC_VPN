"""Packet-analysis store and query service.

Holds one loaded capture in process memory, bounded by packet count and
upload size. Persistence belongs to Layer 11 in a later section.
"""

from __future__ import annotations

import math
import re
import threading
from datetime import datetime, timezone
from typing import Optional

from app.layers.layer03_protocol_analysis import CaptureFormatError, analyze_capture
from app.layers.layer03_protocol_analysis.models import CaptureMetadata, PacketAnalysisResult
from app.schemas.packets import (
    AnalysisStatusSchema,
    CaptureMetadataSchema,
    PacketPageSchema,
    PacketStatisticsSchema,
    PacketSummarySchema,
    ProtocolCountsSchema,
)

SUPPORTED_EXTENSIONS = (".pcap", ".pcapng", ".cap")
SUPPORTED_FORMATS = ["pcap", "pcapng"]
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_PACKETS = 50_000
MAX_PAGE_SIZE = 200

SORTABLE = {"number", "timestamp", "length", "source", "destination", "protocol"}
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


class PacketServiceError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class PacketService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._raw: Optional[bytes] = None
        self._filename: Optional[str] = None
        self._loaded_at: Optional[str] = None
        self._metadata: Optional[CaptureMetadata] = None
        self._packets: list[PacketAnalysisResult] = []
        self._by_id: dict[str, PacketAnalysisResult] = {}
        self._state: str = "NOT INITIALIZED"
        self._last_error: Optional[str] = None

    # ----- lifecycle -------------------------------------------------------

    @staticmethod
    def sanitize_filename(name: str | None) -> str:
        base = (name or "capture").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        base = _SAFE_FILENAME.sub("_", base).strip("._") or "capture"
        return base[:120]

    @staticmethod
    def validate_upload(filename: str | None, size: int) -> None:
        if size <= 0:
            raise PacketServiceError("EMPTY_UPLOAD", "The uploaded file is empty.")
        if size > MAX_UPLOAD_BYTES:
            raise PacketServiceError(
                "UPLOAD_TOO_LARGE",
                f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
                413,
            )
        if not filename or not filename.lower().endswith(SUPPORTED_EXTENSIONS):
            raise PacketServiceError(
                "CAPTURE_FORMAT_UNSUPPORTED",
                "Only .pcap, .pcapng and .cap files are supported.",
                415,
            )

    def load(self, data: bytes, filename: str | None) -> AnalysisStatusSchema:
        """Parse a capture and replace the current store."""
        with self._lock:
            self._state = "ANALYZING"
            try:
                metadata, packets = analyze_capture(data, MAX_PACKETS)
            except CaptureFormatError as exc:
                self._state = "ERROR" if self._packets else "NOT INITIALIZED"
                self._last_error = str(exc)
                raise PacketServiceError("PACKET_PARSE_ERROR", f"Unable to parse packet capture: {exc}", 422)
            self._raw = data
            self._filename = self.sanitize_filename(filename)
            self._loaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._metadata = metadata
            self._packets = packets
            self._by_id = {p.id: p for p in packets}
            self._state = "COMPLETED"
            self._last_error = None
        return self.status()

    def reanalyze(self) -> AnalysisStatusSchema:
        with self._lock:
            raw, filename = self._raw, self._filename
        if raw is None:
            raise PacketServiceError("NO_PACKET_SOURCE", "No capture is loaded to analyze.", 409)
        return self.load(raw, filename)

    def clear(self) -> AnalysisStatusSchema:
        with self._lock:
            self._raw = None
            self._filename = None
            self._loaded_at = None
            self._metadata = None
            self._packets = []
            self._by_id = {}
            self._state = "NOT INITIALIZED"
            self._last_error = None
        return self.status()

    # ----- queries ---------------------------------------------------------

    def status(self) -> AnalysisStatusSchema:
        with self._lock:
            packets = self._packets
            metadata = self._metadata
            capture = None
            if metadata:
                capture = CaptureMetadataSchema(
                    format=metadata.format,
                    link_type=metadata.link_type,
                    link_type_name=metadata.link_type_name,
                    packet_count=metadata.packet_count,
                    truncated=metadata.truncated,
                    filename=self._filename,
                    loaded_at=self._loaded_at,
                )
            return AnalysisStatusSchema(
                state=self._state,  # type: ignore[arg-type]
                supported_formats=SUPPORTED_FORMATS,
                max_upload_bytes=MAX_UPLOAD_BYTES,
                max_packets=MAX_PACKETS,
                capture=capture,
                statistics=self._statistics(packets) if metadata else None,
                protocol_counts=self._protocol_counts(packets) if metadata else None,
                last_error=self._last_error,
            )

    def get(self, packet_id: str) -> PacketAnalysisResult:
        with self._lock:
            packet = self._by_id.get(packet_id)
        if packet is None:
            raise PacketServiceError("PACKET_NOT_FOUND", "No packet with that identifier is loaded.", 404)
        return packet

    def query(
        self,
        *,
        page: int,
        page_size: int,
        protocol: str | None,
        source: str | None,
        destination: str | None,
        port: int | None,
        ipsec: str | None,
        search: str | None,
        sort: str,
        order: str,
    ) -> PacketPageSchema:
        with self._lock:
            rows = list(self._packets)

        rows = [p for p in rows if self._matches(p, protocol, source, destination, port, ipsec, search)]

        key = sort if sort in SORTABLE else "number"
        rows.sort(key=lambda p: (getattr(p, key), p.number), reverse=(order == "desc"))

        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        total = len(rows)
        total_pages = max(1, math.ceil(total / page_size))
        page = max(1, min(page, total_pages))
        start = (page - 1) * page_size
        items = [self._summary(p) for p in rows[start : start + page_size]]
        return PacketPageSchema(items=items, page=page, page_size=page_size, total=total, total_pages=total_pages)

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _matches(p: PacketAnalysisResult, protocol, source, destination, port, ipsec, search) -> bool:
        if protocol and p.protocol != protocol.upper():
            return False
        if source and source.lower() not in p.source.lower():
            return False
        if destination and destination.lower() not in p.destination.lower():
            return False
        if port is not None:
            t = p.transport
            ports = {getattr(t, "source_port", None), getattr(t, "destination_port", None)}
            if port not in ports:
                return False
        if ipsec:
            wanted = ipsec.upper()
            have = p.ipsec.type if p.ipsec else None
            if wanted == "NON-IPSEC" and have is not None:
                return False
            if wanted in ("IKE", "ESP", "AH") and have != wanted:
                return False
        if search:
            needle = search.lower()
            haystack = [str(p.number), p.source, p.destination, p.protocol, p.info]
            if p.ipsec:
                for layer in (p.ipsec.ike, p.ipsec.esp, p.ipsec.ah):
                    if layer is None:
                        continue
                    for attr in ("spi", "initiator_spi", "responder_spi", "exchange_name"):
                        value = getattr(layer, attr, None)
                        if value:
                            haystack.append(str(value))
            if not any(needle in h.lower() for h in haystack):
                return False
        return True

    @staticmethod
    def _summary(p: PacketAnalysisResult) -> PacketSummarySchema:
        return PacketSummarySchema(
            id=p.id, number=p.number, timestamp=p.timestamp, source=p.source, destination=p.destination,
            protocol=p.protocol, length=p.length, info=p.info, parse_status=p.parse_status,
            ipsec_type=p.ipsec.type if p.ipsec else None,
            nat_traversal=p.ipsec.nat_traversal if p.ipsec else False,
        )

    @staticmethod
    def _protocol_counts(packets: list[PacketAnalysisResult]) -> ProtocolCountsSchema:
        counts = ProtocolCountsSchema()
        for p in packets:
            key = p.protocol if p.protocol in ("IKE", "ESP", "AH", "TCP", "UDP", "ICMP") else "OTHER"
            setattr(counts, key, getattr(counts, key) + 1)
        return counts

    @staticmethod
    def _statistics(packets: list[PacketAnalysisResult]) -> PacketStatisticsSchema:
        ike = sum(1 for p in packets if p.ipsec and p.ipsec.type == "IKE")
        esp = sum(1 for p in packets if p.ipsec and p.ipsec.type == "ESP")
        ah = sum(1 for p in packets if p.ipsec and p.ipsec.type == "AH")
        return PacketStatisticsSchema(
            total_packets=len(packets), ipsec_packets=ike + esp + ah, ike_packets=ike, esp_packets=esp,
            ah_packets=ah, malformed_packets=sum(1 for p in packets if p.parse_status != "OK"),
        )


packet_service = PacketService()
