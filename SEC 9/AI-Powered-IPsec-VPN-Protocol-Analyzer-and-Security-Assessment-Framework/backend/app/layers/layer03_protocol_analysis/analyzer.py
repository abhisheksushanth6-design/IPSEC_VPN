"""Frame analyzer: composes the layer decoders into one normalised result.

A decoding failure in any layer marks the packet MALFORMED (structurally
wrong) or ERROR (unexpected), records the affected protocol, and keeps every
layer that was decoded before the failure. One bad packet never aborts the
capture.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.layers.layer03_protocol_analysis.capture_reader import LINK_TYPE_NAMES, Record, read_capture
from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.ike import decode_ike
from app.layers.layer03_protocol_analysis.ipsec import classify_udp_encapsulation, decode_ah, decode_esp
from app.layers.layer03_protocol_analysis.link_layer import ETHERTYPE_IPV4, ETHERTYPE_IPV6, decode_link
from app.layers.layer03_protocol_analysis.models import (
    CaptureMetadata,
    ICMPLayer,
    IPsecAnalysis,
    PacketAnalysisResult,
    RawData,
    SecurityFlags,
    TCPLayer,
    UDPLayer,
)
from app.layers.layer03_protocol_analysis.network_layer import decode_ipv4, decode_ipv6
from app.layers.layer03_protocol_analysis.transport_layer import decode_icmp, decode_tcp, decode_udp

RAW_BYTES_RETAINED = 2048


def analyze_capture(data: bytes, max_packets: int) -> tuple[CaptureMetadata, list[PacketAnalysisResult]]:
    capture = read_capture(data, max_packets)
    results = [
        analyze_frame(capture.link_type, record, number)
        for number, record in enumerate(capture.records, start=1)
    ]
    metadata = CaptureMetadata(
        format=capture.format,
        link_type=capture.link_type,
        link_type_name=LINK_TYPE_NAMES.get(capture.link_type, f"Link type {capture.link_type}"),
        packet_count=len(results),
        truncated=capture.truncated,
    )
    return metadata, results


def analyze_frame(link_type: int, record: Record, number: int) -> PacketAnalysisResult:
    frame = record.frame
    result = PacketAnalysisResult(
        id=uuid.uuid4().hex,
        number=number,
        timestamp=_iso(record.timestamp),
        captured_length=record.captured_length,
        original_length=record.original_length,
        source="—",
        destination="—",
        protocol="OTHER",
        length=record.captured_length,
        info="",
        raw=_raw(frame),
    )
    if record.captured_length < record.original_length:
        result.flags.incomplete = True

    try:
        _decode(link_type, frame, result)
    except TruncatedError as exc:
        _mark(result, "MALFORMED", str(exc), exc.protocol)
    except ValueError as exc:
        _mark(result, "MALFORMED", str(exc), _last_layer(result))
    except Exception as exc:  # noqa: BLE001 - one packet must never abort the capture
        _mark(result, "ERROR", f"Unexpected decoder failure: {type(exc).__name__}", _last_layer(result))

    if not result.info:
        result.info = _default_info(result)
    return result


def _decode(link_type: int, frame: bytes, result: PacketAnalysisResult) -> None:
    ethernet, ethertype, payload = decode_link(link_type, frame)
    if ethernet:
        result.ethernet = ethernet
        result.layers.append("Ethernet")

    if ethertype == ETHERTYPE_IPV4:
        ip, payload = decode_ipv4(payload)
    elif ethertype == ETHERTYPE_IPV6:
        ip, payload = decode_ipv6(payload)
    else:
        result.info = f"Non-IP frame (ethertype {ethernet.ethertype if ethernet else 'unknown'})"
        return

    result.ip = ip
    result.layers.append(f"IPv{ip.version}")
    result.source, result.destination = ip.source, ip.destination
    result.protocol = "IP"
    if ip.fragment_offset or ip.more_fragments:
        result.flags.fragmented = True
    if ip.fragment_offset:
        result.info = f"IPv4 fragment offset {ip.fragment_offset}, {ip.protocol_name}"
        return  # Non-first fragments carry no transport header.

    proto = ip.protocol_number
    if proto == 6:
        tcp, _ = decode_tcp(payload)
        result.transport, result.protocol = tcp, "TCP"
        result.layers.append("TCP")
        result.info = f"TCP {tcp.source_port} → {tcp.destination_port} [{', '.join(tcp.flags) or 'no flags'}] seq={tcp.sequence_number} win={tcp.window}"
    elif proto == 17:
        udp, udp_payload = decode_udp(payload)
        result.transport, result.protocol = udp, "UDP"
        result.layers.append("UDP")
        result.info = f"UDP {udp.source_port} → {udp.destination_port} len={udp.length}"
        _decode_udp_ipsec(udp, udp_payload, result)
    elif proto in (1, 58):
        icmp, _ = decode_icmp(payload, ipv6=(proto == 58))
        result.transport, result.protocol = icmp, "ICMP"
        result.layers.append("ICMPv6" if proto == 58 else "ICMP")
        result.info = f"{'ICMPv6' if proto == 58 else 'ICMP'} {icmp.type_name} (type {icmp.type}, code {icmp.code})"
    elif proto == 50:
        esp = decode_esp(payload)
        result.protocol = "ESP"
        result.layers.append("ESP")
        result.ipsec = IPsecAnalysis(type="ESP", nat_traversal=False, esp=esp)
        result.flags.encrypted = True
        result.info = f"ESP SPI={esp.spi} seq={esp.sequence_number} payload={esp.payload_length} bytes (encrypted)"
    elif proto == 51:
        ah, _ = decode_ah(payload)
        result.protocol = "AH"
        result.layers.append("AH")
        result.ipsec = IPsecAnalysis(type="AH", nat_traversal=False, ah=ah)
        result.flags.authenticated = True
        result.info = f"AH SPI={ah.spi} seq={ah.sequence_number} next={ah.next_header_name} ICV={ah.icv_length} bytes"
    else:
        result.info = f"IPv{ip.version} {ip.protocol_name}"


def _decode_udp_ipsec(udp: UDPLayer, payload: bytes, result: PacketAnalysisResult) -> None:
    kind = classify_udp_encapsulation(udp.destination_port, udp.source_port, payload)
    if kind is None:
        return
    port = 4500 if 4500 in (udp.source_port, udp.destination_port) else 500

    if kind == "NAT_KEEPALIVE":
        result.flags.nat_t = True
        result.info = "UDP/4500 NAT-T keepalive (RFC 3948 §2.3)"
        return

    if kind == "ESP_NAT_T":
        esp = decode_esp(payload)
        result.protocol = "ESP"
        result.layers.append("ESP")
        result.ipsec = IPsecAnalysis(type="ESP", nat_traversal=True, udp_port=port, esp=esp,
                                     nat_traversal_note="ESP encapsulated in UDP/4500 (RFC 3948).")
        result.flags.encrypted = result.flags.nat_t = True
        result.info = f"ESP (UDP-encapsulated) SPI={esp.spi} seq={esp.sequence_number} (encrypted)"
        return

    ike_bytes = payload[4:] if kind == "IKE_NAT_T" else payload
    try:
        ike = decode_ike(ike_bytes)
    except (TruncatedError, ValueError) as exc:
        # Structurally not IKE after all; keep the UDP result and note why.
        result.layers.append("IKE")
        raise TruncatedError("IKE", 28, len(ike_bytes)) if isinstance(exc, TruncatedError) else exc
    result.protocol = "IKE"
    result.layers.append("IKE")
    result.ipsec = IPsecAnalysis(
        type="IKE", nat_traversal=(kind == "IKE_NAT_T"), udp_port=port, ike=ike,
        nat_traversal_note="IKE carried after a 4-byte non-ESP marker on UDP/4500 (RFC 3948 §2.2)."
        if kind == "IKE_NAT_T" else None,
    )
    result.flags.nat_t = kind == "IKE_NAT_T"
    result.flags.encrypted = ike.encrypted_payload
    names = ", ".join(p.name for p in ike.payloads) or "no payloads"
    result.info = f"IKEv{ike.major_version} {ike.exchange_name} msg={ike.message_id} [{names}]"


def _mark(result: PacketAnalysisResult, status: str, message: str, protocol: str | None) -> None:
    result.parse_status = status  # type: ignore[assignment]
    result.parse_error = message
    result.parse_affected_protocol = protocol
    result.flags.malformed = True
    if not result.info:
        result.info = f"{status}: {message}"


def _last_layer(result: PacketAnalysisResult) -> str | None:
    return result.layers[-1] if result.layers else None


def _default_info(result: PacketAnalysisResult) -> str:
    if result.transport:
        if isinstance(result.transport, TCPLayer | UDPLayer):
            return f"{result.transport.kind} {result.transport.source_port} → {result.transport.destination_port}"
        if isinstance(result.transport, ICMPLayer):
            return f"ICMP {result.transport.type_name}"
    return result.protocol


def _raw(frame: bytes) -> RawData:
    kept = frame[:RAW_BYTES_RETAINED]
    ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in kept)
    return RawData(hex=kept.hex(), ascii=ascii_view, length=len(frame), truncated=len(frame) > len(kept))


def _iso(ts: float) -> str:
    if ts <= 0:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


__all__ = ["analyze_capture", "analyze_frame", "SecurityFlags"]
