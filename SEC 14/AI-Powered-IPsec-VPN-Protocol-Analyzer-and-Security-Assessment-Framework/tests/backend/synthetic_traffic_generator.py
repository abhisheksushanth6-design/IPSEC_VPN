"""Synthetic traffic generator for testing the 9 advanced requirements.

Generates byte-exact pcaps for:
1. Transport Mode (AH next header in {1, 6, 17, 58}, IKEv2 USE_TRANSPORT_MODE 16391)
2. IPv6 Communication (IPv6 extension header walking & recording)
3. VoIP Traffic (20ms cadence, small symmetric frames, high MOS)
4. WhatsApp-type Traffic (bursts with idle intervals, low pps, keepalives)
5. E-Mail Traffic (two-phase command-response followed by bulk unidirectional train)
6. Video-Streaming Traffic (periodic chunk bursts, heavy downlink asymmetry, MTU packets)
"""

from __future__ import annotations

import struct
from typing import Sequence

import packet_builders as B


def timed_pcap(timed_frames: Sequence[tuple[bytes, float]], link_type: int = 1) -> bytes:
    """Pack frames with explicit timestamps (seconds with microsecond precision)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    for frame, ts in timed_frames:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec < 0:
            usec = 0
        elif usec >= 1_000_000:
            sec += 1
            usec = 0
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return out


# ==============================================================================
# 1. Transport Mode Builders
# ==============================================================================

def build_ike_notify_use_transport_mode() -> bytes:
    """Build an IKEv2 NOTIFY payload for USE_TRANSPORT_MODE (type 16391)."""
    # Protocol ID = 0, SPI size = 0, Notify Message Type = 16391 (0x4007)
    body = struct.pack("!BBH", 0, 0, 16391)
    return body


def build_ikev2_transport_exchange(exchange: int = 35) -> list[bytes]:
    """Build IKE_AUTH exchange containing USE_TRANSPORT_MODE notification."""
    notify_body = build_ike_notify_use_transport_mode()
    # Payload 41 = NOTIFY
    payloads = [(41, notify_body), (46, b"\x00" * 32)]
    req = B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=exchange, message_id=1, payloads=payloads), 500, 500), 17))
    resp = B.ethernet(B.ipv4(B.udp(B.ikev2(exchange=exchange, message_id=1, flags=0x20, r_spi=b"\x02" * 8, payloads=payloads), 500, 500), 17, src=B.DST4, dst=B.SRC4))
    return [req, resp]


def build_transport_mode_ah_frames(count: int = 10, start_ts: float = 1_700_000_000.0) -> list[tuple[bytes, float]]:
    """Build AH packets carrying inner transport protocol (UDP)."""
    frames: list[tuple[bytes, float]] = []
    for i in range(count):
        inner_udp = B.udp(b"transport_ah_data_" + str(i).encode(), sport=6000, dport=7000)
        ah_packet = B.ah(next_header=17, spi=0xABCD1111, seq=i + 1) + inner_udp
        frame = B.ethernet(B.ipv4(ah_packet, proto=51))
        frames.append((frame, start_ts + i * 0.1))
    return frames


# ==============================================================================
# 2. IPv6 Communication with Extension Headers
# ==============================================================================

def build_ipv6_hop_by_hop(next_header: int = 50) -> bytes:
    """Build an 8-byte Hop-by-Hop Options extension header (RFC 8200)."""
    # next_header (1B), hdr_ext_len=0 (1B, means (0+1)*8 = 8 bytes total)
    # PadN option: type=1, opt_data_len=4, 4 zero bytes
    return struct.pack("!BBBBBBBB", next_header, 0, 1, 4, 0, 0, 0, 0)


def build_ipv6_routing(next_header: int = 50) -> bytes:
    """Build an 8-byte Routing extension header (RFC 8200)."""
    # next_header (1B), hdr_ext_len=0 (1B), routing_type=0, segments_left=0, reserved 4B
    return struct.pack("!BBBBII", next_header, 0, 0, 0, 0, 0)


def build_ipv6_esp_with_ext_headers(count: int = 10, start_ts: float = 1_700_000_000.0) -> list[tuple[bytes, float]]:
    """Build IPv6 ESP frames with Hop-by-Hop and Routing extension headers."""
    frames: list[tuple[bytes, float]] = []
    for i in range(count):
        # IPv6 -> Hop-by-Hop (next=43) -> Routing (next=50) -> ESP
        hbh = build_ipv6_hop_by_hop(next_header=43)
        routing = build_ipv6_routing(next_header=50)
        esp_payload = B.esp(spi=0x66660001, seq=i + 1, ciphertext=b"\xcc" * 48)
        full_payload = hbh + routing + esp_payload

        # Next header in IPv6 main header is 0 (Hop-by-Hop)
        ip6_frame = B.ipv6(full_payload, next_header=0, src=B.SRC6, dst=B.DST6)
        frame = B.ethernet(ip6_frame, ethertype=0x86DD)
        frames.append((frame, start_ts + i * 0.1))
    return frames


# ==============================================================================
# 3. VoIP Traffic Generator (20ms Cadence, Small Frames, High MOS)
# ==============================================================================

def build_voip_traffic(
    count: int = 100,
    start_ts: float = 1_700_000_000.0,
    spi_in: int = 0x11110001,
    spi_out: int = 0x22220002,
) -> list[tuple[bytes, float]]:
    """Build VoIP RTP-over-ESP frames: ~20ms interval, small packet size (~170-200B)."""
    frames: list[tuple[bytes, float]] = []
    ts = start_ts

    for i in range(count):
        # Small jitter: +/- 0.5 ms around 20ms (0.020s)
        jitter = ((i % 5) - 2) * 0.0001
        ts += 0.020 + jitter

        # Voice frame payload: 120-160 bytes of voice ciphertext (total frame ~180-220B)
        payload_size = 130 + (i % 4) * 8
        ciphertext = b"\x12" * payload_size

        if i % 2 == 0:
            # Client to Gateway (Uplink)
            esp_pkt = B.esp(spi=spi_in, seq=(i // 2) + 1, ciphertext=ciphertext)
            ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.SRC4, dst=B.DST4)
        else:
            # Gateway to Client (Downlink)
            esp_pkt = B.esp(spi=spi_out, seq=(i // 2) + 1, ciphertext=ciphertext)
            ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.DST4, dst=B.SRC4)

        frames.append((B.ethernet(ip_pkt), ts))

    return frames


# ==============================================================================
# 4. WhatsApp-type Traffic Generator (Bursts + Keepalives, Low pps)
# ==============================================================================

def build_whatsapp_traffic(
    burst_count: int = 6,
    packets_per_burst: int = 5,
    start_ts: float = 1_700_000_000.0,
    spi_in: int = 0x33330001,
    spi_out: int = 0x44440002,
) -> list[tuple[bytes, float]]:
    """Build conversational messaging traffic: quick bursts followed by 3-5s idle gaps."""
    frames: list[tuple[bytes, float]] = []
    ts = start_ts
    seq_in = 1
    seq_out = 1

    for b in range(burst_count):
        # Message burst (small packets, typing/sending messages)
        for p in range(packets_per_burst):
            ts += 0.040 + (p * 0.010)  # ~40-80ms intra-burst IAT
            payload_size = 110 + (p % 3) * 30
            ciphertext = b"\x33" * payload_size

            if p % 2 == 0:
                esp_pkt = B.esp(spi=spi_in, seq=seq_in, ciphertext=ciphertext)
                ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.SRC4, dst=B.DST4)
                seq_in += 1
            else:
                esp_pkt = B.esp(spi=spi_out, seq=seq_out, ciphertext=ciphertext)
                ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.DST4, dst=B.SRC4)
                seq_out += 1

            frames.append((B.ethernet(ip_pkt), ts))

        # Long idle gap between messages (reading, typing, or presence keepalive)
        ts += 3.5

    return frames


# ==============================================================================
# 5. E-Mail Traffic Generator (Interactive Handshake + Unidirectional Bulk Train)
# ==============================================================================

def build_email_traffic(
    start_ts: float = 1_700_000_000.0,
    bulk_packet_count: int = 40,
    spi_in: int = 0x55550001,
    spi_out: int = 0x66660002,
) -> list[tuple[bytes, float]]:
    """Build Email traffic: 2-phase pattern (small command/response, then large MTU bulk train)."""
    frames: list[tuple[bytes, float]] = []
    ts = start_ts
    seq_in = 1
    seq_out = 1

    # Phase 1: Command-Response (IMAP/SMTP handshake, 8 packets)
    for i in range(8):
        ts += 0.120  # ~120ms round-trip latency
        if i % 2 == 0:
            # Client sends command (~150B)
            esp_pkt = B.esp(spi=spi_in, seq=seq_in, ciphertext=b"\x55" * 120)
            ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.SRC4, dst=B.DST4)
            seq_in += 1
        else:
            # Server sends response (~220B)
            esp_pkt = B.esp(spi=spi_out, seq=seq_out, ciphertext=b"\x66" * 180)
            ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.DST4, dst=B.SRC4)
            seq_out += 1
        frames.append((B.ethernet(ip_pkt), ts))

    # Phase 2: Bulk Email Transmission (train of MTU packets)
    for k in range(bulk_packet_count):
        ts += 0.003  # rapid TCP bulk transfer
        # 1420 bytes ciphertext inside ESP -> total frame ~1460 bytes
        esp_pkt = B.esp(spi=spi_in, seq=seq_in, ciphertext=b"\x77" * 1420)
        ip_pkt = B.ipv4(esp_pkt, proto=50, src=B.SRC4, dst=B.DST4)
        seq_in += 1
        frames.append((B.ethernet(ip_pkt), ts))

        # Occasional TCP ACK back from server every 5 packets
        if k % 5 == 0:
            esp_ack = B.esp(spi=spi_out, seq=seq_out, ciphertext=b"\x88" * 40)
            ip_ack = B.ipv4(esp_ack, proto=50, src=B.DST4, dst=B.SRC4)
            seq_out += 1
            frames.append((B.ethernet(ip_ack), ts + 0.001))

    return frames


# ==============================================================================
# 6. Video-Streaming Traffic Generator (Periodic Chunks + Downlink Asymmetry)
# ==============================================================================

def build_video_streaming_traffic(
    chunk_count: int = 5,
    packets_per_chunk: int = 30,
    start_ts: float = 1_700_000_000.0,
    spi_in: int = 0x77770001,
    spi_out: int = 0x88880002,
) -> list[tuple[bytes, float]]:
    """Build Video streaming: periodic chunk downloads with heavy downlink asymmetry."""
    frames: list[tuple[bytes, float]] = []
    ts = start_ts
    seq_in = 1
    seq_out = 1

    for c in range(chunk_count):
        # Client requests chunk (1 small uplink request)
        esp_req = B.esp(spi=spi_in, seq=seq_in, ciphertext=b"\x91" * 80)
        ip_req = B.ipv4(esp_req, proto=50, src=B.SRC4, dst=B.DST4)
        seq_in += 1
        frames.append((B.ethernet(ip_req), ts))

        # Downlink burst of large MTU frames (video buffer chunk)
        for p in range(packets_per_chunk):
            ts += 0.002
            esp_data = B.esp(spi=spi_out, seq=seq_out, ciphertext=b"\x92" * 1440)
            ip_data = B.ipv4(esp_data, proto=50, src=B.DST4, dst=B.SRC4)
            seq_out += 1
            frames.append((B.ethernet(ip_data), ts))

        # Client sends minimal uplink ACK
        ts += 0.005
        esp_ack = B.esp(spi=spi_in, seq=seq_in, ciphertext=b"\x93" * 40)
        ip_ack = B.ipv4(esp_ack, proto=50, src=B.SRC4, dst=B.DST4)
        seq_in += 1
        frames.append((B.ethernet(ip_ack), ts))

        # Idle time between chunks (video player playback buffer interval ~1.5s)
        ts += 1.5

    return frames
