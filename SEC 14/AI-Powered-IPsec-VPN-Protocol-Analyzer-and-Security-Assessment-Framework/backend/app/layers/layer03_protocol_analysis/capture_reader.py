"""Readers for pcap and pcapng capture files.

Both yield (timestamp_seconds, captured_length, original_length, frame_bytes)
tuples along with the link-layer type. Only the block types needed to recover
packets are interpreted; everything else is skipped by length.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Literal

from app.layers.layer03_protocol_analysis.errors import CaptureFormatError

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

LINK_TYPE_NAMES = {
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "Raw IP",
    LINKTYPE_LINUX_SLL: "Linux cooked capture",
    LINKTYPE_IPV4: "Raw IPv4",
    LINKTYPE_IPV6: "Raw IPv6",
    LINKTYPE_LINUX_SLL2: "Linux cooked capture v2",
}

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass(frozen=True)
class Record:
    timestamp: float
    captured_length: int
    original_length: int
    frame: bytes


@dataclass
class Capture:
    format: Literal["pcap", "pcapng"]
    link_type: int
    records: list[Record]
    truncated: bool


def detect_format(data: bytes) -> Literal["pcap", "pcapng"]:
    head = data[:4]
    if head in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
        return "pcap"
    if head == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureFormatError("Not a pcap or pcapng file.")


def read_capture(data: bytes, max_packets: int) -> Capture:
    fmt = detect_format(data)
    if fmt == "pcap":
        return _read_pcap(data, max_packets)
    return _read_pcapng(data, max_packets)


def _read_pcap(data: bytes, max_packets: int) -> Capture:
    if len(data) < 24:
        raise CaptureFormatError("pcap header is truncated.")
    magic = data[:4]
    little = magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE)
    nanos = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
    endian = "<" if little else ">"

    _, _, _, _, _, link_type = struct.unpack(endian + "HHiIII", data[4:24])
    records: list[Record] = []
    offset = 24
    truncated = False

    while offset + 16 <= len(data):
        if len(records) >= max_packets:
            truncated = True
            break
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        if len(frame) < incl_len:
            truncated = True
            frame = frame  # keep what exists; parser reports incompleteness
        offset += incl_len
        timestamp = ts_sec + (ts_frac / 1e9 if nanos else ts_frac / 1e6)
        records.append(Record(timestamp, len(frame), orig_len, frame))

    return Capture("pcap", link_type, records, truncated)


def _read_pcapng(data: bytes, max_packets: int) -> Capture:
    """Interpret SHB, IDB, EPB and SPB blocks; skip the rest by length."""
    endian = ">"
    link_type = LINKTYPE_ETHERNET
    ts_resolution = 1e-6
    records: list[Record] = []
    offset = 0
    truncated = False
    seen_shb = False

    while offset + 12 <= len(data):
        if len(records) >= max_packets:
            truncated = True
            break

        block_type_raw = data[offset : offset + 4]
        if block_type_raw == PCAPNG_MAGIC:
            # Section Header Block: byte-order magic decides endianness.
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise CaptureFormatError("pcapng byte-order magic is invalid.")
            seen_shb = True
            block_type = 0x0A0D0D0A
        else:
            if not seen_shb:
                raise CaptureFormatError("pcapng file does not start with a Section Header Block.")
            (block_type,) = struct.unpack(endian + "I", block_type_raw)

        (block_length,) = struct.unpack(endian + "I", data[offset + 4 : offset + 8])
        if block_length < 12 or offset + block_length > len(data):
            truncated = True
            break
        body = data[offset + 8 : offset + block_length - 4]

        if block_type == 0x00000001:  # Interface Description Block
            link_type, _, _snaplen = struct.unpack(endian + "HHI", body[:8])
            ts_resolution = _parse_if_tsresol(body[8:], endian)
        elif block_type == 0x00000006:  # Enhanced Packet Block
            _iface, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            frame = body[20 : 20 + cap_len]
            timestamp = ((ts_high << 32) | ts_low) * ts_resolution
            records.append(Record(timestamp, len(frame), orig_len, frame))
        elif block_type == 0x00000003:  # Simple Packet Block (no timestamp)
            (orig_len,) = struct.unpack(endian + "I", body[:4])
            frame = body[4 : 4 + orig_len]
            records.append(Record(0.0, len(frame), orig_len, frame))

        offset += block_length

    if not seen_shb:
        raise CaptureFormatError("pcapng file has no Section Header Block.")
    return Capture("pcapng", link_type, records, truncated)


def _parse_if_tsresol(options: bytes, endian: str) -> float:
    """Extract if_tsresol (code 9) from IDB options; default microseconds."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset : offset + 4])
        offset += 4
        if code == 0:
            break
        value = options[offset : offset + length]
        if code == 9 and length >= 1:
            raw = value[0]
            if raw & 0x80:
                return 2.0 ** -(raw & 0x7F)
            return 10.0 ** -raw
        offset += (length + 3) & ~3
    return 1e-6


def iter_records(capture: Capture) -> Iterator[Record]:
    yield from capture.records
