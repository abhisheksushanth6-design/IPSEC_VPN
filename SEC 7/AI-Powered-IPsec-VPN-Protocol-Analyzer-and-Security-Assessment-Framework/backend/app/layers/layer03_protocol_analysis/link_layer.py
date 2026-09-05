"""Link-layer decoding: Ethernet II (with 802.1Q), Linux SLL, raw IP."""

from __future__ import annotations

import struct

from app.layers.layer03_protocol_analysis.capture_reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
)
from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.models import EthernetLayer

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def decode_link(link_type: int, frame: bytes) -> tuple[EthernetLayer | None, int | None, bytes]:
    """Return (ethernet_layer, ethertype, payload). ethertype None means unknown."""
    if link_type == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            raise TruncatedError("Ethernet", 14, len(frame))
        dst, src, ethertype = struct.unpack("!6s6sH", frame[:14])
        offset = 14
        vlan_id = None
        if ethertype == ETHERTYPE_VLAN:
            if len(frame) < 18:
                raise TruncatedError("802.1Q", 18, len(frame))
            tci, ethertype = struct.unpack("!HH", frame[14:18])
            vlan_id = tci & 0x0FFF
            offset = 18
        layer = EthernetLayer(_mac(src), _mac(dst), f"0x{ethertype:04x}", vlan_id)
        return layer, ethertype, frame[offset:]

    if link_type == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            raise TruncatedError("Linux SLL", 16, len(frame))
        ethertype = struct.unpack("!H", frame[14:16])[0]
        return None, ethertype, frame[16:]

    if link_type == LINKTYPE_IPV4:
        return None, ETHERTYPE_IPV4, frame
    if link_type == LINKTYPE_IPV6:
        return None, ETHERTYPE_IPV6, frame
    if link_type == LINKTYPE_RAW:
        if not frame:
            raise TruncatedError("IP", 1, 0)
        version = frame[0] >> 4
        return None, (ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6 if version == 6 else None), frame

    return None, None, frame
