"""IKE / ISAKMP header and payload chain decoding (RFC 2408, RFC 7296).

Payload *contents* are not decoded here; the chain of payload headers is,
which is enough to name each payload and detect the encrypted (SK) payload.
"""

from __future__ import annotations

import struct

from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.models import IKELayer, IKEPayload

ISAKMP_HEADER_LENGTH = 28

IKEV2_EXCHANGES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME", 43: "IKE_INTERMEDIATE",
}
IKEV1_EXCHANGES = {
    0: "None", 1: "Base", 2: "Identity Protection (Main Mode)", 3: "Authentication Only",
    4: "Aggressive", 5: "Informational", 32: "Quick Mode", 33: "New Group Mode",
}

IKEV2_PAYLOADS = {
    33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ", 39: "AUTH",
    40: "Nonce", 41: "NOTIFY", 42: "DELETE", 43: "VENDOR", 44: "TSi", 45: "TSr",
    46: "SK (Encrypted)", 47: "CP", 48: "EAP", 49: "GSPM", 50: "IDg", 51: "GSA",
    52: "KD", 53: "SKF (Encrypted Fragment)",
}
IKEV1_PAYLOADS = {
    1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT", 7: "CERTREQ",
    8: "HASH", 9: "SIG", 10: "NONCE", 11: "NOTIFY", 12: "DELETE", 13: "VENDOR",
    20: "NAT-D", 21: "NAT-OA",
}

IKEV2_FLAGS = [(0x08, "Initiator"), (0x10, "Version"), (0x20, "Response")]
IKEV1_FLAGS = [(0x01, "Encryption"), (0x02, "Commit"), (0x04, "Authentication")]

ENCRYPTED_PAYLOAD_TYPES = {46, 53}


def decode_ike(data: bytes) -> IKELayer:
    if len(data) < ISAKMP_HEADER_LENGTH:
        raise TruncatedError("IKE", ISAKMP_HEADER_LENGTH, len(data))
    i_spi, r_spi, next_payload, version, exchange_type, flags, message_id, length = struct.unpack(
        "!8s8sBBBBII", data[:ISAKMP_HEADER_LENGTH]
    )
    major, minor = version >> 4, version & 0x0F
    if major not in (1, 2):
        raise ValueError(f"IKE major version {major} is not 1 or 2")
    if length < ISAKMP_HEADER_LENGTH:
        raise ValueError(f"IKE length {length} is below the 28-byte header")

    is_v2 = major == 2
    exchange_names = IKEV2_EXCHANGES if is_v2 else IKEV1_EXCHANGES
    payload_names = IKEV2_PAYLOADS if is_v2 else IKEV1_PAYLOADS
    flag_bits = IKEV2_FLAGS if is_v2 else IKEV1_FLAGS

    payloads = _decode_payload_chain(data[ISAKMP_HEADER_LENGTH:], next_payload, payload_names)
    encrypted = any(p.type_number in ENCRYPTED_PAYLOAD_TYPES for p in payloads) if is_v2 else bool(flags & 0x01)

    return IKELayer(
        version=f"{major}.{minor}",
        major_version=major,
        minor_version=minor,
        exchange_type=exchange_type,
        exchange_name=exchange_names.get(exchange_type, f"Exchange {exchange_type}"),
        initiator_spi=i_spi.hex(),
        responder_spi=r_spi.hex(),
        message_id=message_id,
        flags=[name for bit, name in flag_bits if flags & bit],
        length=length,
        payloads=payloads,
        payload_count=len(payloads),
        encrypted_payload=encrypted,
    )


def _decode_payload_chain(data: bytes, first_type: int, names: dict[int, str]) -> list[IKEPayload]:
    """Walk the generic payload headers: next(1), critical/reserved(1), length(2)."""
    payloads: list[IKEPayload] = []
    payload_type = first_type
    offset = 0
    # A chain longer than this is not a real IKE message.
    for _ in range(64):
        if payload_type == 0:
            break
        if len(data) - offset < 4:
            raise TruncatedError(f"IKE payload {names.get(payload_type, payload_type)}", 4, len(data) - offset)
        next_type, crit, length = struct.unpack("!BBH", data[offset : offset + 4])
        if length < 4:
            raise ValueError(f"IKE payload length {length} is below the 4-byte generic header")
        if offset + length > len(data):
            raise TruncatedError(f"IKE payload {names.get(payload_type, payload_type)}", offset + length, len(data))
        payloads.append(IKEPayload(payload_type, names.get(payload_type, f"Payload {payload_type}"), length, bool(crit & 0x80)))
        if payload_type in ENCRYPTED_PAYLOAD_TYPES:
            # Anything after SK is ciphertext; the chain inside cannot be read.
            break
        payload_type = next_type
        offset += length
    return payloads
