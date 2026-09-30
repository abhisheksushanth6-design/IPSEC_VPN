"""IKE / ISAKMP header and payload chain decoding (RFC 2408, RFC 7296).

Payload *contents* are not decoded here; the chain of payload headers is,
which is enough to name each payload and detect the encrypted (SK) payload.
"""

from __future__ import annotations

import struct

from app.layers.layer03_protocol_analysis.errors import TruncatedError
from app.layers.layer03_protocol_analysis.models import (
    IKELayer,
    IKEPayload,
    IKEProposal,
    IKETransform,
)

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

# Cryptographic Algorithm ID mappings (RFC 7296 §3.3.2 & IANA IKEv2 Parameters)
ENCR_ALGORITHMS = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "BLOWFISH",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
    28: "CHACHA20-POLY1305",
}

PRF_ALGORITHMS = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
}

INTEG_ALGORITHMS = {
    0: "NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

DH_GROUPS = {
    1: "MODP-768 (Group 1)",
    2: "MODP-1024 (Group 2)",
    5: "MODP-1536 (Group 5)",
    14: "MODP-2048 (Group 14)",
    15: "MODP-3072 (Group 15)",
    16: "MODP-4096 (Group 16)",
    17: "MODP-6144 (Group 17)",
    18: "MODP-8192 (Group 18)",
    19: "ECP-256 (Group 19)",
    20: "ECP-384 (Group 20)",
    21: "ECP-521 (Group 21)",
    31: "Curve25519 (Group 31)",
    32: "Curve448 (Group 32)",
}

TRANSFORM_TYPES = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "D-H",
    5: "ESN",
}

PROTOCOL_NAMES = {
    1: "IKE",
    2: "AH",
    3: "ESP",
}


def decode_ike_proposals(data: bytes, is_v2: bool = True) -> list[IKEProposal]:
    """Decode IKE proposals and cryptographic transforms from SA payload data."""
    proposals: list[IKEProposal] = []
    if not data or len(data) < 8:
        return proposals

    offset = 0
    if not is_v2:
        # IKEv1 SA payload begins with 4-byte DOI + 4-byte Situation
        offset = 8
        if len(data) < 16:
            return proposals

    try:
        while offset + 8 <= len(data):
            if is_v2:
                # IKEv2 Proposal substructure (RFC 7296 §3.3)
                last_more, _res, prop_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack(
                    "!BBHBBBB", data[offset : offset + 8]
                )
                if prop_len < 8 or offset + prop_len > len(data):
                    break

                spi_hex: str | None = None
                spi_end = offset + 8 + spi_sz
                if spi_sz > 0 and spi_end <= offset + prop_len:
                    spi_bytes = data[offset + 8 : spi_end]
                    spi_hex = "0x" + spi_bytes.hex()

                trans_offset = spi_end
                transforms: list[IKETransform] = []
                encr_list: list[str] = []
                integ_list: list[str] = []
                prf_list: list[str] = []
                dh_list: list[str] = []
                esn_val: str | None = None

                for _ in range(num_transforms):
                    if trans_offset + 8 > offset + prop_len:
                        break
                    _last_t, _tres, trans_len, trans_type, _tres2, trans_id = struct.unpack(
                        "!BBHBBH", data[trans_offset : trans_offset + 8]
                    )
                    if trans_len < 8:
                        break

                    type_name = TRANSFORM_TYPES.get(trans_type, f"TYPE_{trans_type}")
                    key_len: int | None = None

                    # Check for Transform Attributes (e.g. Key Length)
                    if trans_len >= 12 and trans_offset + 12 <= offset + prop_len:
                        attr_type, attr_val = struct.unpack(
                            "!HH", data[trans_offset + 8 : trans_offset + 12]
                        )
                        # Type 0x800e is Key Length (Basic format)
                        if attr_type == 0x800E:
                            key_len = attr_val

                    # Resolve human-readable transform name
                    if trans_type == 1:
                        raw_name = ENCR_ALGORITHMS.get(trans_id, f"ENCR_{trans_id}")
                        name = f"{raw_name}_{key_len}" if key_len else raw_name
                        encr_list.append(name)
                    elif trans_type == 2:
                        name = PRF_ALGORITHMS.get(trans_id, f"PRF_{trans_id}")
                        prf_list.append(name)
                    elif trans_type == 3:
                        name = INTEG_ALGORITHMS.get(trans_id, f"AUTH_{trans_id}")
                        integ_list.append(name)
                    elif trans_type == 4:
                        name = DH_GROUPS.get(trans_id, f"DH_GROUP_{trans_id}")
                        dh_list.append(name)
                    elif trans_type == 5:
                        name = "ESN" if trans_id == 1 else "NO_ESN"
                        esn_val = name
                    else:
                        name = f"TRANS_{trans_id}"

                    transforms.append(
                        IKETransform(
                            type_id=trans_type,
                            type_name=type_name,
                            transform_id=trans_id,
                            transform_name=name,
                            key_length=key_len,
                        )
                    )
                    trans_offset += trans_len

                proposals.append(
                    IKEProposal(
                        proposal_number=prop_num,
                        protocol_id=proto_id,
                        protocol_name=PROTOCOL_NAMES.get(proto_id, f"PROTO_{proto_id}"),
                        spi=spi_hex,
                        transforms=transforms,
                        encryption_algorithms=encr_list,
                        integrity_algorithms=integ_list,
                        prf_algorithms=prf_list,
                        dh_groups=dh_list,
                        esn=esn_val,
                    )
                )

                if last_more == 0:
                    break
                offset += prop_len

            else:
                # IKEv1 Proposal substructure (RFC 2408 §3.5)
                # Next payload(1), reserved(1), length(2), proposal#(1), proto(1), spi_size(1), num_transforms(1)
                _next_p, _pres, prop_len, prop_num, proto_id, spi_sz, num_transforms = struct.unpack(
                    "!BBHBBBB", data[offset : offset + 8]
                )
                if prop_len < 8 or offset + prop_len > len(data):
                    break

                spi_hex = None
                spi_end = offset + 8 + spi_sz
                if spi_sz > 0 and spi_end <= offset + prop_len:
                    spi_hex = "0x" + data[offset + 8 : spi_end].hex()

                # In IKEv1, transforms are chained inside the proposal
                trans_offset = spi_end
                transforms = []
                encr_list = []
                integ_list = []
                dh_list = []

                for _ in range(num_transforms):
                    if trans_offset + 8 > offset + prop_len:
                        break
                    _next_t, _tres, trans_len, trans_num, trans_id, _tres2 = struct.unpack(
                        "!BBHBBB", data[trans_offset : trans_offset + 7]
                    )
                    if trans_len < 8:
                        break

                    # Walk attributes (2-byte type, 2-byte value)
                    attr_ptr = trans_offset + 8
                    key_len = None
                    dh_grp = None
                    while attr_ptr + 4 <= trans_offset + trans_len:
                        atype, aval = struct.unpack("!HH", data[attr_ptr : attr_ptr + 4])
                        # 0x8001: Encryption algorithm
                        if atype == 0x8001:
                            v1_encr = {1: "DES-CBC", 5: "3DES-CBC", 7: "AES-CBC"}.get(aval, f"ENCR_{aval}")
                            encr_list.append(v1_encr)
                        # 0x8002: Hash algorithm
                        elif atype == 0x8002:
                            v1_hash = {1: "MD5", 2: "SHA1", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}.get(aval, f"HASH_{aval}")
                            integ_list.append(v1_hash)
                        # 0x8004: Group description
                        elif atype == 0x8004:
                            dh_grp = DH_GROUPS.get(aval, f"Group_{aval}")
                            dh_list.append(dh_grp)
                        # 0x800E: Key length
                        elif atype == 0x800E:
                            key_len = aval
                        attr_ptr += 4

                    transforms.append(
                        IKETransform(
                            type_id=1,
                            type_name="IKEv1_TRANSFORM",
                            transform_id=trans_id,
                            transform_name=f"Transform_{trans_id}",
                            key_length=key_len,
                        )
                    )
                    trans_offset += trans_len

                proposals.append(
                    IKEProposal(
                        proposal_number=prop_num,
                        protocol_id=proto_id,
                        protocol_name=PROTOCOL_NAMES.get(proto_id, f"PROTO_{proto_id}"),
                        spi=spi_hex,
                        transforms=transforms,
                        encryption_algorithms=encr_list,
                        integrity_algorithms=integ_list,
                        prf_algorithms=[],
                        dh_groups=dh_list,
                        esn=None,
                    )
                )

                offset += prop_len
                break  # Standard IKEv1 proposal chain handled safely
    except Exception:
        pass

    return proposals


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

    payloads = _decode_payload_chain(data[ISAKMP_HEADER_LENGTH:], next_payload, payload_names, is_v2=is_v2)
    encrypted = any(p.type_number in ENCRYPTED_PAYLOAD_TYPES for p in payloads) if is_v2 else bool(flags & 0x01)

    # Flatten proposals across all payloads
    all_proposals = [prop for p in payloads for prop in p.proposals]

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
        proposals=all_proposals,
    )


NOTIFY_MESSAGE_TYPES = {
    16384: "INITIAL_CONTACT",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
    16404: "REDIRECT_SUPPORTED",
    16405: "REDIRECT",
}


def _decode_payload_chain(data: bytes, first_type: int, names: dict[int, str], is_v2: bool = True) -> list[IKEPayload]:
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

        notify_type: int | None = None
        notify_name: str | None = None
        if payload_type in (11, 41) and (offset + 8 <= len(data)):
            try:
                _proto, _spi_sz, n_type = struct.unpack("!BBH", data[offset + 4 : offset + 8])
                notify_type = n_type
                notify_name = NOTIFY_MESSAGE_TYPES.get(n_type, f"NOTIFY_{n_type}")
            except struct.error:
                pass

        # Decode proposals if this is an SA payload (Type 33 in v2, Type 1 in v1)
        proposals: list[IKEProposal] = []
        if (is_v2 and payload_type == 33) or (not is_v2 and payload_type == 1):
            body_bytes = data[offset + 4 : offset + length]
            proposals = decode_ike_proposals(body_bytes, is_v2=is_v2)

        payload_display = f"{names.get(payload_type, f'Payload {payload_type}')}"
        if notify_name:
            payload_display = f"{payload_display} ({notify_name})"

        payloads.append(
            IKEPayload(
                type_number=payload_type,
                name=payload_display,
                length=length,
                critical=bool(crit & 0x80),
                notify_type=notify_type,
                notify_name=notify_name,
                proposals=proposals,
            )
        )
        if payload_type in ENCRYPTED_PAYLOAD_TYPES:
            # Anything after SK is ciphertext; the chain inside cannot be read.
            break
        payload_type = next_type
        offset += length
    return payloads

