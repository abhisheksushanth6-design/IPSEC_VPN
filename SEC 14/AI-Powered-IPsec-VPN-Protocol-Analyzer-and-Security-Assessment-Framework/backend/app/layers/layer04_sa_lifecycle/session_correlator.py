"""Session correlation and deterministic fingerprint generation engine.

Correlates IKE, ESP, and AH packets from Layer 02 / Layer 03 into logical VPN
sessions using endpoint pairs, SPI associations, SA information, timestamps,
and protocol characteristics. Generates deterministic, tamper-evident SHA-256
session signatures.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Optional

from app.layers.layer03_protocol_analysis.models import PacketAnalysisResult
from app.layers.layer04_sa_lifecycle.models import (
    SessionFingerprintComponents,
    VPNSessionFingerprint,
)

INACTIVITY_GAP_SECONDS = 300.0


def _parse_ts(ts_val: Optional[str]) -> Optional[float]:
    if not ts_val:
        return None
    try:
        return float(ts_val)
    except (ValueError, TypeError):
        return None


def _format_duration(start: Optional[float], end: Optional[float]) -> float:
    if start is None or end is None or end < start:
        return 0.0
    return round(end - start, 3)


def correlate_sessions_and_fingerprint(
    packets: list[PacketAnalysisResult],
    capture_id: str = "default",
) -> list[VPNSessionFingerprint]:
    """Correlate IPsec packets into VPN sessions and generate stable fingerprints."""
    # 1. Filter IPsec packets
    ipsec_packets = [
        p for p in packets
        if p.ipsec is not None and p.parse_status == "OK" and p.source and p.destination and p.source != "—"
    ]
    if not ipsec_packets:
        return []

    # Sort packets chronologically
    def _pkt_key(p: PacketAnalysisResult) -> tuple[float, int]:
        ts = _parse_ts(p.timestamp) or 0.0
        return (ts, p.number)

    ipsec_packets.sort(key=_pkt_key)

    # 2. Group into endpoint pairs
    endpoint_groups: dict[tuple[str, str], list[list[PacketAnalysisResult]]] = defaultdict(list)
    last_timestamps: dict[tuple[str, str], float] = {}

    for p in ipsec_packets:
        pair = tuple(sorted([p.source, p.destination]))
        ts = _parse_ts(p.timestamp)
        buckets = endpoint_groups[pair]

        prev_ts = last_timestamps.get(pair)
        # Split session on inactivity gap (> 300 seconds)
        if not buckets or (ts is not None and prev_ts is not None and (ts - prev_ts) > INACTIVITY_GAP_SECONDS):
            buckets.append([])

        buckets[-1].append(p)
        if ts is not None:
            last_timestamps[pair] = ts

    # 3. Process each session bucket
    sessions: list[VPNSessionFingerprint] = []
    sess_idx = 0

    for pair, buckets in endpoint_groups.items():
        for bucket in buckets:
            sess_idx += 1
            pkt_numbers = [p.number for p in bucket]
            timestamps = [t for t in (_parse_ts(p.timestamp) for p in bucket) if t is not None]
            start_ts = min(timestamps) if timestamps else None
            end_ts = max(timestamps) if timestamps else None
            duration = _format_duration(start_ts, end_ts)

            total_pkts = len(bucket)
            total_bytes = sum(p.length for p in bucket)

            ike_pkts = [p for p in bucket if p.ipsec.type == "IKE" and p.ipsec.ike]
            esp_pkts = [p for p in bucket if p.ipsec.type == "ESP" and p.ipsec.esp]
            ah_pkts = [p for p in bucket if p.ipsec.type == "AH" and p.ipsec.ah]

            # Protocols present
            protocols_set: set[str] = set()
            if ike_pkts:
                protocols_set.add("IKE")
            if esp_pkts:
                protocols_set.add("ESP")
            if ah_pkts:
                protocols_set.add("AH")
            protocols = sorted(list(protocols_set))

            # IKE SA characteristics
            ike_version: Optional[str] = None
            initiator_spi: Optional[str] = None
            responder_spi: Optional[str] = None
            encryption_algorithms: set[str] = set()
            integrity_algorithms: set[str] = set()
            dh_groups: set[str] = set()
            prf_algorithms: set[str] = set()
            has_delete = False

            for p in ike_pkts:
                ike = p.ipsec.ike
                if not ike_version and ike.version:
                    ike_version = ike.version
                if not initiator_spi and ike.initiator_spi and ike.initiator_spi != "0000000000000000":
                    initiator_spi = ike.initiator_spi
                if not responder_spi and ike.responder_spi and ike.responder_spi != "0000000000000000":
                    responder_spi = ike.responder_spi
                if ike.exchange_name in ("INFORMATIONAL", "Informational"):
                    # Check for Delete payloads or notify
                    for pl in ike.payloads:
                        if "DELETE" in pl.name.upper():
                            has_delete = True

                for prop in ike.proposals:
                    encryption_algorithms.update(prop.encryption_algorithms)
                    integrity_algorithms.update(prop.integrity_algorithms)
                    dh_groups.update(prop.dh_groups)
                    prf_algorithms.update(prop.prf_algorithms)

            # Child SAs
            child_spis_set: set[str] = set()
            for p in esp_pkts:
                child_spis_set.add(p.ipsec.esp.spi)
            for p in ah_pkts:
                child_spis_set.add(p.ipsec.ah.spi)
            child_sa_spis = sorted(list(child_spis_set))

            # Encapsulation mode & NAT-T
            encapsulation_mode = "TRANSPORT" if any(p.ipsec.encapsulation_mode == "TRANSPORT" for p in bucket) else "TUNNEL"
            nat_traversal = any(p.ipsec.nat_traversal for p in bucket)

            # Direction & Endpoints
            # Initiator is the source of the first packet or the first IKE request
            first_pkt = bucket[0]
            initiator_ip = first_pkt.source
            responder_ip = first_pkt.destination
            for p in ike_pkts:
                if "Initiator" in p.ipsec.ike.flags or p.ipsec.ike.message_id == 0:
                    initiator_ip = p.source
                    responder_ip = p.destination
                    break

            # State derivation
            if has_delete:
                state = "TERMINATED"
            elif esp_pkts or ah_pkts:
                state = "ACTIVE"
            elif any(p.ipsec.ike and p.ipsec.ike.exchange_name in ("IKE_AUTH", "Quick Mode") for p in ike_pkts):
                state = "ESTABLISHED"
            elif ike_pkts:
                state = "NEGOTIATING"
            else:
                state = "UNKNOWN"

            # 4. Build canonical components
            components = SessionFingerprintComponents(
                endpoint_pair=list(pair),
                protocols=protocols,
                ike_version=ike_version,
                initiator_spi=initiator_spi,
                responder_spi=responder_spi,
                child_spis=child_sa_spis,
                encapsulation_mode=encapsulation_mode,
                nat_traversal=nat_traversal,
                encryption_algorithms=sorted(list(encryption_algorithms)),
                integrity_algorithms=sorted(list(integrity_algorithms)),
                dh_groups=sorted(list(dh_groups)),
                prf_algorithms=sorted(list(prf_algorithms)),
            )

            # 5. Compute deterministic signature
            canonical_dict = components.to_canonical_dict()
            canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
            signature = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            short_sig = signature[:16]
            session_id = f"sess_{capture_id}_{short_sig}"

            crypto_summary = {
                "encryption": sorted(list(encryption_algorithms)),
                "integrity": sorted(list(integrity_algorithms)),
                "dh_groups": sorted(list(dh_groups)),
                "prf": sorted(list(prf_algorithms)),
            }

            sessions.append(
                VPNSessionFingerprint(
                    session_id=session_id,
                    capture_id=capture_id,
                    fingerprint=signature,
                    short_signature=short_sig,
                    initiator_ip=initiator_ip,
                    responder_ip=responder_ip,
                    endpoint_pair=list(pair),
                    protocols=protocols,
                    state=state,  # type: ignore[arg-type]
                    start_time=bucket[0].timestamp,
                    end_time=bucket[-1].timestamp,
                    duration_seconds=duration,
                    total_packets=total_pkts,
                    total_bytes=total_bytes,
                    ike_packets=len(ike_pkts),
                    esp_packets=len(esp_pkts),
                    ah_packets=len(ah_pkts),
                    ike_version=ike_version,
                    initiator_spi=initiator_spi,
                    responder_spi=responder_spi,
                    child_sa_spis=child_sa_spis,
                    encapsulation_mode=encapsulation_mode,
                    nat_traversal=nat_traversal,
                    packet_numbers=pkt_numbers,
                    crypto_summary=crypto_summary,
                    components=components,
                )
            )

    return sessions
