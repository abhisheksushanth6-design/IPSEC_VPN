"""CIC-IDS2017 / CICFlowMeter feature contract used by the local XGBoost model.

These names match the ISCX CSV column headers after stripping whitespace.
Session-level IPsec features are mapped onto this contract at inference time so
the locally trained model can score VPN sessions without a cloud LLM.
"""

from __future__ import annotations

from typing import Any, Dict, List

import numpy as np

CIC_FEATURES: List[str] = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Down/Up Ratio",
]

CICIDS_FEATURE_VERSION = "cicids-flow-1.0"
CICIDS_MODEL_ID = "model_cicids_xgb_local"
CICIDS_MODEL_TYPE = "XGBoost"


def _f(feat: Dict[str, Any], key: str, default: float = 0.0) -> float:
    value = feat.get(key)
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def session_features_to_cic_vector(feat: Dict[str, Any]) -> np.ndarray:
    """Approximate CICFlowMeter columns from Layer 05 session aggregates.

    IPsec session vectors do not split packet-size stats by direction. Forward
    (outbound) and backward (inbound) volume/count are preserved; length and IAT
    statistics are shared across directions when directional stats are absent.
    Duration and IAT values that look like seconds are converted to microseconds
    to match CIC-IDS2017.
    """
    duration_s = max(_f(feat, "session_duration_seconds"), 0.0)
    duration_us = duration_s * 1_000_000.0

    fwd_pkts = _f(feat, "outbound_packet_count")
    bwd_pkts = _f(feat, "inbound_packet_count")
    if fwd_pkts == 0.0 and bwd_pkts == 0.0:
        total = _f(feat, "packet_count")
        symmetry = _f(feat, "traffic_symmetry_ratio", 1.0)
        if symmetry <= 0:
            symmetry = 1.0
        fwd_pkts = total / (1.0 + symmetry)
        bwd_pkts = total - fwd_pkts

    fwd_bytes = _f(feat, "outbound_byte_count")
    bwd_bytes = _f(feat, "inbound_byte_count")
    if fwd_bytes == 0.0 and bwd_bytes == 0.0:
        total_bytes = _f(feat, "byte_count")
        pkt_total = fwd_pkts + bwd_pkts
        if pkt_total > 0:
            fwd_bytes = total_bytes * (fwd_pkts / pkt_total)
            bwd_bytes = total_bytes - fwd_bytes
        else:
            fwd_bytes = total_bytes

    pkt_max = _f(feat, "maximum_packet_size")
    pkt_min = _f(feat, "minimum_packet_size")
    pkt_mean = _f(feat, "average_packet_size")
    pkt_std = _f(feat, "packet_size_standard_deviation")

    iat_mean = _f(feat, "mean_interarrival_time") * 1_000_000.0
    iat_var = _f(feat, "interarrival_variance")
    iat_std = float(np.sqrt(max(iat_var, 0.0))) * 1_000_000.0
    iat_max = _f(feat, "max_interarrival_time") * 1_000_000.0
    iat_min = _f(feat, "min_interarrival_time") * 1_000_000.0

    bytes_per_s = _f(feat, "byte_rate")
    pkts_per_s = _f(feat, "packet_rate")
    if duration_s > 0:
        if bytes_per_s == 0.0:
            bytes_per_s = (fwd_bytes + bwd_bytes) / duration_s
        if pkts_per_s == 0.0:
            pkts_per_s = (fwd_pkts + bwd_pkts) / duration_s

    down_up = (bwd_pkts / fwd_pkts) if fwd_pkts > 0 else _f(feat, "traffic_symmetry_ratio", 0.0)

    values = [
        duration_us,
        fwd_pkts,
        bwd_pkts,
        fwd_bytes,
        bwd_bytes,
        pkt_max,
        pkt_min,
        pkt_mean,
        pkt_std,
        pkt_max,
        pkt_min,
        pkt_mean,
        pkt_std,
        bytes_per_s,
        pkts_per_s,
        iat_mean,
        iat_std,
        iat_max,
        iat_min,
        duration_us,
        iat_mean,
        iat_std,
        iat_max,
        iat_min,
        duration_us,
        iat_mean,
        iat_std,
        iat_max,
        iat_min,
        down_up,
    ]
    vector = np.asarray(values, dtype=np.float64)
    vector[~np.isfinite(vector)] = 0.0
    return vector
