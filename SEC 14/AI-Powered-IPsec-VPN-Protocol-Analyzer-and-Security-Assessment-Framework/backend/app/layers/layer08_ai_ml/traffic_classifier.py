"""Layer 07 — AI/ML Traffic Classifier inside Encrypted ESP.

Performs multi-class classification on encrypted IPsec/ESP flows without payload decryption
by analysing packet sizing, inter-arrival time distributions, directional asymmetry, burst
dynamics and application-specific flow signatures.

Supported classes: VOIP, WHATSAPP, EMAIL, WEB_BROWSING, ICMP, VIDEO_STREAMING, OTHER.

Design rules that matter for correctness:

* Features are computed from **data-plane packets only** (ESP/AH). IKE control messages
  that precede or interleave a flow are excluded — an IKE handshake 300 ms before a VoIP
  stream must not inflate the inter-arrival variance of the stream.
* There is exactly **one** feature implementation (``FlowFeatures.from_packets``). The
  training pipeline extracts features from generated captures through the same decoder and
  the same function, so the model never sees a feature distribution it will not see at
  inference time (no train/serve skew).
* Sizes are on-wire frame lengths (Ethernet + outer IP + ESP overhead), so the "small
  packet" threshold is 300 bytes: a G.711 RTP frame is ~200 bytes inside and ~260–290
  bytes on the wire once tunnelled.
* The classifier abstains (predicts OTHER) when no class reaches the confidence floor.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None
import numpy as np
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.ipsec_session import IPsecSession
from app.models.traffic_classification import TrafficClassificationRow
from app.services.packet_service import packet_service

logger = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "models" / "traffic_classifier_supervised.joblib"
_CACHED_MODEL: Optional[Tuple[Any, List[str], str]] = None

SMALL_PACKET_MAX_BYTES = 300
MTU_PACKET_MIN_BYTES = 1200
IDLE_GAP_SECONDS = 1.0
CHUNK_GAP_SECONDS = 0.8
ABSTAIN_THRESHOLD = 0.45
FEATURE_VECTOR_VERSION = "2.0"

TARGET_CLASSES = ["VOIP", "WHATSAPP", "EMAIL", "WEB_BROWSING", "ICMP", "VIDEO_STREAMING", "OTHER"]

FEATURE_NAMES: List[str] = [
    "packet_count",
    "byte_count",
    "duration",
    "mean_iat",
    "iat_cv",
    "small_packet_ratio",
    "mtu_packet_ratio",
    "inbound_outbound_byte_ratio",
    "packets_per_second",
    "bytes_per_second",
    "chunk_burst_periodicity",
    "mos_score_estimate",
    "direction_asymmetry",
    "mean_packet_length",
    "packet_length_std",
    "packet_length_cv",
    "uplink_packet_ratio",
    "idle_gap_ratio",
    "max_gap_seconds",
    "length_entropy_bits",
    "burst_count",
    "median_iat",
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _epoch(ts: Any) -> Optional[float]:
    if ts is None or ts == "":
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(str(ts)).timestamp()
    except ValueError:
        try:
            return float(ts)
        except (TypeError, ValueError):
            return None


def _length_of(p: Any) -> int:
    return int(getattr(p, "original_length", 0) or getattr(p, "captured_length", 0) or getattr(p, "length", 0) or 0)


def _is_data_plane(p: Any) -> bool:
    ipsec = getattr(p, "ipsec", None)
    return ipsec is not None and (getattr(ipsec, "esp", None) is not None or getattr(ipsec, "ah", None) is not None)


class FlowFeatures:
    """Statistical features extracted from the data plane of one encrypted IPsec session."""

    def __init__(
        self,
        session_id: str,
        packet_count: int,
        byte_count: int,
        duration: float,
        mean_iat: float,
        iat_cv: float,
        small_packet_ratio: float,
        mtu_packet_ratio: float,
        inbound_outbound_byte_ratio: float,
        packets_per_second: float,
        bytes_per_second: float,
        chunk_burst_periodicity: Optional[float] = None,
        mos_score_estimate: Optional[float] = None,
        *,
        mean_packet_length: Optional[float] = None,
        packet_length_std: Optional[float] = None,
        packet_length_cv: Optional[float] = None,
        uplink_packet_ratio: Optional[float] = None,
        idle_gap_ratio: Optional[float] = None,
        max_gap_seconds: Optional[float] = None,
        length_entropy_bits: Optional[float] = None,
        burst_count: Optional[int] = None,
        median_iat: Optional[float] = None,
        provenance: str = "PACKETS",
    ):
        self.session_id = session_id
        self.packet_count = int(packet_count)
        self.byte_count = int(byte_count)
        self.duration = float(duration)
        self.mean_iat = float(mean_iat)
        self.iat_cv = float(iat_cv)
        self.small_packet_ratio = float(small_packet_ratio)
        self.mtu_packet_ratio = float(mtu_packet_ratio)
        self.inbound_outbound_byte_ratio = float(inbound_outbound_byte_ratio)
        self.packets_per_second = float(packets_per_second)
        self.bytes_per_second = float(bytes_per_second)
        self.chunk_burst_periodicity = chunk_burst_periodicity
        self.mos_score_estimate = mos_score_estimate
        avg_len = (self.byte_count / self.packet_count) if self.packet_count else 0.0
        self.mean_packet_length = float(mean_packet_length) if mean_packet_length is not None else avg_len
        self.packet_length_std = float(packet_length_std) if packet_length_std is not None else 0.0
        self.packet_length_cv = float(packet_length_cv) if packet_length_cv is not None else (self.packet_length_std / self.mean_packet_length if self.mean_packet_length else 0.0)
        self.uplink_packet_ratio = float(uplink_packet_ratio) if uplink_packet_ratio is not None else 0.5
        self.idle_gap_ratio = float(idle_gap_ratio) if idle_gap_ratio is not None else 0.0
        self.max_gap_seconds = float(max_gap_seconds) if max_gap_seconds is not None else self.mean_iat
        self.length_entropy_bits = float(length_entropy_bits) if length_entropy_bits is not None else 0.0
        self.burst_count = int(burst_count) if burst_count is not None else 1
        self.median_iat = float(median_iat) if median_iat is not None else self.mean_iat
        self.provenance = provenance

    # ---- derived ------------------------------------------------------------------------

    @property
    def iat_coefficient_of_variation(self) -> float:
        return self.iat_cv

    @property
    def direction_asymmetry(self) -> float:
        r = self.inbound_outbound_byte_ratio
        return abs(r - 1.0) / (r + 1.0) if r >= 0 else 0.0

    def vector(self) -> List[float]:
        values = {
            "packet_count": self.packet_count, "byte_count": self.byte_count, "duration": self.duration, "mean_iat": self.mean_iat,
            "iat_cv": self.iat_cv, "small_packet_ratio": self.small_packet_ratio, "mtu_packet_ratio": self.mtu_packet_ratio,
            "inbound_outbound_byte_ratio": self.inbound_outbound_byte_ratio, "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second, "chunk_burst_periodicity": self.chunk_burst_periodicity or 0.0,
            "mos_score_estimate": self.mos_score_estimate or 0.0, "direction_asymmetry": self.direction_asymmetry,
            "mean_packet_length": self.mean_packet_length, "packet_length_std": self.packet_length_std, "packet_length_cv": self.packet_length_cv,
            "uplink_packet_ratio": self.uplink_packet_ratio, "idle_gap_ratio": self.idle_gap_ratio, "max_gap_seconds": self.max_gap_seconds,
            "length_entropy_bits": self.length_entropy_bits, "burst_count": self.burst_count, "median_iat": self.median_iat,
        }
        return [float(values[name]) for name in FEATURE_NAMES]

    # ---- construction -------------------------------------------------------------------

    @classmethod
    def from_packets(cls, packets: Sequence[Any], session_id: str = "FLOW-01", initiator: Optional[str] = None) -> "FlowFeatures":
        """Compute features from decoded packets. IKE/non-IPsec packets are dropped when any data-plane packet exists."""
        pkts = list(packets)
        data = [p for p in pkts if _is_data_plane(p)]
        if data:
            pkts = data
        if not pkts:
            return cls(session_id, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, provenance="NONE")

        lengths = [_length_of(p) for p in pkts]
        packet_count = len(pkts)
        byte_count = sum(lengths)

        stamped = sorted(((t, p) for p in pkts if (t := _epoch(getattr(p, "timestamp", None))) is not None), key=lambda x: x[0])
        timestamps = [t for t, _ in stamped]
        gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
        if len(timestamps) >= 2:
            duration = max(0.001, timestamps[-1] - timestamps[0])
            mean_iat = sum(gaps) / len(gaps)
            var = sum((g - mean_iat) ** 2 for g in gaps) / len(gaps)
            std_iat = math.sqrt(var)
            iat_cv = (std_iat / mean_iat) if mean_iat > 0 else 0.0
            srt = sorted(gaps)
            median_iat = srt[len(srt) // 2]
            max_gap = max(gaps)
            idle = [g for g in gaps if g >= IDLE_GAP_SECONDS]
            idle_ratio = len(idle) / len(gaps)
            burst_count = 1 + len(idle)
            large = [g for g in gaps if g >= CHUNK_GAP_SECONDS]
            periodicity = (sum(large) / len(large)) if len(large) >= 2 else None
        else:
            duration, mean_iat, std_iat, iat_cv, median_iat, max_gap, idle_ratio, burst_count, periodicity = 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1, None

        pps = packet_count / duration
        bps = byte_count / duration
        small_ratio = sum(1 for l in lengths if l <= SMALL_PACKET_MAX_BYTES) / packet_count
        mtu_ratio = sum(1 for l in lengths if l >= MTU_PACKET_MIN_BYTES) / packet_count
        mean_len = byte_count / packet_count
        std_len = math.sqrt(sum((l - mean_len) ** 2 for l in lengths) / packet_count)
        bins = Counter(l // 64 for l in lengths)
        entropy = -sum((c / packet_count) * math.log2(c / packet_count) for c in bins.values())

        sources = [getattr(p, "source", None) for p in pkts]
        if initiator is None:
            ordered = [t_p[1] for t_p in stamped] or pkts
            initiator = getattr(ordered[0], "source", None) or (Counter(s for s in sources if s).most_common(1)[0][0] if any(sources) else None)
        up_bytes = sum(l for p, l in zip(pkts, lengths) if getattr(p, "source", None) == initiator)
        down_bytes = byte_count - up_bytes
        up_pkts = sum(1 for p in pkts if getattr(p, "source", None) == initiator)
        io_ratio = (down_bytes / up_bytes) if up_bytes > 0 else (float(down_bytes) if down_bytes else 1.0)
        io_ratio = max(0.0, min(io_ratio, 1000.0))

        # ITU-T G.107 E-model style estimate, only meaningful for small isochronous frames.
        mos = None
        if small_ratio >= 0.60 and 0.0 < mean_iat <= 0.050 and len(timestamps) >= 2:
            jitter_ms = std_iat * 1000.0
            r_val = max(0.0, min(100.0, 93.2 - (0.024 * mean_iat * 1000) - (0.11 * jitter_ms)))
            mos = 1.0 + 0.035 * r_val + r_val * (r_val - 60.0) * (100.0 - r_val) * 7e-6
            mos = max(1.0, min(4.5, mos))

        return cls(
            session_id=session_id, packet_count=packet_count, byte_count=byte_count, duration=duration, mean_iat=mean_iat, iat_cv=iat_cv,
            small_packet_ratio=small_ratio, mtu_packet_ratio=mtu_ratio, inbound_outbound_byte_ratio=io_ratio, packets_per_second=pps,
            bytes_per_second=bps, chunk_burst_periodicity=periodicity, mos_score_estimate=mos, mean_packet_length=mean_len,
            packet_length_std=std_len, packet_length_cv=(std_len / mean_len if mean_len else 0.0), uplink_packet_ratio=up_pkts / packet_count,
            idle_gap_ratio=idle_ratio, max_gap_seconds=max_gap, length_entropy_bits=entropy, burst_count=burst_count, median_iat=median_iat,
            provenance="PACKETS",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 4),
            "mean_iat": round(self.mean_iat, 6),
            "iat_cv": round(self.iat_cv, 4),
            "small_packet_ratio": round(self.small_packet_ratio, 4),
            "mtu_packet_ratio": round(self.mtu_packet_ratio, 4),
            "inbound_outbound_byte_ratio": round(self.inbound_outbound_byte_ratio, 4),
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "chunk_burst_periodicity": round(self.chunk_burst_periodicity, 4) if self.chunk_burst_periodicity else None,
            "mos_score_estimate": round(self.mos_score_estimate, 2) if self.mos_score_estimate else None,
            "direction_asymmetry": round(self.direction_asymmetry, 4),
            "mean_packet_length": round(self.mean_packet_length, 2),
            "packet_length_std": round(self.packet_length_std, 2),
            "packet_length_cv": round(self.packet_length_cv, 4),
            "uplink_packet_ratio": round(self.uplink_packet_ratio, 4),
            "idle_gap_ratio": round(self.idle_gap_ratio, 4),
            "max_gap_seconds": round(self.max_gap_seconds, 4),
            "length_entropy_bits": round(self.length_entropy_bits, 4),
            "burst_count": self.burst_count,
            "median_iat": round(self.median_iat, 6),
            "feature_vector_version": FEATURE_VECTOR_VERSION,
            "provenance": self.provenance,
        }


@dataclass
class TrafficPrediction:
    predicted_type: str
    confidence: float
    probabilities: Dict[str, float]
    explanations: List[Dict[str, Any]]
    abstained: bool = False
    model_version: Optional[str] = None
    rule_probabilities: Dict[str, float] = field(default_factory=dict)
    ml_probabilities: Dict[str, float] = field(default_factory=dict)

    @property
    def explanation(self) -> str:
        return " ".join([e.get("reason", "") for e in self.explanations])

    def __iter__(self):
        return iter((self.predicted_type, self.confidence, self.probabilities, self.explanations))

    def __getitem__(self, index):
        return (self.predicted_type, self.confidence, self.probabilities, self.explanations)[index]

    def __len__(self):
        return 4


class TrafficClassifier:
    """Evaluates encrypted flows against calibrated probabilistic traffic signatures."""

    RULE_WEIGHT_WITH_MODEL = 0.35     # rule-scorer weight while the supervised model is confident (top prob ≥ 0.80)
    RULE_WEIGHT_MODEL_UNSURE = 0.65   # rule-scorer weight once the model's top probability falls to ≤ 0.50

    @classmethod
    def _rule_weight(cls, ml_top_probability: float) -> float:
        """Uncertainty-gated ensemble weight.

        The supervised model is trained on testbed flows; when a flow falls outside that distribution its
        posterior flattens (top probability drops). The signature rules encode physical constraints
        (packetisation cadence, MTU trains, chunk periodicity) that transfer across generators, so their
        weight rises linearly as the model's top probability falls from 0.80 to 0.50.
        """
        if ml_top_probability >= 0.80:
            return cls.RULE_WEIGHT_WITH_MODEL
        if ml_top_probability <= 0.50:
            return cls.RULE_WEIGHT_MODEL_UNSURE
        span = (0.80 - ml_top_probability) / 0.30
        return cls.RULE_WEIGHT_WITH_MODEL + span * (cls.RULE_WEIGHT_MODEL_UNSURE - cls.RULE_WEIGHT_WITH_MODEL)

    @classmethod
    def get_supervised_model(cls) -> Optional[Tuple[Any, List[str], str]]:
        global _CACHED_MODEL
        if _CACHED_MODEL is not None:
            return _CACHED_MODEL
        if joblib is None or not _MODEL_PATH.exists():
            return None
        try:
            artifact = joblib.load(_MODEL_PATH)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load supervised traffic classifier: %s", exc)
            return None
        if isinstance(artifact, dict) and "model" in artifact:
            _CACHED_MODEL = (artifact["model"], list(artifact.get("feature_names") or FEATURE_NAMES), str(artifact.get("version") or "unknown"))
        else:
            _CACHED_MODEL = (artifact, FEATURE_NAMES[:13], "legacy-1.0")
        logger.info("Loaded supervised traffic classifier %s from %s", _CACHED_MODEL[2], _MODEL_PATH)
        return _CACHED_MODEL

    @classmethod
    def reset_model_cache(cls) -> None:
        global _CACHED_MODEL
        _CACHED_MODEL = None

    @classmethod
    def extract_flow_features(cls, session: IPsecSession) -> FlowFeatures:
        """Derive flow features from the session's ESP/AH packets (IKE control traffic excluded)."""
        if packet_service.capture_id == session.capture_id:
            links = list(session.packets)
            data_links = [sp for sp in links if (sp.role or "").upper() in ("ESP", "AH")] or links
            packets = [p for sp in data_links if (p := packet_service.by_number(sp.packet_number)) is not None]
            if packets:
                return FlowFeatures.from_packets(packets, session_id=session.id, initiator=session.source)

        # Capture no longer loaded: only the session aggregate is known. Report it as such; the
        # classifier will most likely abstain rather than guess from invented ratios.
        data_count = int((session.esp_packets or 0) + (session.ah_packets or 0)) or int(session.packet_count or 0)
        duration = max(0.001, float(session.duration_seconds or 1.0))
        return FlowFeatures(
            session_id=session.id, packet_count=data_count, byte_count=int(session.byte_count or 0), duration=duration,
            mean_iat=duration / max(1, data_count), iat_cv=0.0, small_packet_ratio=0.0, mtu_packet_ratio=0.0,
            inbound_outbound_byte_ratio=1.0, packets_per_second=data_count / duration, bytes_per_second=int(session.byte_count or 0) / duration,
            provenance="SESSION_AGGREGATE",
        )

    # ------------------------------------------------------------------ #

    @classmethod
    def _rule_scores(cls, f: FlowFeatures) -> Tuple[Dict[str, float], List[Dict[str, Any]]]:
        raw: Dict[str, float] = {}
        expl: List[Dict[str, Any]] = []

        def note(feature: str, value: Any, influence: str, reason: str) -> None:
            expl.append({"feature": feature, "value": value, "influence": influence, "reason": reason})

        # VOIP — isochronous ~20 ms cadence, low jitter, small frames, symmetric
        s = 0.0
        if 0.012 <= f.mean_iat <= 0.038:
            s += 4.5
            note("mean_interarrival_time", round(f.mean_iat, 4), "+4.5 towards VOIP", f"Inter-arrival {f.mean_iat*1000:.1f} ms matches the 20ms RTP packetisation cadence (ptime=20).")
        elif 0.008 <= f.mean_iat <= 0.060:
            s += 2.0
        if f.iat_cv < 0.35:
            s += 3.5
            note("iat_coefficient_of_variation", round(f.iat_cv, 4), "+3.5 towards VOIP", "Isochronous delivery with very low jitter, characteristic of real-time voice.")
        elif f.iat_cv < 0.60:
            s += 1.5
        if f.small_packet_ratio > 0.65 and f.mean_iat <= 0.12:
            s += 3.0
            note("small_packet_ratio", round(f.small_packet_ratio, 4), "+3.0 towards VOIP", f"{f.small_packet_ratio*100:.1f}% of frames are ≤ {SMALL_PACKET_MAX_BYTES} bytes on the wire, matching G.711/G.729/Opus voice frames inside ESP.")
        if 0.3 <= f.inbound_outbound_byte_ratio <= 3.0:
            s += 1.0
        if f.packet_length_cv < 0.25 and f.small_packet_ratio > 0.65:
            s += 1.0
        raw["VOIP"] = s

        # WHATSAPP — conversational bursts, keepalives, low rate, idle gaps
        s = 0.0
        if f.packets_per_second < 8.0 and f.duration > 5.0:
            s += 3.5
            note("packets_per_second", round(f.packets_per_second, 2), "+3.5 towards WHATSAPP", "Low average packet rate with conversational idle gaps typical of messaging.")
        if f.iat_cv > 0.85:
            s += 2.5
        if f.idle_gap_ratio > 0.25 and f.mtu_packet_ratio < 0.20:
            s += 3.0
            note("idle_gap_ratio", round(f.idle_gap_ratio, 3), "+3.0 towards WHATSAPP", f"{f.idle_gap_ratio*100:.0f}% of intervals are idle gaps ≥ 1 s between short message bursts.")
        if 0.40 <= f.small_packet_ratio <= 1.0 and f.mtu_packet_ratio < 0.20:
            s += 2.0
        raw["WHATSAPP"] = s

        # EMAIL — short command/response phase then one bulk train
        s = 0.0
        if 0.35 <= f.mtu_packet_ratio <= 0.85:
            s += 3.0
            note("mtu_packet_ratio", round(f.mtu_packet_ratio, 4), "+3.0 towards EMAIL", "Bulk MIME transfer segments alongside small command/response frames.")
        if f.small_packet_ratio > 0.10 and f.mtu_packet_ratio > 0.35:
            s += 3.5
            note("bimodal_sizing", f"small={f.small_packet_ratio:.2f}, mtu={f.mtu_packet_ratio:.2f}", "+3.5 towards EMAIL", "Bimodal size distribution: protocol commands plus a unidirectional data train.")
        if (1.5 <= f.inbound_outbound_byte_ratio <= 15.0 or 0.05 <= f.inbound_outbound_byte_ratio <= 0.65) and f.mtu_packet_ratio > 0.35:
            s += 2.0
        if f.chunk_burst_periodicity is None and f.mtu_packet_ratio > 0.35 and f.burst_count <= 3:
            s += 2.5
            note("single_bulk_train", f"bursts={f.burst_count}", "+2.5 towards EMAIL", "One continuous bulk delivery without periodic streaming chunks.")
        raw["EMAIL"] = s

        # VIDEO_STREAMING — periodic segment bursts, heavy downlink, MTU-sized
        s = 0.0
        if f.chunk_burst_periodicity is not None and 1.2 <= f.chunk_burst_periodicity <= 10.0:
            s += 5.0
            note("chunk_burst_periodicity", round(f.chunk_burst_periodicity, 2), "+5.0 towards VIDEO_STREAMING", f"Periodic bursts every {f.chunk_burst_periodicity:.1f} s match HLS/DASH video segment (chunk) fetches.")
        if f.inbound_outbound_byte_ratio > 4.0 or f.inbound_outbound_byte_ratio < 0.25:
            s += 3.5 if f.chunk_burst_periodicity is not None else 1.5
        if f.mtu_packet_ratio > 0.60:
            s += 3.5 if f.small_packet_ratio < 0.35 else 1.0
        if f.bytes_per_second > 50000.0:
            s += 1.5
        raw["VIDEO_STREAMING"] = s

        # WEB_BROWSING — request bursts, multimodal sizes, moderate downlink asymmetry
        s = 0.0
        if 0.15 <= f.small_packet_ratio <= 0.75 and 0.05 <= f.mtu_packet_ratio <= 0.60:
            s += 3.5
            note("web_sizing_distribution", f"small={f.small_packet_ratio:.2f}, mtu={f.mtu_packet_ratio:.2f}", "+3.5 towards WEB_BROWSING", "Multimodal frame sizes: HTTP requests plus HTML/JS/image responses.")
        if 1.2 <= f.inbound_outbound_byte_ratio <= 12.0:
            s += 2.0
        if 0.02 <= f.mean_iat <= 0.60 and 0.4 <= f.iat_cv <= 3.0:
            s += 1.5
        if f.burst_count >= 3 and f.idle_gap_ratio > 0.05 and f.mtu_packet_ratio > 0.10:
            s += 3.0
            note("page_load_bursts", f"bursts={f.burst_count}", "+3.0 towards WEB_BROWSING", "Several page-load bursts separated by think-time gaps.")
        raw["WEB_BROWSING"] = s

        # ICMP — 1 s cadence, uniform small frames, 1:1 symmetry
        s = 0.0
        if f.small_packet_ratio >= 0.85 and f.mtu_packet_ratio == 0.0 and 0.80 <= f.inbound_outbound_byte_ratio <= 1.25:
            s += 4.5
            note("symmetric_small_packets", f"small={f.small_packet_ratio:.2f}, ratio={f.inbound_outbound_byte_ratio:.2f}", "+4.5 towards ICMP", "Symmetric, uniformly sized small frames characteristic of echo request/reply pairs.")
        if 0.40 <= f.mean_iat <= 1.20 and f.iat_cv <= 1.10 and f.median_iat <= 1.05:
            s += 4.0
            note("ping_cadence", f"iat={f.mean_iat:.2f}s, cv={f.iat_cv:.2f}", "+4.0 towards ICMP", "≈1 s request/reply cadence consistent with ping diagnostics.")
        if f.packet_length_cv < 0.05 and f.small_packet_ratio >= 0.85:
            s += 1.5
        raw["ICMP"] = s

        raw["OTHER"] = 2.0
        return raw, expl

    @classmethod
    def classify(cls, features: FlowFeatures) -> TrafficPrediction:
        """Compute multi-class probabilities and explainability for the flow."""
        if features.packet_count == 0 or features.provenance == "NONE":
            probs = {c: (1.0 if c == "OTHER" else 0.0) for c in TARGET_CLASSES}
            return TrafficPrediction("OTHER", 0.0, probs, [{"feature": "data_packets", "value": 0, "influence": "abstained", "reason": "No ESP/AH data-plane packets are available for this session; no traffic prediction is made."}], abstained=True, model_version=None)

        raw_scores, explanations = cls._rule_scores(features)
        exp_scores = {k: math.exp(v) for k, v in raw_scores.items()}
        total = sum(exp_scores.values())
        rule_probs = {k: v / total for k, v in exp_scores.items()}
        probabilities = dict(rule_probs)
        ml_probs: Dict[str, float] = {}
        model_version: Optional[str] = None
        gate_note: Optional[Dict[str, Any]] = None

        loaded = cls.get_supervised_model()
        if loaded is not None and features.provenance == "PACKETS":
            model, feature_names, model_version = loaded
            try:
                full = dict(zip(FEATURE_NAMES, features.vector()))
                x = np.array([[full.get(name, 0.0) for name in feature_names]])
                vec = model.predict_proba(x)[0]
                ml_probs = {str(c): float(p) for c, p in zip(list(model.classes_), vec)}
                # Physical-constraint calibration: a class whose defining cadence is impossible gets zeroed.
                if (features.iat_cv > 1.5 or features.mean_iat < 0.20) and "ICMP" in ml_probs and features.small_packet_ratio < 0.85:
                    ml_probs["ICMP"] = 0.0
                if (features.iat_cv > 1.2 or features.mean_iat > 0.12) and "VOIP" in ml_probs:
                    ml_probs["VOIP"] = 0.0
                s = sum(ml_probs.values())
                if s > 0:
                    ml_probs = {k: v / s for k, v in ml_probs.items()}
                    ml_top = max(ml_probs.values())
                    w = cls._rule_weight(ml_top)
                    keys = set(rule_probs) | set(ml_probs)
                    blended = {k: w * rule_probs.get(k, 0.0) + (1 - w) * ml_probs.get(k, 0.0) for k in keys}
                    bs = sum(blended.values()) or 1.0
                    probabilities = {k: v / bs for k, v in blended.items()}
                    if w > cls.RULE_WEIGHT_WITH_MODEL:
                        gate_note = {"feature": "ensemble_gate", "value": round(w, 2), "influence": "rules weighted up",
                                     "reason": f"The supervised model's top probability was only {ml_top:.0%} (flow outside its training "
                                               f"distribution), so the physical-signature rules carry {w:.0%} of the decision."}
            except Exception as exc:  # noqa: BLE001
                logger.warning("Supervised prediction error, using rule probabilities: %s", exc)

        probabilities = {k: round(v, 4) for k, v in probabilities.items() if k in TARGET_CLASSES}
        predicted = max(probabilities.items(), key=lambda kv: kv[1])[0]
        confidence = float(probabilities[predicted])
        abstained = False
        if confidence < ABSTAIN_THRESHOLD or features.provenance != "PACKETS":
            abstained = True
            predicted = "OTHER"
        relevant = [e for e in explanations if predicted in e["influence"]]
        if gate_note is not None:
            relevant.append(gate_note)
        if abstained:
            relevant.append({"feature": "confidence_floor", "value": round(confidence, 3), "influence": "abstained → OTHER",
                             "reason": f"No class reached the {ABSTAIN_THRESHOLD:.0%} confidence floor"
                                       + (" (features come from the session aggregate, not packets)" if features.provenance != "PACKETS" else "")
                                       + "; the flow is reported as OTHER rather than guessed."})
        elif not relevant:
            relevant.append({"feature": "supervised_model", "value": model_version or "rules", "influence": f"classified as {predicted}",
                             "reason": f"Supervised model classified the flow as {predicted} ({confidence*100:.1f}% confidence) from the {len(FEATURE_NAMES)}-feature observable flow vector."})
        return TrafficPrediction(predicted, round(confidence, 4), probabilities, relevant, abstained=abstained, model_version=model_version,
                                 rule_probabilities={k: round(v, 4) for k, v in rule_probs.items()}, ml_probabilities={k: round(v, 4) for k, v in ml_probs.items()})


class TrafficClassificationService:
    """Coordinates persistence, querying, and execution of Layer 07 traffic classification."""

    def __init__(self, db: Session):
        self.db = db

    def classify_session(self, session: IPsecSession) -> TrafficClassificationRow:
        features = TrafficClassifier.extract_flow_features(session)
        prediction = TrafficClassifier.classify(features)
        probs = prediction.probabilities

        existing = self.db.scalar(select(TrafficClassificationRow).where(TrafficClassificationRow.session_id == session.id))

        # Persist the full SIH class distribution (VoIP, WhatsApp, e-mail, web, ICMP, video, other), normalised.
        raw = {k: float(probs.get(k, 0.0)) for k in TARGET_CLASSES}
        total = sum(raw.values()) or 1.0
        probs_5 = {k: round(v / total, 4) for k, v in raw.items()}

        explanations = list(prediction.explanations)
        explanations.append({"feature": "_meta", "value": prediction.model_version or "rules-only", "abstained": prediction.abstained,
                             "influence": "model", "reason": f"Feature vector v{FEATURE_VECTOR_VERSION} from {features.packet_count} data-plane packets ({features.provenance})."})

        flow_id = f"FLOW-{session.source}-{session.destination}"
        if existing:
            existing.traffic_type = prediction.predicted_type
            existing.confidence = prediction.confidence
            existing.probabilities_json = json.dumps(probs_5)
            existing.features_json = json.dumps(features.to_dict())
            existing.explainability_json = json.dumps(explanations)
            self.db.commit()
            self.db.refresh(existing)
            return existing

        row = TrafficClassificationRow(
            id=f"TC-{uuid.uuid4().hex[:12].upper()}", capture_id=session.capture_id, session_id=session.id, flow_id=flow_id,
            traffic_type=prediction.predicted_type, confidence=prediction.confidence, probabilities_json=json.dumps(probs_5),
            features_json=json.dumps(features.to_dict()), explainability_json=json.dumps(explanations), created_at=_utc_now(),
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def classify_capture(self, capture_id: str) -> List[TrafficClassificationRow]:
        sessions = self.db.scalars(select(IPsecSession).where(IPsecSession.capture_id == capture_id)).all()
        return [self.classify_session(s) for s in sessions]

    def get_by_session(self, session_id: str) -> Optional[TrafficClassificationRow]:
        return self.db.scalar(select(TrafficClassificationRow).where(TrafficClassificationRow.session_id == session_id))

    def get_by_capture(self, capture_id: str) -> List[TrafficClassificationRow]:
        if not capture_id or capture_id == "default":
            return list(self.db.scalars(select(TrafficClassificationRow).order_by(desc(TrafficClassificationRow.confidence))).all())
        rows = self.db.scalars(
            select(TrafficClassificationRow).where(TrafficClassificationRow.capture_id == capture_id).order_by(desc(TrafficClassificationRow.confidence))
        ).all()
        if not rows:
            sessions = self.db.scalars(select(IPsecSession).where(IPsecSession.capture_id == capture_id)).all()
            if sessions:
                rows = self.classify_capture(capture_id)
        return list(rows)

    def get_summary(self, capture_id: str) -> Dict[str, Any]:
        rows = self.get_by_capture(capture_id)
        distribution: Dict[str, int] = {"VOIP": 0, "WHATSAPP": 0, "EMAIL": 0, "VIDEO_STREAMING": 0, "WEB_BROWSING": 0, "ICMP": 0, "OTHER": 0, "GENERIC": 0}
        for r in rows:
            distribution[r.traffic_type] = distribution.get(r.traffic_type, 0) + 1
        avg_conf = (sum(r.confidence for r in rows) / len(rows)) if rows else 0.0
        return {
            "capture_id": capture_id,
            "total_classified": len(rows),
            "distribution": distribution,
            "voip_count": distribution.get("VOIP", 0),
            "whatsapp_count": distribution.get("WHATSAPP", 0),
            "email_count": distribution.get("EMAIL", 0),
            "video_streaming_count": distribution.get("VIDEO_STREAMING", 0),
            "web_browsing_count": distribution.get("WEB_BROWSING", 0),
            "icmp_count": distribution.get("ICMP", 0),
            "other_count": distribution.get("OTHER", 0) + distribution.get("GENERIC", 0),
            "generic_count": distribution.get("GENERIC", 0) + distribution.get("OTHER", 0),
            "average_confidence": round(avg_conf, 4),
        }
