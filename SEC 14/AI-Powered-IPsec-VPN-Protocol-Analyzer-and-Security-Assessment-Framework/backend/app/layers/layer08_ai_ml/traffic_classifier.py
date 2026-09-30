"""Layer 08 — AI/ML Traffic Classifier inside Encrypted ESP.

Performs multi-class classification on encrypted IPsec/ESP flows without payload decryption
by analyzing packet sizing, inter-arrival time distributions, directional asymmetry,
burst dynamics, and application-specific flow signatures.

Supported classes:
- VOIP: Isochronous 20ms RTP cadences, small symmetric packets, MOS score estimation.
- WHATSAPP: Intermittent chat bursts, presence keepalives, mixed chat/media sizes.
- EMAIL: Command-response handshake followed by unidirectional MIME bulk transfer.
- VIDEO_STREAMING: Periodic HLS/DASH chunk download bursts, high downlink asymmetry, MTU packets.
- GENERIC: General encrypted VPN tunnel traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import math
from pathlib import Path
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import joblib
except ImportError:
    joblib = None
import numpy as np
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.ipsec_session import IPsecSession
from app.models.traffic_classification import TrafficClassificationRow
from app.services.packet_service import packet_service

logger = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "models" / "traffic_classifier_supervised.joblib"
_CACHED_MODEL = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FlowFeatures:
    """Statistical features extracted from an encrypted IPsec session."""

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
    ):
        self.session_id = session_id
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.duration = duration
        self.mean_iat = mean_iat
        self.iat_cv = iat_cv
        self.small_packet_ratio = small_packet_ratio
        self.mtu_packet_ratio = mtu_packet_ratio
        self.inbound_outbound_byte_ratio = inbound_outbound_byte_ratio
        self.packets_per_second = packets_per_second
        self.bytes_per_second = bytes_per_second
        self.chunk_burst_periodicity = chunk_burst_periodicity
        self.mos_score_estimate = mos_score_estimate

    @property
    def iat_coefficient_of_variation(self) -> float:
        return self.iat_cv

    @property
    def direction_asymmetry(self) -> float:
        r = self.inbound_outbound_byte_ratio
        return abs(r - 1.0) / (r + 1.0)

    @classmethod
    def from_packets(cls, packets: List[Any], session_id: str = "FLOW-01") -> "FlowFeatures":
        packet_count = len(packets)
        byte_count = sum(getattr(p, "captured_length", getattr(p, "length", 0)) for p in packets)

        timestamps = []
        for p in packets:
            ts_val = getattr(p, "timestamp", None)
            if ts_val:
                try:
                    if isinstance(ts_val, (int, float)):
                        timestamps.append(float(ts_val))
                    else:
                        timestamps.append(datetime.fromisoformat(str(ts_val)).timestamp())
                except Exception:
                    pass
        timestamps.sort()

        if len(timestamps) >= 2:
            duration = max(0.001, timestamps[-1] - timestamps[0])
            gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            mean_iat = sum(gaps) / len(gaps) if gaps else 0.02
            variance = sum((g - mean_iat) ** 2 for g in gaps) / len(gaps) if gaps else 0.0
            std_dev = math.sqrt(variance)
            iat_cv = (std_dev / mean_iat) if mean_iat > 0 else 0.0
        else:
            duration = 1.0
            mean_iat = 0.02
            std_dev = 0.002
            iat_cv = 0.1
            gaps = []

        pps = packet_count / duration
        bps = byte_count / duration

        lengths = [getattr(p, "captured_length", getattr(p, "length", 0)) for p in packets]
        small_count = sum(1 for l in lengths if l <= 220)
        mtu_count = sum(1 for l in lengths if l >= 1400)
        small_ratio = small_count / max(1, packet_count)
        mtu_ratio = mtu_count / max(1, packet_count)

        srcs = [getattr(p, "source", None) for p in packets if getattr(p, "source", None)]
        if srcs:
            primary_src = max(set(srcs), key=srcs.count)
            fwd_bytes = sum(getattr(p, "captured_length", 0) for p in packets if getattr(p, "source", None) == primary_src)
            rev_bytes = byte_count - fwd_bytes
            in_out_ratio = (fwd_bytes / max(1, rev_bytes))
        else:
            in_out_ratio = 1.0

        # Chunk burst periodicity
        large_gaps = [g for g in gaps if g >= 0.8] if len(timestamps) >= 2 else []
        periodicity = (sum(large_gaps) / len(large_gaps)) if len(large_gaps) >= 2 else None

        # MOS estimate for small packet streams
        mos = None
        if small_ratio >= 0.60 and mean_iat <= 0.050:
            jitter_ms = (std_dev * 1000.0) if len(timestamps) >= 2 else 2.0
            r_val = 93.2 - (0.024 * mean_iat * 1000) - (0.11 * jitter_ms)
            r_clamped = max(0.0, min(100.0, r_val))
            mos = 1.0 + 0.035 * r_clamped + r_clamped * (r_clamped - 60.0) * (100.0 - r_clamped) * 7e-6
            mos = max(1.0, min(4.5, mos))

        return cls(
            session_id=session_id,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            mean_iat=mean_iat,
            iat_cv=iat_cv,
            small_packet_ratio=small_ratio,
            mtu_packet_ratio=mtu_ratio,
            inbound_outbound_byte_ratio=in_out_ratio,
            packets_per_second=pps,
            bytes_per_second=bps,
            chunk_burst_periodicity=periodicity,
            mos_score_estimate=mos,
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
        }


@dataclass
class TrafficPrediction:
    predicted_type: str
    confidence: float
    probabilities: Dict[str, float]
    explanations: List[Dict[str, Any]]

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

    @classmethod
    def get_supervised_model(cls) -> Any:
        global _CACHED_MODEL
        if _CACHED_MODEL is not None:
            return _CACHED_MODEL
        if joblib is not None and _MODEL_PATH.exists():
            try:
                _CACHED_MODEL = joblib.load(_MODEL_PATH)
                logger.info("Loaded supervised traffic classifier from %s", _MODEL_PATH)
                return _CACHED_MODEL
            except Exception as exc:
                logger.warning("Could not load supervised traffic classifier: %s", exc)
        return None

    @classmethod
    def extract_flow_features(cls, session: IPsecSession) -> FlowFeatures:
        """Derive flow features directly from session record and linked packet data."""
        # Query associated packets from packet_service if available
        packets = [
            p for sp in session.packets
            if (p := packet_service.by_number(sp.packet_number)) is not None
        ] if packet_service.capture_id == session.capture_id else []

        duration = max(0.001, session.duration_seconds or 1.0)
        pps = session.packet_count / duration
        bps = session.byte_count / duration

        if packets and len(packets) >= 2:
            timestamps = []
            for p in packets:
                if p.timestamp:
                    try:
                        ts = datetime.fromisoformat(p.timestamp).timestamp()
                        timestamps.append(ts)
                    except ValueError:
                        pass
            timestamps.sort()
            gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))] if len(timestamps) >= 2 else [0.05]
            mean_iat = sum(gaps) / len(gaps) if gaps else 0.05
            var_iat = sum((g - mean_iat) ** 2 for g in gaps) / len(gaps) if gaps else 0.0
            std_iat = math.sqrt(var_iat)
            iat_cv = (std_iat / mean_iat) if mean_iat > 0 else 1.0

            small_pkts = sum(1 for p in packets if p.original_length <= 160)
            mtu_pkts = sum(1 for p in packets if p.original_length >= 1200)
            small_ratio = small_pkts / len(packets)
            mtu_ratio = mtu_pkts / len(packets)

            out_bytes = sum(p.original_length for p in packets if p.ip and p.ip.source == session.source)
            in_bytes = sum(p.original_length for p in packets if p.ip and p.ip.destination == session.source)
            io_ratio = (in_bytes / max(1, out_bytes)) if out_bytes > 0 else 1.0

            # Periodicity
            periodicity = None
            if len(timestamps) >= 10:
                t0 = timestamps[0]
                buckets: dict[int, int] = {}
                for t in timestamps:
                    sec = int(t - t0)
                    buckets[sec] = buckets.get(sec, 0) + 1
                mean_b = sum(buckets.values()) / max(1, len(buckets))
                peaks = [s for s, c in sorted(buckets.items()) if c > mean_b * 1.5]
                if len(peaks) >= 2:
                    peak_gaps = [peaks[i] - peaks[i - 1] for i in range(1, len(peaks))]
                    periodicity = sum(peak_gaps) / len(peak_gaps)

            # MOS score estimation (VoIP E-model ITU-T G.107)
            jitter_ms = std_iat * 1000.0
            delay_penalty = min(30.0, jitter_ms * 0.8)
            r_val = max(0.0, min(100.0, 93.2 - delay_penalty))
            mos = 1.0 + 0.035 * r_val + r_val * (r_val - 60.0) * (100.0 - r_val) * 7e-6
            mos = max(1.0, min(4.5, mos))
        else:
            # Fallback estimation from aggregate session statistics
            mean_iat = duration / max(1, session.packet_count)
            iat_cv = 0.8
            small_ratio = 0.3
            mtu_ratio = 0.2
            io_ratio = 1.0
            periodicity = None
            mos = None

        return FlowFeatures(
            session_id=session.id,
            packet_count=session.packet_count,
            byte_count=session.byte_count,
            duration=duration,
            mean_iat=mean_iat,
            iat_cv=iat_cv,
            small_packet_ratio=small_ratio,
            mtu_packet_ratio=mtu_ratio,
            inbound_outbound_byte_ratio=io_ratio,
            packets_per_second=pps,
            bytes_per_second=bps,
            chunk_burst_periodicity=periodicity,
            mos_score_estimate=mos,
        )

    @classmethod
    def classify(cls, features: FlowFeatures) -> Tuple[str, float, Dict[str, float], List[Dict[str, Any]]]:
        """Compute multi-class probabilities and explainability for the flow."""
        raw_scores: Dict[str, float] = {}
        explanations: List[Dict[str, Any]] = []

        # 1. Evaluate VOIP Score
        # VoIP characteristics: 20ms RTP cadence (mean_iat ~ 0.02s), low CV (< 0.40), small packets (> 0.65)
        voip_score = 0.0
        if 0.012 <= features.mean_iat <= 0.038:
            voip_score += 4.5
            explanations.append({
                "feature": "mean_interarrival_time",
                "value": round(features.mean_iat, 4),
                "influence": "+4.5 towards VOIP",
                "reason": f"Interarrival time {features.mean_iat*1000:.1f}ms closely matches the standard 20ms VoIP RTP audio frame packetization.",
            })
        elif 0.008 <= features.mean_iat <= 0.060:
            voip_score += 2.0

        if features.iat_cv < 0.35:
            voip_score += 3.5
            explanations.append({
                "feature": "iat_coefficient_of_variation",
                "value": round(features.iat_cv, 4),
                "influence": "+3.5 towards VOIP",
                "reason": "Isochronous packet delivery with very low jitter characteristic of real-time voice streaming.",
            })
        elif features.iat_cv < 0.60:
            voip_score += 1.5

        if features.small_packet_ratio > 0.65 and features.mean_iat <= 0.12:
            voip_score += 3.0
            explanations.append({
                "feature": "small_packet_ratio",
                "value": round(features.small_packet_ratio, 4),
                "influence": "+3.0 towards VOIP",
                "reason": f"{features.small_packet_ratio*100:.1f}% of packets are <= 160 bytes with low latency cadence, matching compressed G.711/G.729 voice payloads.",
            })

        if 0.3 <= features.inbound_outbound_byte_ratio <= 3.0:
            voip_score += 1.0

        raw_scores["VOIP"] = voip_score

        # 2. Evaluate WHATSAPP Score
        # WhatsApp characteristics: Bursty message clusters, presence keepalives, low pps with idle gaps
        wa_score = 0.0
        if features.packets_per_second < 8.0 and features.duration > 5.0:
            wa_score += 3.5
            explanations.append({
                "feature": "packets_per_second",
                "value": round(features.packets_per_second, 2),
                "influence": "+3.5 towards WHATSAPP",
                "reason": "Low average packet rate with conversational idle gaps typical of instant messaging sessions.",
            })

        if features.iat_cv > 0.85:
            wa_score += 3.5
            explanations.append({
                "feature": "iat_coefficient_of_variation",
                "value": round(features.iat_cv, 4),
                "influence": "+3.5 towards WHATSAPP",
                "reason": "High variance in packet arrival intervals reflects intermittent user typing and presence keepalives.",
            })

        if 0.40 <= features.small_packet_ratio <= 1.0 and features.mtu_packet_ratio < 0.20:
            wa_score += 3.5
            explanations.append({
                "feature": "packet_distribution",
                "value": f"small={features.small_packet_ratio:.2f}, mtu={features.mtu_packet_ratio:.2f}",
                "influence": "+3.5 towards WHATSAPP",
                "reason": "Mixed small notification/receipt frames and message bodies with minimal MTU payloads.",
            })

        raw_scores["WHATSAPP"] = wa_score

        # 3. Evaluate EMAIL Score
        # Email characteristics: command-response exchange followed by unidirectional bulk transfer
        email_score = 0.0
        if 0.35 <= features.mtu_packet_ratio <= 0.85:
            email_score += 3.5
            explanations.append({
                "feature": "mtu_packet_ratio",
                "value": round(features.mtu_packet_ratio, 4),
                "influence": "+3.5 towards EMAIL",
                "reason": "Multi-phase email flow with both small command-response packets and large bulk MIME message/attachment transfers.",
            })

        if features.small_packet_ratio > 0.10 and features.mtu_packet_ratio > 0.35:
            email_score += 4.5
            explanations.append({
                "feature": "bimodal_sizing",
                "value": f"small={features.small_packet_ratio:.2f}, mtu={features.mtu_packet_ratio:.2f}",
                "influence": "+4.5 towards EMAIL",
                "reason": "Presence of both small protocol command frames and large data transmission frames.",
            })

        if (1.5 <= features.inbound_outbound_byte_ratio <= 15.0 or 0.05 <= features.inbound_outbound_byte_ratio <= 0.65) and features.mtu_packet_ratio > 0.35:
            email_score += 2.0

        if features.chunk_burst_periodicity is None and features.mtu_packet_ratio > 0.35:
            email_score += 2.0
            explanations.append({
                "feature": "non_periodic_train",
                "value": "aperiodic",
                "influence": "+2.0 towards EMAIL",
                "reason": "Unidirectional batch delivery without periodic streaming chunks.",
            })

        raw_scores["EMAIL"] = email_score

        # 4. Evaluate VIDEO_STREAMING Score
        # Video streaming characteristics: HLS/DASH segment chunk bursts, high downlink asymmetry, high MTU ratio
        video_score = 0.0
        if features.chunk_burst_periodicity is not None and 1.2 <= features.chunk_burst_periodicity <= 10.0:
            video_score += 5.0
            explanations.append({
                "feature": "chunk_burst_periodicity",
                "value": round(features.chunk_burst_periodicity, 2),
                "influence": "+5.0 towards VIDEO_STREAMING",
                "reason": f"Detected periodic chunk bursts every {features.chunk_burst_periodicity:.1f}s matching HLS/DASH video fragment requests.",
            })

        if features.inbound_outbound_byte_ratio > 4.0 or features.inbound_outbound_byte_ratio < 0.25:
            if features.chunk_burst_periodicity is not None:
                video_score += 3.5
            else:
                video_score += 1.5

        if features.mtu_packet_ratio > 0.60:
            if features.small_packet_ratio < 0.10:
                video_score += 3.5
            else:
                video_score += 1.0

        if features.bytes_per_second > 50000.0:
            video_score += 1.5

        raw_scores["VIDEO_STREAMING"] = video_score

        # 5. Evaluate WEB_BROWSING Score
        # Web browsing characteristics: Bursty interactive request-response exchanges,
        # bimodal/multimodal sizing (small HTTP requests + larger response resources), moderate downlink asymmetry
        web_score = 0.0
        if 0.15 <= features.small_packet_ratio <= 0.70 and 0.05 <= features.mtu_packet_ratio <= 0.35:
            web_score += 4.5
            explanations.append({
                "feature": "web_sizing_distribution",
                "value": f"small={features.small_packet_ratio:.2f}, mtu={features.mtu_packet_ratio:.2f}",
                "influence": "+4.5 towards WEB_BROWSING",
                "reason": "Multimodal frame distribution consistent with web browsing (HTTP client requests and varying HTML/JS/image payload responses).",
            })

        if 1.2 <= features.inbound_outbound_byte_ratio <= 8.0:
            web_score += 3.0
            explanations.append({
                "feature": "downlink_asymmetry",
                "value": round(features.inbound_outbound_byte_ratio, 2),
                "influence": "+3.0 towards WEB_BROWSING",
                "reason": "Asymmetric downlink-heavy flow consistent with client browser web retrieval.",
            })

        if 0.02 <= features.mean_iat <= 0.40 and 0.40 <= features.iat_cv <= 1.5:
            web_score += 2.5

        if 8.0 <= features.packets_per_second <= 150.0:
            web_score += 2.0

        raw_scores["WEB_BROWSING"] = web_score

        # 6. Evaluate ICMP Score
        # ICMP characteristics: Strict periodic ping cadence, uniform small packet sizes, symmetric 1:1 request-reply
        icmp_score = 0.0
        if features.small_packet_ratio >= 0.85 and features.mtu_packet_ratio == 0.0:
            if 0.80 <= features.inbound_outbound_byte_ratio <= 1.25:
                icmp_score += 4.5
                explanations.append({
                    "feature": "symmetric_small_packets",
                    "value": f"small={features.small_packet_ratio:.2f}, ratio={features.inbound_outbound_byte_ratio:.2f}",
                    "influence": "+4.5 towards ICMP",
                    "reason": "Symmetric, uniformly sized small frames characteristic of ICMP echo request/reply ping cycles.",
                })

        if 0.40 <= features.mean_iat <= 1.20 and features.iat_cv <= 0.30:
            icmp_score += 4.0
            explanations.append({
                "feature": "ping_cadence",
                "value": f"iat={features.mean_iat:.2f}s, cv={features.iat_cv:.2f}",
                "influence": "+4.0 towards ICMP",
                "reason": "Strict 1-second interval periodic cadence consistent with ping diagnostics.",
            })

        raw_scores["ICMP"] = icmp_score

        # 7. Generic / Other Baseline
        raw_scores["GENERIC"] = 2.0
        raw_scores["OTHER"] = 2.0

        # Domain rules Softmax normalization
        exp_scores = {k: math.exp(v) for k, v in raw_scores.items()}
        sum_exp = sum(exp_scores.values())
        rule_probabilities = {k: round(v / sum_exp, 4) for k, v in exp_scores.items()}
        probabilities = dict(rule_probabilities)

        # Calibrated ensemble blending with Supervised Random Forest model if available
        model = cls.get_supervised_model()
        if model is not None:
            try:
                x = np.array([[
                    float(features.packet_count),
                    float(features.byte_count),
                    float(features.duration),
                    float(features.mean_iat),
                    float(features.iat_cv),
                    float(features.small_packet_ratio),
                    float(features.mtu_packet_ratio),
                    float(features.inbound_outbound_byte_ratio),
                    float(features.packets_per_second),
                    float(features.bytes_per_second),
                    float(features.chunk_burst_periodicity or 0.0),
                    float(features.mos_score_estimate or 0.0),
                    float(features.direction_asymmetry),
                ]])
                probs_vec = model.predict_proba(x)[0]
                classes = list(model.classes_)
                ml_probabilities = {str(cls_name): float(p) for cls_name, p in zip(classes, probs_vec)}

                # Domain calibration: Physical protocol constraints on ML raw output
                if (features.iat_cv > 0.50 or features.mean_iat < 0.20) and "ICMP" in ml_probabilities:
                    ml_probabilities["ICMP"] = 0.0
                if (features.iat_cv > 0.70 or features.mean_iat > 0.12) and "VOIP" in ml_probabilities:
                    ml_probabilities["VOIP"] = 0.0

                # Re-normalize ML probabilities if any were zeroed
                ml_sum = sum(ml_probabilities.values())
                if ml_sum > 0:
                    ml_probabilities = {k: v / ml_sum for k, v in ml_probabilities.items()}

                all_keys = set(rule_probabilities.keys()) | set(ml_probabilities.keys())
                blended = {}
                for k in all_keys:
                    p_rule = rule_probabilities.get(k, 0.0)
                    p_ml = ml_probabilities.get(k, 0.0)
                    blended[k] = 0.5 * p_rule + 0.5 * p_ml
                sum_blended = sum(blended.values())
                if sum_blended > 0:
                    probabilities = {k: round(v / sum_blended, 4) for k, v in blended.items()}
            except Exception as exc:
                logger.warning("Supervised prediction error, using rule probabilities: %s", exc)

        # Select highest probability class
        predicted_class = str(max(probabilities.items(), key=lambda item: item[1])[0])
        confidence = float(probabilities[predicted_class])

        # If highest confidence is weak or close to generic, default to OTHER
        if confidence < 0.35:
            predicted_class = "OTHER"
            confidence = max(probabilities.get("OTHER", 0.30), probabilities.get("GENERIC", 0.30), 0.35)

        relevant_explanations = [
            e for e in explanations if predicted_class in e["influence"]
        ]
        if not relevant_explanations:
            relevant_explanations.append({
                "feature": "flow_features_profile",
                "value": "observable_flow",
                "influence": f"classified as {predicted_class}",
                "reason": f"AI model classified flow as {predicted_class} ({confidence*100:.1f}% confidence) based on observable flow statistics.",
            })

        return TrafficPrediction(predicted_class, confidence, probabilities, relevant_explanations)


class TrafficClassificationService:
    """Coordinates persistence, querying, and execution of Layer 08 traffic classification."""

    def __init__(self, db: Session):
        self.db = db

    def classify_session(self, session: IPsecSession) -> TrafficClassificationRow:
        """Run classification on a single session and store the result."""
        features = TrafficClassifier.extract_flow_features(session)
        pred_class, confidence, probs, explanations = TrafficClassifier.classify(features)

        # Check existing row
        existing = self.db.scalar(
            select(TrafficClassificationRow).where(TrafficClassificationRow.session_id == session.id)
        )

        # Maintain 5 canonical classes for backward compatibility with TrafficClassificationRow schema
        raw_5 = {
            "VOIP": probs.get("VOIP", 0.0),
            "WHATSAPP": max(probs.get("WHATSAPP", 0.0), probs.get("WEB_BROWSING", 0.0)),
            "EMAIL": probs.get("EMAIL", 0.0),
            "VIDEO_STREAMING": probs.get("VIDEO_STREAMING", 0.0),
            "GENERIC": round(probs.get("GENERIC", 0.0) + probs.get("ICMP", 0.0) + probs.get("OTHER", 0.0), 4),
        }
        sum_5 = sum(raw_5.values()) or 1.0
        probs_5 = {k: round(v / sum_5, 4) for k, v in raw_5.items()}

        flow_id = f"FLOW-{session.source}-{session.destination}"
        if existing:
            existing.traffic_type = pred_class
            existing.confidence = confidence
            existing.probabilities_json = json.dumps(probs_5)
            existing.features_json = json.dumps(features.to_dict())
            existing.explainability_json = json.dumps(explanations)
            self.db.commit()
            self.db.refresh(existing)
            return existing

        row_id = f"TC-{uuid.uuid4().hex[:12].upper()}"
        row = TrafficClassificationRow(
            id=row_id,
            capture_id=session.capture_id,
            session_id=session.id,
            flow_id=flow_id,
            traffic_type=pred_class,
            confidence=confidence,
            probabilities_json=json.dumps(probs_5),
            features_json=json.dumps(features.to_dict()),
            explainability_json=json.dumps(explanations),
            created_at=_utc_now(),
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def classify_capture(self, capture_id: str) -> List[TrafficClassificationRow]:
        """Classify all sessions belonging to the given capture."""
        sessions = self.db.scalars(
            select(IPsecSession).where(IPsecSession.capture_id == capture_id)
        ).all()
        results = [self.classify_session(s) for s in sessions]
        return results

    def get_by_session(self, session_id: str) -> Optional[TrafficClassificationRow]:
        return self.db.scalar(
            select(TrafficClassificationRow).where(TrafficClassificationRow.session_id == session_id)
        )

    def get_by_capture(self, capture_id: str) -> List[TrafficClassificationRow]:
        if not capture_id or capture_id == "default":
            rows = self.db.scalars(
                select(TrafficClassificationRow)
                .order_by(desc(TrafficClassificationRow.confidence))
            ).all()
            return list(rows)

        rows = self.db.scalars(
            select(TrafficClassificationRow)
            .where(TrafficClassificationRow.capture_id == capture_id)
            .order_by(desc(TrafficClassificationRow.confidence))
        ).all()
        # If no classifications yet but sessions exist, run classification automatically
        if not rows:
            sessions = self.db.scalars(
                select(IPsecSession).where(IPsecSession.capture_id == capture_id)
            ).all()
            if sessions:
                rows = self.classify_capture(capture_id)
        return list(rows)

    def get_summary(self, capture_id: str) -> Dict[str, Any]:
        rows = self.get_by_capture(capture_id)
        distribution: Dict[str, int] = {
            "VOIP": 0, "WHATSAPP": 0, "EMAIL": 0, "VIDEO_STREAMING": 0, "WEB_BROWSING": 0, "ICMP": 0, "OTHER": 0, "GENERIC": 0
        }
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
