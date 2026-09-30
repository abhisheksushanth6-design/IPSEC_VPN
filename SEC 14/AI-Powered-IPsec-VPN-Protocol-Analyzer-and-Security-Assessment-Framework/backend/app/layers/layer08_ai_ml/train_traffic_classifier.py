"""Train and evaluate supervised multi-class model for encrypted ESP traffic classification.

SIH Problem Statement: SIH 26160 — NTRO
Task: Predict type of traffic inside encrypted ESP/IPsec without payload inspection,
using observable non-payload statistical flow and session features.

Supported Classes:
1. VOIP: Voice over IP (RTP/SIP), small isochronous ~20ms frames, low jitter, symmetric ratio, high MOS.
2. WHATSAPP: Instant messaging, bursty chat clusters, presence keepalives, low pps, high arrival variance.
3. EMAIL: SMTP/IMAP/POP3, handshake followed by unidirectional bulk MIME data transfer, bimodal packet sizes.
4. WEB_BROWSING: Interactive HTTP/HTTPS browsing, multimodal sizing, moderate downlink asymmetry.
5. ICMP: Diagnostic ping flows, strict 1.0s periodic cadence, uniform small packets, 1:1 symmetry.
6. VIDEO_STREAMING: Adaptive bitrate streaming (HLS/DASH), periodic chunk download bursts, high MTU ratio, high bps.
7. OTHER: Unclassified / generic background encrypted TCP/UDP VPN tunnel sessions.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FEATURE_NAMES = [
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
]

TARGET_CLASSES = [
    "VOIP",
    "WHATSAPP",
    "EMAIL",
    "WEB_BROWSING",
    "ICMP",
    "VIDEO_STREAMING",
    "OTHER",
]


def generate_synthetic_flow_dataset(
    samples_per_class: int = 200,
    random_seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    """Generate statistically faithful non-payload flow features for encrypted ESP traffic."""
    np.random.seed(random_seed)
    x_records: List[List[float]] = []
    y_labels: List[str] = []
    raw_dataset: List[Dict[str, Any]] = []

    for label in TARGET_CLASSES:
        for i in range(samples_per_class):
            if label == "VOIP":
                # Isochronous ~20ms frames (G.711/G.729), 50 packets/s, low jitter (CV < 0.35)
                # Small packets (60-160B) ratio > 0.70, MTU ratio = 0, symmetric ratio ~ 1.0, MOS 3.8-4.4
                duration = np.random.uniform(10.0, 120.0)
                mean_iat = np.random.normal(0.020, 0.003)
                mean_iat = max(0.012, min(0.035, mean_iat))
                iat_cv = np.random.uniform(0.05, 0.30)
                pps = 1.0 / mean_iat
                packet_count = int(duration * pps)
                small_ratio = np.random.uniform(0.75, 0.98)
                mtu_ratio = 0.0
                io_ratio = np.random.uniform(0.85, 1.18)
                bps = pps * np.random.uniform(120.0, 200.0)
                byte_count = int(bps * duration)
                periodicity = 0.0
                mos = np.random.uniform(3.8, 4.4)

            elif label == "WHATSAPP":
                # Bursty messaging, low pps, long duration, high IAT variance (CV > 0.85)
                # Mostly small/medium frames, MTU ratio < 0.15, idle gaps
                duration = np.random.uniform(15.0, 180.0)
                mean_iat = np.random.uniform(0.2, 2.5)
                iat_cv = np.random.uniform(0.9, 2.5)
                pps = np.random.uniform(0.5, 6.0)
                packet_count = max(10, int(duration * pps))
                small_ratio = np.random.uniform(0.60, 1.0)
                mtu_ratio = np.random.uniform(0.0, 0.12)
                io_ratio = np.random.uniform(0.3, 3.0)
                bps = np.random.uniform(500.0, 8000.0)
                byte_count = int(bps * duration)
                periodicity = 0.0
                mos = 0.0

            elif label == "EMAIL":
                # Bimodal: initial command handshake (small) + bulk MIME transfer (MTU)
                duration = np.random.uniform(2.0, 30.0)
                mean_iat = np.random.uniform(0.01, 0.15)
                iat_cv = np.random.uniform(0.4, 1.2)
                small_ratio = np.random.uniform(0.15, 0.40)
                mtu_ratio = np.random.uniform(0.40, 0.80)
                io_ratio = np.random.choice([np.random.uniform(0.05, 0.35), np.random.uniform(2.5, 12.0)])
                pps = np.random.uniform(15.0, 120.0)
                packet_count = max(15, int(duration * pps))
                bps = np.random.uniform(25000.0, 350000.0)
                byte_count = int(bps * duration)
                periodicity = 0.0
                mos = 0.0

            elif label == "WEB_BROWSING":
                # Interactive browsing: request-response bursts, multimodal sizes, moderate downlink asymmetry
                duration = np.random.uniform(3.0, 60.0)
                mean_iat = np.random.uniform(0.03, 0.30)
                iat_cv = np.random.uniform(0.5, 1.6)
                small_ratio = np.random.uniform(0.20, 0.55)
                mtu_ratio = np.random.uniform(0.10, 0.40)
                io_ratio = np.random.uniform(1.8, 7.5)  # downlink heavy
                pps = np.random.uniform(10.0, 80.0)
                packet_count = max(20, int(duration * pps))
                bps = np.random.uniform(15000.0, 150000.0)
                byte_count = int(bps * duration)
                periodicity = 0.0
                mos = 0.0

            elif label == "ICMP":
                # Diagnostic echo ping: exactly ~1.0s periodic cadence, uniform small packets, 1:1 symmetry
                duration = np.random.uniform(5.0, 60.0)
                mean_iat = np.random.normal(1.0, 0.03)
                mean_iat = max(0.85, min(1.15, mean_iat))
                iat_cv = np.random.uniform(0.01, 0.18)
                small_ratio = 1.0
                mtu_ratio = 0.0
                io_ratio = np.random.uniform(0.95, 1.05)
                pps = 1.0 / mean_iat
                packet_count = max(4, int(duration * pps))
                bps = pps * 84.0  # 84 bytes standard ping
                byte_count = int(bps * duration)
                periodicity = 0.0
                mos = 0.0

            elif label == "VIDEO_STREAMING":
                # HLS/DASH chunk downloads: periodic chunk bursts every 2-6s, very high downlink asymmetry, high MTU
                duration = np.random.uniform(20.0, 180.0)
                mean_iat = np.random.uniform(0.005, 0.05)
                iat_cv = np.random.uniform(1.2, 3.2)  # chunk pauses create high CV
                small_ratio = np.random.uniform(0.02, 0.15)
                mtu_ratio = np.random.uniform(0.65, 0.95)
                io_ratio = np.random.uniform(5.0, 35.0)  # overwhelming downlink
                pps = np.random.uniform(40.0, 250.0)
                packet_count = max(50, int(duration * pps))
                bps = np.random.uniform(150000.0, 1200000.0)  # high bitrate
                byte_count = int(bps * duration)
                periodicity = np.random.uniform(1.8, 6.0)  # chunk interval
                mos = 0.0

            else:  # OTHER
                # Generic unclassified VPN flows
                duration = np.random.uniform(2.0, 90.0)
                mean_iat = np.random.uniform(0.01, 0.8)
                iat_cv = np.random.uniform(0.4, 1.8)
                small_ratio = np.random.uniform(0.1, 0.7)
                mtu_ratio = np.random.uniform(0.05, 0.5)
                io_ratio = np.random.uniform(0.2, 5.0)
                pps = np.random.uniform(2.0, 100.0)
                packet_count = max(10, int(duration * pps))
                bps = np.random.uniform(2000.0, 100000.0)
                byte_count = int(bps * duration)
                periodicity = 0.0
                mos = 0.0

            direction_asymmetry = abs(io_ratio - 1.0) / (io_ratio + 1.0)

            feat = [
                float(packet_count),
                float(byte_count),
                float(duration),
                float(mean_iat),
                float(iat_cv),
                float(small_ratio),
                float(mtu_ratio),
                float(io_ratio),
                float(pps),
                float(bps),
                float(periodicity),
                float(mos),
                float(direction_asymmetry),
            ]
            x_records.append(feat)
            y_labels.append(label)

            raw_dataset.append({
                "sample_id": f"FLOW-{label}-{i+1:04d}",
                "traffic_type": label,
                "features": {k: float(v) for k, v in zip(FEATURE_NAMES, feat)},
                "ipsec_context": {
                    "encapsulation": "ESP",
                    "mode": str(np.random.choice(["TUNNEL", "TRANSPORT"])),
                    "encryption": str(np.random.choice(["AES-256-GCM", "AES-128-GCM", "AES-256-CBC"])),
                    "dh_group": int(np.random.choice([14, 19, 20, 21])),
                },
            })

    return np.array(x_records), np.array(y_labels), raw_dataset


def train_and_export_traffic_model(
    output_dir: Path,
    samples_per_class: int = 200,
) -> Dict[str, Any]:
    """Train RandomForest multi-class traffic classifier, evaluate, and save artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Generating stratified flow dataset (%d per class)...", samples_per_class)
    X, y, raw_data = generate_synthetic_flow_dataset(samples_per_class=samples_per_class, random_seed=42)

    # 70% Train, 15% Validation, 15% Test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    val_ratio_of_train_val = 0.15 / 0.85
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=val_ratio_of_train_val, stratify=y_train_val, random_state=42
    )

    logger.info("Train samples: %d, Val samples: %d, Test samples: %d", len(X_train), len(X_val), len(X_test))

    # Train Random Forest
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    # Validation evaluation
    val_preds = clf.predict(X_val)
    val_acc = float(accuracy_score(y_val, val_preds))
    val_f1 = float(f1_score(y_val, val_preds, average="macro"))

    # Test evaluation
    test_preds = clf.predict(X_test)
    test_acc = float(accuracy_score(y_test, test_preds))
    test_f1 = float(f1_score(y_test, test_preds, average="macro"))
    test_report = classification_report(y_test, test_preds, output_dict=True)

    # Feature importances
    feature_importances = {
        name: round(float(imp), 4)
        for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)
    }
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

    logger.info("Test Accuracy: %.4f, Macro F1: %.4f", test_acc, test_f1)

    # Model artifact path
    model_path = models_dir / "traffic_classifier_supervised.joblib"
    joblib.dump(clf, model_path)
    logger.info("Saved model artifact to %s", model_path)

    # Metrics and dataset metadata
    metrics_data = {
        "problem_statement": "SIH 26160 — NTRO",
        "task": "AI-Based Protocol & Traffic Classification (Encrypted ESP)",
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 12,
        "total_dataset_size": len(X),
        "split": {
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
            "train_ratio": 0.70,
            "val_ratio": 0.15,
            "test_ratio": 0.15,
        },
        "classes": TARGET_CLASSES,
        "features": FEATURE_NAMES,
        "validation_accuracy": round(val_acc, 4),
        "validation_macro_f1": round(val_f1, 4),
        "test_accuracy": round(test_acc, 4),
        "test_macro_f1": round(test_f1, 4),
        "feature_importances": sorted_importances,
        "per_class_metrics": {
            cls: {
                "precision": round(test_report[cls]["precision"], 4),
                "recall": round(test_report[cls]["recall"], 4),
                "f1_score": round(test_report[cls]["f1-score"], 4),
                "support": int(test_report[cls]["support"]),
            }
            for cls in TARGET_CLASSES
            if cls in test_report
        },
    }

    metrics_path = models_dir / "traffic_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)
    logger.info("Saved metrics to %s", metrics_path)

    # Export dataset snapshot for reproducibility
    dataset_path = output_dir / "traffic_dataset_1400.json"
    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump({"metadata": metrics_data, "samples": raw_data}, f, indent=2)
    logger.info("Saved dataset snapshot to %s", dataset_path)

    return metrics_data


if __name__ == "__main__":
    base_data_dir = Path(__file__).resolve().parent.parent.parent.parent / "data"
    train_and_export_traffic_model(base_data_dir, samples_per_class=200)
