"""Train and evaluate the supervised encrypted-ESP traffic classifier.

SIH Problem Statement: SIH 26160 — NTRO
Task: Predict the type of traffic inside encrypted ESP/IPsec without payload inspection,
using observable non-payload flow features.

Pipeline (no train/serve skew):
    software testbed capture (real ESP framing + encryption)
      → Layer 03 packet decoder
      → FlowFeatures.from_packets (the exact inference function)
      → RandomForest

Reported metrics are on a held-out test split (70/15/15 stratified) plus 5-fold
cross-validation on the training portion, and additionally on a *held-out cipher
configuration* (profiles never seen in training) so the number is not a memorised
generator. The dataset is synthetic application traffic inside real IPsec framing; the
README and the metrics file say so explicitly.

Usage:
    python -m app.layers.layer08_ai_ml.train_traffic_classifier --samples-per-class 200 --workers 4
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from app.layers.layer08_ai_ml.dataset_builder import DATASET_VERSION, TRAINING_PROFILES, generate_dataset, load_dataset
from app.layers.layer08_ai_ml.traffic_classifier import FEATURE_NAMES, FEATURE_VECTOR_VERSION, TARGET_CLASSES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODEL_VERSION = "2.0"
HELD_OUT_PROFILES = ["PROFILE-07-TUNNEL-DOWNGRADE-IPV4", "PROFILE-10-TUNNEL-TFC-PADDED-IPV4"]


def train_and_export_traffic_model(
    data_dir: Path,
    samples_per_class: int = 200,
    workers: int = 1,
    regenerate: bool = True,
    base_seed: int = 20240,
) -> Dict[str, Any]:
    data_dir.mkdir(parents=True, exist_ok=True)
    models_dir = data_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    dataset_dir = data_dir / "datasets"
    csv_path = dataset_dir / f"esp_flow_features_v{DATASET_VERSION}.csv"

    train_profiles = [p for p in TRAINING_PROFILES if p not in HELD_OUT_PROFILES]
    t0 = time.time()
    if regenerate or not csv_path.exists():
        logger.info("Generating %d captures per class through the real pipeline (%d workers)…", samples_per_class, workers)
        generate_dataset(samples_per_class=samples_per_class, base_seed=base_seed, profiles=train_profiles, out_dir=dataset_dir,
                         sample_pcaps_per_class=3, workers=workers,
                         progress=lambda i, n: logger.info("  %d/%d flows", i, n) if i % 100 == 0 else None)
    X_list, y_list, meta = load_dataset(csv_path)
    X, y = np.array(X_list), np.array(y_list)
    logger.info("Dataset: %d flows, %d features, generated in %.0fs", len(X), X.shape[1], time.time() - t0)

    X_trval, X_test, y_trval, y_test = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_trval, y_trval, test_size=0.15 / 0.85, stratify=y_trval, random_state=42)

    clf = RandomForestClassifier(n_estimators=300, max_depth=16, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    val_pred = clf.predict(X_val)
    test_pred = clf.predict(X_test)
    val_acc, val_f1 = float(accuracy_score(y_val, val_pred)), float(f1_score(y_val, val_pred, average="macro"))
    test_acc, test_f1 = float(accuracy_score(y_test, test_pred)), float(f1_score(y_test, test_pred, average="macro"))
    report = classification_report(y_test, test_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, test_pred, labels=TARGET_CLASSES)
    cv = cross_val_score(RandomForestClassifier(n_estimators=200, max_depth=16, min_samples_leaf=2, class_weight="balanced", random_state=7, n_jobs=-1),
                         X_trval, y_trval, cv=StratifiedKFold(5, shuffle=True, random_state=42), scoring="f1_macro")

    # Held-out cipher configuration: profiles the model never saw during training.
    logger.info("Evaluating on held-out configurations %s…", HELD_OUT_PROFILES)
    held = generate_dataset(samples_per_class=max(10, samples_per_class // 10), base_seed=base_seed + 777, profiles=HELD_OUT_PROFILES, out_dir=None, workers=workers)
    Xh = np.array([[r.features[n] for n in FEATURE_NAMES] for r in held])
    yh = np.array([r.traffic_type for r in held])
    held_pred = clf.predict(Xh)
    held_acc, held_f1 = float(accuracy_score(yh, held_pred)), float(f1_score(yh, held_pred, average="macro"))
    held_by_profile: Dict[str, Dict[str, float]] = {}
    for pid in HELD_OUT_PROFILES:
        idx = [i for i, r in enumerate(held) if r.profile_id == pid]
        if idx:
            held_by_profile[pid] = {"accuracy": round(float(accuracy_score(yh[idx], held_pred[idx])), 4), "samples": len(idx)}

    # Final model on train+val for deployment; metrics above remain those of the held-out evaluation.
    final = RandomForestClassifier(n_estimators=300, max_depth=16, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=-1)
    final.fit(X_trval, y_trval)
    importances = dict(sorted({n: round(float(v), 4) for n, v in zip(FEATURE_NAMES, final.feature_importances_)}.items(), key=lambda kv: kv[1], reverse=True))

    t_inf = time.time()
    for _ in range(200):
        final.predict_proba(X_test[:1])
    latency_ms = (time.time() - t_inf) / 200 * 1000.0

    bundle = {
        "model": final, "feature_names": FEATURE_NAMES, "version": MODEL_VERSION, "feature_vector_version": FEATURE_VECTOR_VERSION,
        "classes": list(final.classes_), "trained_at": datetime.now(timezone.utc).isoformat(), "dataset_version": DATASET_VERSION,
    }
    model_path = models_dir / "traffic_classifier_supervised.joblib"
    joblib.dump(bundle, model_path)

    metrics: Dict[str, Any] = {
        "problem_statement": "SIH 26160 — NTRO",
        "task": "AI-Based Protocol & Traffic Classification (Encrypted ESP)",
        "model_type": "RandomForestClassifier", "model_version": MODEL_VERSION, "n_estimators": 300, "max_depth": 16,
        "feature_vector_version": FEATURE_VECTOR_VERSION, "features": FEATURE_NAMES, "classes": TARGET_CLASSES,
        "dataset": {
            "version": DATASET_VERSION, "total_flows": int(len(X)), "training_profiles": train_profiles, "held_out_profiles": HELD_OUT_PROFILES,
            "provenance": "Synthetic application traffic (statistical models) inside real RFC 4303 ESP framing with real encryption; features extracted through the deployed Layer 03 → Layer 07 pipeline. No real user traffic.",
            "split": {"train": int(len(X_train)), "val": int(len(X_val)), "test": int(len(X_test)), "ratios": [0.70, 0.15, 0.15]},
        },
        "validation_accuracy": round(val_acc, 4), "validation_macro_f1": round(val_f1, 4),
        "test_accuracy": round(test_acc, 4), "test_macro_f1": round(test_f1, 4),
        "cv5_macro_f1_mean": round(float(cv.mean()), 4), "cv5_macro_f1_std": round(float(cv.std()), 4),
        "held_out_configuration": {"accuracy": round(held_acc, 4), "macro_f1": round(held_f1, 4), "samples": int(len(held)), "by_profile": held_by_profile,
                                   "note": "Profiles never seen in training (downgrade suite; TFC-padded frames). TFC padding is designed to defeat size-based classification, so lower accuracy there is expected and honest."},
        "inference_latency_ms": round(latency_ms, 3),
        "feature_importances": importances,
        "per_class_metrics": {c: {"precision": round(report[c]["precision"], 4), "recall": round(report[c]["recall"], 4), "f1_score": round(report[c]["f1-score"], 4), "support": int(report[c]["support"])} for c in TARGET_CLASSES if c in report},
        "confusion_matrix": {"labels": TARGET_CLASSES, "matrix": cm.tolist()},
        "trained_at": bundle["trained_at"],
    }
    (models_dir / "traffic_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    logger.info("Test accuracy %.4f, macro-F1 %.4f; CV5 F1 %.4f±%.4f; held-out config accuracy %.4f", test_acc, test_f1, cv.mean(), cv.std(), held_acc)
    logger.info("Saved model bundle to %s", model_path)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples-per-class", type=int, default=200)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--no-regenerate", action="store_true", help="Reuse the existing dataset CSV")
    parser.add_argument("--seed", type=int, default=20240)
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parent.parent.parent.parent / "data")
    args = parser.parse_args()
    train_and_export_traffic_model(args.data_dir, samples_per_class=args.samples_per_class, workers=args.workers,
                                   regenerate=not args.no_regenerate, base_seed=args.seed)


if __name__ == "__main__":
    main()
