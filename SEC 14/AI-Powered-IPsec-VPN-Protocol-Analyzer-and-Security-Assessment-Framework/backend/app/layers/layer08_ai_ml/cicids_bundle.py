"""Register the locally trained CIC-IDS2017 XGBoost bundle as the default Layer 08 model."""

from __future__ import annotations

import io
import json
import logging
import os
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.layers.layer08_ai_ml.cicids_features import (
    CIC_FEATURES,
    CICIDS_FEATURE_VERSION,
    CICIDS_MODEL_ID,
    CICIDS_MODEL_TYPE,
)
from app.layers.layer08_ai_ml.registry import model_registry
from app.models.ml_anomaly import MLModelRow, TrainingDatasetRow

logger = logging.getLogger(__name__)

CICIDS_DIR = Path(__file__).resolve().parents[3] / "data" / "cicids"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _UBJSONParser:
    """Minimal streaming UBJSON parser to unpack XGBoost models pickled on Linux.

    Resolves cross-platform deserialization failures (XGBoost Issue #12459)
    where MSVC C++ std::random stream fails on Linux-serialized PRNG states.
    """

    def __init__(self, data: bytes):
        self.stream = io.BytesIO(data)

    def parse(self) -> Any:
        tag = self.stream.read(1)
        if not tag:
            return None
        return self._parse_val(tag)

    def _parse_val(self, tag: bytes) -> Any:
        if tag == b"Z":
            return None
        elif tag == b"T":
            return True
        elif tag == b"F":
            return False
        elif tag == b"i":
            return struct.unpack(">b", self.stream.read(1))[0]
        elif tag == b"U":
            return struct.unpack(">B", self.stream.read(1))[0]
        elif tag == b"I":
            return struct.unpack(">h", self.stream.read(2))[0]
        elif tag == b"l":
            return struct.unpack(">i", self.stream.read(4))[0]
        elif tag == b"L":
            return struct.unpack(">q", self.stream.read(8))[0]
        elif tag == b"d":
            return struct.unpack(">f", self.stream.read(4))[0]
        elif tag == b"D":
            return struct.unpack(">d", self.stream.read(8))[0]
        elif tag == b"C":
            return self.stream.read(1).decode("latin1")
        elif tag == b"S":
            length = self._parse_val(self.stream.read(1))
            return self.stream.read(length).decode("utf-8", errors="replace")
        elif tag == b"[":
            return self._parse_array()
        elif tag == b"{":
            return self._parse_object()
        else:
            raise ValueError(f"Unknown UBJSON tag: {tag!r} at pos {self.stream.tell()}")

    def _parse_array(self) -> list:
        next_byte = self.stream.read(1)
        type_tag = None
        count = None
        if next_byte == b"$":
            type_tag = self.stream.read(1)
            next_byte = self.stream.read(1)
        if next_byte == b"#":
            count_tag = self.stream.read(1)
            count = self._parse_val(count_tag)
        arr = []
        if count is not None:
            for _ in range(count):
                arr.append(self._parse_val(type_tag) if type_tag else self._parse_val(self.stream.read(1)))
            return arr
        tag = next_byte
        while tag and tag != b"]":
            arr.append(self._parse_val(tag))
            tag = self.stream.read(1)
        return arr

    def _parse_object(self) -> dict:
        next_byte = self.stream.read(1)
        type_tag = None
        count = None
        if next_byte == b"$":
            type_tag = self.stream.read(1)
            next_byte = self.stream.read(1)
        if next_byte == b"#":
            count_tag = self.stream.read(1)
            count = self._parse_val(count_tag)
        obj = {}
        if count is not None:
            for _ in range(count):
                k_len = self._parse_val(self.stream.read(1))
                k = self.stream.read(k_len).decode("utf-8")
                v = self._parse_val(type_tag) if type_tag else self._parse_val(self.stream.read(1))
                obj[k] = v
            return obj
        tag = next_byte
        while tag and tag != b"}":
            k_len = self._parse_val(tag)
            k = self.stream.read(k_len).decode("utf-8")
            v = self._parse_val(self.stream.read(1))
            obj[k] = v
            tag = self.stream.read(1)
        return obj


def _recover_linux_xgb_on_windows(model_path: Path) -> Any:
    """Safely restore a Linux-pickled XGBClassifier on Windows."""
    import pickle
    import xgboost as xgb

    orig_setstate = xgb.core.Booster.__setstate__
    captured: dict[str, Any] = {}

    def temp_setstate(self: Any, state: dict[str, Any]) -> None:
        captured["buf"] = state.get("handle")

    xgb.core.Booster.__setstate__ = temp_setstate
    try:
        with open(model_path, "rb") as f:
            clf = pickle.load(f)
    finally:
        xgb.core.Booster.__setstate__ = orig_setstate

    buf = captured.get("buf")
    if not buf:
        raise ValueError(f"Could not extract booster buffer from {model_path}")

    parser = _UBJSONParser(buf)
    parsed = parser.parse()
    native_dict = {
        "learner": parsed["Model"]["learner"],
        "version": parsed["Config"]["version"],
    }
    native_json = json.dumps(native_dict).encode("utf-8")
    booster = xgb.Booster()
    booster.load_model(bytearray(native_json))
    clf._Booster = booster
    logger.info("Successfully recovered XGBoost model from Linux UBJSON stream on Windows")
    return clf


def _load_supervised_model(model_path: Path) -> Any:
    """Load the supervised model artifact with automatic cross-platform fallback."""
    try:
        return joblib.load(model_path)
    except Exception as exc:
        logger.warning(
            "Direct joblib.load failed for %s (%s); attempting cross-platform recovery",
            model_path,
            exc,
        )
        return _recover_linux_xgb_on_windows(model_path)


def cicids_artifacts_present(cicids_dir: Optional[Path] = None) -> bool:
    root = cicids_dir or CICIDS_DIR
    required = (
        "supervised_model.joblib",
        "isolation_forest.joblib",
        "scaler.joblib",
        "feature_columns.json",
        "metrics.json",
    )
    return all((root / name).is_file() for name in required)


def load_cicids_bundle(cicids_dir: Optional[Path] = None) -> Dict[str, Any]:
    root = cicids_dir or CICIDS_DIR
    feature_columns = json.loads((root / "feature_columns.json").read_text(encoding="utf-8"))
    metrics = json.loads((root / "metrics.json").read_text(encoding="utf-8"))
    feature_max_path = root / "feature_max.joblib"
    return {
        "backend": "cicids-xgboost",
        "xgb": _load_supervised_model(root / "supervised_model.joblib"),
        "iso": joblib.load(root / "isolation_forest.joblib"),
        "scaler": joblib.load(root / "scaler.joblib"),
        "feature_columns": feature_columns,
        "feature_max": joblib.load(feature_max_path) if feature_max_path.is_file() else None,
        "metrics": metrics,
    }


def ensure_cicids_model_registered(
    db: Session, force_active: bool = True
) -> Optional[MLModelRow]:
    """Load local CIC-IDS artifacts into the model registry if they exist.

    Ensures model_cicids_xgb_local is the sole ACTIVE model when registered,
    while keeping any existing models (e.g. Isolation Forest) intact but INACTIVE.
    """
    if os.environ.get("PYTEST_CURRENT_TEST") and not force_active:
        return None
    if not cicids_artifacts_present():
        logger.info("No local CIC-IDS artifacts at %s; skip bootstrap", CICIDS_DIR)
        return None

    existing = db.execute(
        select(MLModelRow).where(MLModelRow.id == CICIDS_MODEL_ID)
    ).scalar_one_or_none()

    if existing is not None:
        # Synchronize checksum with the actual artifact file on disk if it changed
        artifact_path = (
            Path(existing.model_artifact_path)
            if existing.model_artifact_path
            else (model_registry.models_dir / f"{CICIDS_MODEL_ID}.joblib")
        )
        if artifact_path.is_file():
            actual_checksum = model_registry.compute_file_checksum(artifact_path)
            if existing.model_checksum != actual_checksum:
                logger.info(
                    "Updating %s model_checksum in DB: %s -> %s to match actual artifact",
                    CICIDS_MODEL_ID,
                    existing.model_checksum,
                    actual_checksum,
                )
                existing.model_checksum = actual_checksum
                db.commit()
                db.refresh(existing)
                model_registry.clear_cache()

        if force_active and not existing.is_active:
            # Ensure model_cicids_xgb_local is the sole active model
            all_models = db.execute(select(MLModelRow)).scalars().all()
            for m in all_models:
                m.is_active = (m.id == CICIDS_MODEL_ID)
            db.commit()
            db.refresh(existing)
            model_registry.clear_cache()
            logger.info("Set %s as sole ACTIVE model (deactivated other models)", CICIDS_MODEL_ID)
        return existing

    bundle = load_cicids_bundle()
    metrics = bundle["metrics"]
    dataset_id = "ds_cicids2017_local"
    if db.execute(select(TrainingDatasetRow).where(TrainingDatasetRow.id == dataset_id)).scalar_one_or_none() is None:
        db.add(
            TrainingDatasetRow(
                id=dataset_id,
                baseline_id="CIC-IDS2017",
                dataset_version="1.0",
                feature_version=CICIDS_FEATURE_VERSION,
                sample_count=int(metrics.get("train_samples") or 0),
                feature_count=len(CIC_FEATURES),
                session_ids_json="[]",
                feature_names_json=json.dumps(CIC_FEATURES),
                missing_data_summary_json="{}",
                created_at=_utc_now(),
            )
        )

    diagnostics = {
        "sample_count": int(metrics.get("train_samples") or 0),
        "feature_count": len(CIC_FEATURES),
        "contamination": 0.0,
        "score_min": 0.0,
        "score_max": 1.0,
        "score_mean": float(metrics.get("accuracy") or 0.0),
        "score_std": 0.0,
        "score_p25": 0.0,
        "score_p50": 0.0,
        "score_p75": 0.0,
        "score_threshold": 0.5,
        "accuracy": metrics.get("accuracy"),
        "f1": metrics.get("f1"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "evaluation_strategy": metrics.get("evaluation_strategy"),
    }
    metadata = {
        "backend": "cicids-xgboost",
        "feature_version": CICIDS_FEATURE_VERSION,
        "preprocessing_version": "1.0",
        "feature_columns": bundle["feature_columns"],
        "diagnostics": diagnostics,
        "scaler": bundle["scaler"],
        "iso": bundle["iso"],
        "feature_max": bundle["feature_max"],
    }
    artifact_path, checksum = model_registry.save_model(
        model_id=CICIDS_MODEL_ID,
        model_object=bundle["xgb"],
        metadata=metadata,
    )

    # Deactivate all existing models without deleting them (e.g. Isolation Forest)
    all_models = db.execute(select(MLModelRow)).scalars().all()
    for m in all_models:
        m.is_active = False

    now = _utc_now()
    row = MLModelRow(
        id=CICIDS_MODEL_ID,
        name="Local CIC-IDS2017 XGBoost",
        model_type=CICIDS_MODEL_TYPE,
        model_version="1.0",
        feature_version=CICIDS_FEATURE_VERSION,
        preprocessing_version="1.0",
        training_dataset_id=dataset_id,
        baseline_id="CIC-IDS2017",
        training_samples=int(metrics.get("train_samples") or 0),
        feature_count=len(CIC_FEATURES),
        status="READY",
        is_active=True,  # Sole active model
        configuration_json=json.dumps(
            {
                "algorithm": "XGBoostClassifier",
                "training_data": "CIC-IDS2017 ISCX CSVs",
                "cloud_api": False,
            }
        ),
        metrics_json=json.dumps(diagnostics),
        feature_names_json=json.dumps(CIC_FEATURES),
        model_artifact_path=artifact_path,
        model_checksum=checksum,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    model_registry.clear_cache()
    logger.info("Registered and ACTIVATED local CIC-IDS XGBoost model %s", CICIDS_MODEL_ID)
    return row
