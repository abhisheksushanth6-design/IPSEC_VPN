"""Model training pipeline for Layer 08 AI / ML Anomaly Detection Engine.

Extracts real session observations from established Section 9 baselines and
Section 8 feature vectors, validates minimum sample thresholds, fits an
Isolation Forest model with controlled random seeds, computes genuine diagnostics,
and persists versioned model artifacts with SHA-256 checksums.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.layers.layer08_ai_ml.preprocessing import (
    FEATURE_NAMES,
    PreprocessingPipeline,
)
from app.layers.layer08_ai_ml.registry import model_registry
from app.layers.layer08_ai_ml.schemas import (
    MLModelConfiguration,
    MLModelDetail,
    MLModelDiagnostics,
    MLModelTrainRequest,
)
from app.layers.layer08_ai_ml.validators import (
    CURRENT_FEATURE_VERSION,
    CURRENT_PREPROCESSING_VERSION,
    validate_feature_version_compatibility,
    validate_training_sample_count,
)
from app.models.baseline import BaselineProfileRow, BaselineSessionLinkRow
from app.models.feature_vector import FeatureValueRow, FeatureVectorRow
from app.models.ml_anomaly import MLModelRow, TrainingDatasetRow

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ModelTrainingService:
    """Orchestrates dataset extraction, preprocessing, Isolation Forest fitting, and persistence."""

    def __init__(self, db: Session):
        self.db = db

    def train_model(self, request: MLModelTrainRequest) -> MLModelDetail:
        """Execute end-to-end model training workflow on real baseline session data."""
        # 1. Fetch baseline profile
        baseline = self.db.execute(
            select(BaselineProfileRow).where(BaselineProfileRow.id == request.baseline_id)
        ).scalar_one_or_none()

        if not baseline:
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Baseline profile '{request.baseline_id}' not found.",
            )

        # 2. Fetch linked sessions for this baseline
        links = self.db.execute(
            select(BaselineSessionLinkRow).where(
                BaselineSessionLinkRow.baseline_id == request.baseline_id
            )
        ).scalars().all()

        session_ids = [link.session_id for link in links]

        # If baseline had no explicit link rows, check session_count
        if not session_ids:
            logger.warning("No session links for baseline %s", request.baseline_id)

        # 3. Load session feature vectors from Layer 05
        raw_session_features: List[Dict[str, Any]] = []
        valid_session_ids: List[str] = []
        missing_data_summary: Dict[str, int] = {fname: 0 for fname in FEATURE_NAMES}

        for sid in session_ids:
            vector = self.db.execute(
                select(FeatureVectorRow).where(
                    FeatureVectorRow.entity_type == "SESSION",
                    FeatureVectorRow.entity_id == sid,
                )
            ).scalar_one_or_none()

            if not vector:
                continue

            # Validate feature schema version
            validate_feature_version_compatibility(
                CURRENT_FEATURE_VERSION, vector.feature_version
            )

            # Query all values for this vector
            val_rows = self.db.execute(
                select(FeatureValueRow).where(FeatureValueRow.vector_id == vector.id)
            ).scalars().all()

            feat_dict: Dict[str, Any] = {}
            for vrow in val_rows:
                if vrow.name in FEATURE_NAMES:
                    if vrow.data_type == "INTEGER":
                        feat_dict[vrow.name] = vrow.value_integer
                    elif vrow.data_type == "FLOAT":
                        feat_dict[vrow.name] = vrow.value_float
                    elif vrow.data_type == "BOOLEAN":
                        feat_dict[vrow.name] = vrow.value_boolean
                    elif vrow.data_type == "CATEGORICAL":
                        feat_dict[vrow.name] = vrow.value_text

            # Record missingness
            for fname in FEATURE_NAMES:
                if fname not in feat_dict or feat_dict[fname] is None:
                    missing_data_summary[fname] += 1

            raw_session_features.append(feat_dict)
            valid_session_ids.append(sid)

        # 4. Enforce strict minimum sample requirement — reject fake or insufficient data
        validate_training_sample_count(
            len(raw_session_features), request.minimum_training_samples
        )

        # 5. Fit deterministic preprocessing pipeline
        pipeline = PreprocessingPipeline(
            feature_names=FEATURE_NAMES,
            preprocessing_version=CURRENT_PREPROCESSING_VERSION,
        )
        pipeline.fit(raw_session_features)

        # 6. Transform into normalized training matrix
        x_train = pipeline.transform_batch(raw_session_features)

        # 7. Configure hyperparameters
        config = request.configuration or MLModelConfiguration()
        model_config_dict = {
            "contamination": config.contamination,
            "n_estimators": config.n_estimators,
            "max_samples": config.max_samples,
            "random_state": config.random_state,
        }

        # 8. Train Isolation Forest
        model = IsolationForest(
            n_estimators=config.n_estimators,
            contamination=config.contamination,
            max_samples=config.max_samples,
            random_state=config.random_state,
            n_jobs=1,
        )
        model.fit(x_train)

        # 9. Compute genuine unsupervised diagnostics (no fake classification accuracy!)
        decision_scores = model.decision_function(x_train)
        diagnostics = MLModelDiagnostics(
            sample_count=len(x_train),
            feature_count=len(FEATURE_NAMES),
            contamination=config.contamination,
            score_min=float(np.min(decision_scores)),
            score_max=float(np.max(decision_scores)),
            score_mean=float(np.mean(decision_scores)),
            score_std=float(np.std(decision_scores)),
            score_p25=float(np.percentile(decision_scores, 25)),
            score_p50=float(np.percentile(decision_scores, 50)),
            score_p75=float(np.percentile(decision_scores, 75)),
            score_threshold=0.0,
        )

        # 10. Persist Training Dataset snapshot
        dataset_id = f"ds_{uuid.uuid4().hex[:12]}"
        dataset_row = TrainingDatasetRow(
            id=dataset_id,
            baseline_id=request.baseline_id,
            dataset_version="1.0",
            feature_version=CURRENT_FEATURE_VERSION,
            sample_count=len(valid_session_ids),
            feature_count=len(FEATURE_NAMES),
            session_ids_json=json.dumps(valid_session_ids),
            feature_names_json=json.dumps(FEATURE_NAMES),
            missing_data_summary_json=json.dumps(missing_data_summary),
            created_at=_utc_now(),
        )
        self.db.add(dataset_row)

        # 11. Prepare model identity and metadata
        model_id = f"model_isoforest_{uuid.uuid4().hex[:10]}"
        model_name = request.name or f"Isolation Forest v1.0 ({baseline.name})"

        # Determine next model version
        existing_count = len(self.db.execute(select(MLModelRow)).scalars().all())
        model_version = f"1.{existing_count}"

        metadata_to_save = {
            "model_id": model_id,
            "name": model_name,
            "model_version": model_version,
            "feature_version": CURRENT_FEATURE_VERSION,
            "preprocessing_version": CURRENT_PREPROCESSING_VERSION,
            "baseline_id": request.baseline_id,
            "training_dataset_id": dataset_id,
            "configuration": model_config_dict,
            "preprocessing_pipeline": pipeline.to_dict(),
            "diagnostics": diagnostics.model_dump(),
        }

        # 12. Persist model artifact to disk with SHA-256 integrity verification
        artifact_path, checksum = model_registry.save_model(
            model_id=model_id,
            model_object=model,
            metadata=metadata_to_save,
        )

        # Check if any model is currently active
        has_active = self.db.execute(
            select(MLModelRow).where(MLModelRow.is_active == True)  # noqa: E712
        ).scalar_one_or_none()

        is_active = (has_active is None)  # Activate first model automatically

        # 13. Persist MLModelRow in database
        now = _utc_now()
        model_row = MLModelRow(
            id=model_id,
            name=model_name,
            model_type="IsolationForest",
            model_version=model_version,
            feature_version=CURRENT_FEATURE_VERSION,
            preprocessing_version=CURRENT_PREPROCESSING_VERSION,
            training_dataset_id=dataset_id,
            baseline_id=request.baseline_id,
            training_samples=len(valid_session_ids),
            feature_count=len(FEATURE_NAMES),
            status="READY",
            is_active=is_active,
            configuration_json=json.dumps(model_config_dict),
            metrics_json=json.dumps(diagnostics.model_dump()),
            feature_names_json=json.dumps(FEATURE_NAMES),
            model_artifact_path=artifact_path,
            model_checksum=checksum,
            created_at=now,
            updated_at=now,
        )
        self.db.add(model_row)
        self.db.commit()
        self.db.refresh(model_row)

        logger.info(
            "Successfully trained and registered model %s (%s) with %d samples",
            model_id,
            model_name,
            len(valid_session_ids),
        )

        return MLModelDetail(
            id=model_row.id,
            name=model_row.name,
            model_type=model_row.model_type,
            model_version=model_row.model_version,
            feature_version=model_row.feature_version,
            preprocessing_version=model_row.preprocessing_version,
            training_samples=model_row.training_samples,
            feature_count=model_row.feature_count,
            status=model_row.status,
            is_active=model_row.is_active,
            configuration=model_config_dict,
            metrics=diagnostics,
            feature_names=FEATURE_NAMES,
            model_checksum=checksum,
            training_dataset_id=dataset_id,
            baseline_id=request.baseline_id,
            created_at=model_row.created_at,
            updated_at=model_row.updated_at,
        )
