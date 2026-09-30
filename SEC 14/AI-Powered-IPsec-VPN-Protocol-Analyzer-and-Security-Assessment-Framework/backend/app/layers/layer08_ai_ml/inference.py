"""Anomaly inference engine for Layer 08 AI / ML Anomaly Detection.

Loads the validated active or specified model, preprocesses the target session's
feature vector, computes raw and normalized anomaly scores, determines classification,
derives explainable evidence, queries baseline and drift status for the 3-signal panel,
and persists the factual analysis results.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.layers.layer08_ai_ml.cicids_features import (
    CIC_FEATURES,
    CICIDS_MODEL_TYPE,
    session_features_to_cic_vector,
)
from app.layers.layer08_ai_ml.explainability import AnomalyExplanationService
from app.layers.layer08_ai_ml.preprocessing import (
    FEATURE_NAMES,
    PreprocessingPipeline,
)
from app.layers.layer08_ai_ml.registry import model_registry
from app.layers.layer08_ai_ml.schemas import (
    AnomalyAnalysisResponse,
    AnomalyFeatureContribution,
    AnomalyInferenceRequest,
    SignalComparisonSummary,
)
from app.layers.layer08_ai_ml.validators import (
    MissingFeatureVectorError,
    validate_feature_version_compatibility,
    validate_model_inference_status,
)
from app.models.baseline import BaselineFeatureRow, BaselineSessionLinkRow
from app.models.drift import DriftAnalysisRow
from app.models.feature_vector import FeatureValueRow, FeatureVectorRow
from app.models.ml_anomaly import (
    AnomalyAnalysisRow,
    AnomalyFeatureContributionRow,
    MLModelRow,
)

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_normalized_display_score(raw_score: float) -> float:
    """Derive an intuitive 0-100 anomaly score via logistic transformation.
    
    Formula: display_score = 100.0 / (1.0 + exp(10.0 * raw_score))
    
    Semantics:
    - Higher score (0-100) = more anomalous relative to learned profile.
    - Raw score 0.0 (decision boundary) maps to exactly 50.0.
    - Deep inliers (raw >= +0.3) map to < 5.0.
    - Extreme anomalies (raw <= -0.3) map to > 95.0.
    - Strictly measures statistical distance; NOT attack probability.
    """
    # Prevent overflow in exp
    scaled = 10.0 * raw_score
    if scaled > 40.0:
        return 0.0
    if scaled < -40.0:
        return 100.0

    score = 100.0 / (1.0 + math.exp(scaled))
    return round(float(score), 2)


class AnomalyInferenceService:
    """Executes single-session anomaly inference with explainability and 3-signal comparison."""

    def __init__(self, db: Session):
        self.db = db

    def run_inference(self, request: AnomalyInferenceRequest) -> AnomalyAnalysisResponse:
        """Execute anomaly analysis on the designated session."""
        # 1. Resolve model
        if request.model_id:
            model_row = self.db.execute(
                select(MLModelRow).where(MLModelRow.id == request.model_id)
            ).scalar_one_or_none()
        else:
            model_row = self.db.execute(
                select(MLModelRow).where(MLModelRow.is_active == True)  # noqa: E712
            ).scalar_one_or_none()

        if not model_row:
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="NO AI MODEL AVAILABLE: No active or specified ML model found. "
                       "Train a model on a valid baseline before running anomaly inference.",
            )

        # 2. Validate model status
        validate_model_inference_status(model_row.status, model_row.id)

        # 3. Load model artifact with integrity verification
        model_object, metadata = model_registry.load_model(
            model_id=model_row.id,
            artifact_path_str=model_row.model_artifact_path or "",
            expected_checksum=model_row.model_checksum,
        )

        # 4. Fetch target session's feature vector
        vector = self.db.execute(
            select(FeatureVectorRow).where(
                FeatureVectorRow.entity_type == "SESSION",
                FeatureVectorRow.entity_id == request.session_id,
            )
        ).scalar_one_or_none()

        if not vector:
            raise MissingFeatureVectorError(request.session_id)

        # 5. Validate feature schema compatibility (session Isolation Forest only)
        is_cicids = (
            model_row.model_type == CICIDS_MODEL_TYPE
            or metadata.get("backend") == "cicids-xgboost"
        )
        if not is_cicids:
            validate_feature_version_compatibility(
                model_row.feature_version, vector.feature_version
            )

        # 6. Extract raw feature dictionary from FeatureValueRow
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

        if is_cicids:
            raw_cic = session_features_to_cic_vector(feat_dict)
            feature_max = metadata.get("feature_max")
            if feature_max is not None:
                raw_cic = np.minimum(raw_cic, np.asarray(feature_max, dtype=np.float64))
            scaler = metadata.get("scaler")
            if scaler is None:
                from fastapi import HTTPException, status
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="CIC-IDS model is missing its scaler artifact.",
                )
            scaled_cic = scaler.transform(raw_cic.reshape(1, -1))
            if hasattr(model_object, "predict_proba"):
                attack_probability = float(model_object.predict_proba(scaled_cic)[0, 1])
            else:
                attack_probability = float(model_object.predict(scaled_cic)[0])
            importances = getattr(model_object, "feature_importances_", None)
            contributions, explanation_summary, anom_feat_count = (
                AnomalyExplanationService.explain_cicids_vector(
                    feature_names=metadata.get("feature_columns") or CIC_FEATURES,
                    raw_values=raw_cic,
                    scaled_values=scaled_cic[0],
                    importances=importances,
                    attack_probability=attack_probability,
                )
            )
            raw_score = attack_probability
            display_score = round(attack_probability * 100.0, 2)
            is_anomalous = attack_probability >= 0.5
            classification = "ANOMALOUS" if is_anomalous else "NORMAL"
            features_analyzed = len(metadata.get("feature_columns") or CIC_FEATURES)
            pipeline_feature_count = features_analyzed
        else:
            # 7. Reconstruct PreprocessingPipeline from model metadata
            pipeline_dict = metadata.get("preprocessing_pipeline")
            if pipeline_dict:
                pipeline = PreprocessingPipeline.from_dict(pipeline_dict)
            else:
                pipeline = PreprocessingPipeline(feature_names=FEATURE_NAMES)

            # 8. Transform features
            scaled_vector, imputed_raw = pipeline.transform_single(feat_dict)

            # 9. Execute Isolation Forest inference
            raw_score = float(model_object.decision_function(scaled_vector)[0])
            prediction = int(model_object.predict(scaled_vector)[0])  # -1 = outlier, +1 = inlier

            display_score = compute_normalized_display_score(raw_score)

            # 10. Load baseline statistics if model is linked to a baseline
            baseline_stats: Dict[str, Dict[str, Any]] = {}
            if model_row.baseline_id:
                b_features = self.db.execute(
                    select(BaselineFeatureRow).where(
                        BaselineFeatureRow.baseline_id == model_row.baseline_id
                    )
                ).scalars().all()
                for bf in b_features:
                    baseline_stats[bf.name] = {
                        "mean": bf.mean,
                        "std_dev": bf.std_dev,
                        "median": bf.median,
                    }

            # 11. Generate explainable feature evidence
            contributions, explanation_summary, anom_feat_count = (
                AnomalyExplanationService.explain_session(
                    observed_features=imputed_raw,
                    pipeline=pipeline,
                    baseline_stats=baseline_stats,
                )
            )

            # Classification strictly defined: NORMAL vs ANOMALOUS
            # Flags as anomalous if IsolationForest prediction is outlier (-1),
            # display score >= 50.0, or at least 3 significant feature deviations (>1.5σ)
            is_anomalous = (prediction == -1 or display_score >= 50.0 or anom_feat_count >= 3)
            classification = "ANOMALOUS" if is_anomalous else "NORMAL"

            if is_anomalous and display_score < 50.0:
                # Calibrate display score to reflect the multi-feature deviation
                display_score = round(max(display_score, 50.0 + min(45.0, anom_feat_count * 5.0)), 2)
            features_analyzed = len(pipeline.feature_names)
            pipeline_feature_count = features_analyzed

        # 12. Query Section 9 Baseline and Section 10 Drift status for 3-Signal Comparison
        # Check baseline membership
        baseline_link = self.db.execute(
            select(BaselineSessionLinkRow).where(
                BaselineSessionLinkRow.session_id == request.session_id
            )
        ).scalars().first()

        baseline_status = "WITHIN_BASELINE" if baseline_link else "NO_BASELINE"

        # Check latest drift analysis for this session
        latest_drift = self.db.execute(
            select(DriftAnalysisRow)
            .where(DriftAnalysisRow.session_id == request.session_id)
            .order_by(desc(DriftAnalysisRow.analyzed_at))
        ).scalars().first()

        drift_status = "NOT_ANALYZED"
        drift_analysis_id = None
        if latest_drift:
            drift_analysis_id = latest_drift.id
            drift_status = "DRIFT_DETECTED" if latest_drift.features_drifting > 0 else "NO_DRIFT"

        signal_comparison = SignalComparisonSummary(
            baseline_id=model_row.baseline_id,
            baseline_status=baseline_status,
            drift_analysis_id=drift_analysis_id,
            drift_status=drift_status,
            ml_model_id=model_row.id,
            ml_status=classification,
        )

        # 13. Persist AnomalyAnalysisRow and AnomalyFeatureContributionRow
        analysis_id = f"anom_{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        analysis_row = AnomalyAnalysisRow(
            id=analysis_id,
            session_id=request.session_id,
            model_id=model_row.id,
            model_version=model_row.model_version,
            feature_version=model_row.feature_version,
            preprocessing_version=model_row.preprocessing_version,
            classification=classification,
            raw_score=round(raw_score, 4),
            display_score=display_score,
            features_analyzed=features_analyzed,
            features_anomalous=anom_feat_count,
            explanation_summary=explanation_summary,
            baseline_id=model_row.baseline_id,
            drift_analysis_id=drift_analysis_id,
            analyzed_at=now,
        )
        self.db.add(analysis_row)

        for c in contributions:
            contrib_row = AnomalyFeatureContributionRow(
                analysis_id=analysis_id,
                feature_name=c.feature_name,
                display_name=c.display_name,
                category=c.category,
                data_type=c.data_type,
                observed_value_json=json.dumps(c.observed_value),
                reference_mean=c.reference_mean,
                reference_std=c.reference_std,
                reference_median=c.reference_median,
                contribution_score=c.contribution_score,
                deviation=c.deviation,
                direction=c.direction,
                evidence_description=c.evidence_description,
            )
            self.db.add(contrib_row)

        self.db.commit()

        logger.info(
            "Completed anomaly analysis %s for session %s (score=%.2f, class=%s)",
            analysis_id,
            request.session_id,
            display_score,
            classification,
        )

        return AnomalyAnalysisResponse(
            id=analysis_id,
            session_id=request.session_id,
            model_id=model_row.id,
            model_version=model_row.model_version,
            feature_version=model_row.feature_version,
            preprocessing_version=model_row.preprocessing_version,
            classification=classification,
            raw_score=round(raw_score, 4),
            display_score=display_score,
            features_analyzed=features_analyzed,
            features_anomalous=anom_feat_count,
            explanation_summary=explanation_summary,
            feature_contributions=contributions,
            signal_comparison=signal_comparison,
            analyzed_at=now,
        )
