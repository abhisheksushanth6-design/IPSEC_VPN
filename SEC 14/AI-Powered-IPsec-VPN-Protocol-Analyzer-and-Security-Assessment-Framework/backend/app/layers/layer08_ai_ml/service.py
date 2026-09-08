"""Service layer coordinating Layer 08 AI / ML Anomaly Detection operations.

Provides model lifecycle management, training coordination, inference execution,
historical analysis querying, and engine health reporting.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.layers.layer08_ai_ml.inference import AnomalyInferenceService
from app.layers.layer08_ai_ml.registry import model_registry
from app.layers.layer08_ai_ml.schemas import (
    AIAnomalyEngineStatus,
    AnomalyAnalysisResponse,
    AnomalyFeatureContribution,
    AnomalyInferenceRequest,
    MLModelDetail,
    MLModelDiagnostics,
    MLModelSummary,
    MLModelTrainRequest,
    SignalComparisonSummary,
    TrainingDatasetDetail,
    TrainingDatasetSummary,
)
from app.layers.layer08_ai_ml.trainer import ModelTrainingService
from app.layers.layer08_ai_ml.validators import (
    CURRENT_FEATURE_VERSION,
    CURRENT_PREPROCESSING_VERSION,
)
from app.models.baseline import BaselineProfileRow, BaselineSessionLinkRow
from app.models.drift import DriftAnalysisRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import (
    AnomalyAnalysisRow,
    AnomalyFeatureContributionRow,
    MLModelRow,
    TrainingDatasetRow,
)

logger = logging.getLogger(__name__)


class AIAnomalyService:
    """High-level facade for Layer 08 AI / ML Anomaly Detection Engine."""

    def __init__(self, db: Session):
        self.db = db

    def get_status(self) -> AIAnomalyEngineStatus:
        """Determine actual operational status and health of the ML engine."""
        if not os.environ.get("PYTEST_CURRENT_TEST"):
            from app.layers.layer08_ai_ml.cicids_bundle import ensure_cicids_model_registered
            ensure_cicids_model_registered(self.db)

        models = self.db.execute(select(MLModelRow)).scalars().all()
        active_row = self.db.execute(
            select(MLModelRow).where(MLModelRow.is_active == True)  # noqa: E712
        ).scalar_one_or_none()

        baselines_count = len(self.db.execute(select(BaselineProfileRow)).scalars().all())
        sessions_count = len(self.db.execute(select(IPsecSession)).scalars().all())
        writable = model_registry.is_writable()

        active_summary = None
        if active_row:
            active_summary = MLModelSummary(
                id=active_row.id,
                name=active_row.name,
                model_type=active_row.model_type,
                model_version=active_row.model_version,
                feature_version=active_row.feature_version,
                preprocessing_version=active_row.preprocessing_version,
                training_samples=active_row.training_samples,
                feature_count=active_row.feature_count,
                status=active_row.status,
                is_active=active_row.is_active,
                created_at=active_row.created_at,
                updated_at=active_row.updated_at,
            )

        # Status determination according to Section 5:
        # NOT INITIALIZED, READY, TRAINING, TRAINED, INFERENCE READY, ERROR, INSUFFICIENT DATA
        if not writable:
            engine_status = "ERROR"
        elif active_row and active_row.status in ("READY", "TRAINED"):
            engine_status = "INFERENCE READY"
        elif len(models) > 0:
            engine_status = "READY"
        elif sessions_count < 3 and baselines_count == 0:
            engine_status = "NOT INITIALIZED"
        elif baselines_count == 0:
            engine_status = "NOT INITIALIZED"
        else:
            engine_status = "READY"

        return AIAnomalyEngineStatus(
            status=engine_status,
            active_model=active_summary,
            total_models=len(models),
            feature_version=CURRENT_FEATURE_VERSION,
            preprocessing_version=CURRENT_PREPROCESSING_VERSION,
            models_dir_writable=writable,
            available_baselines_count=baselines_count,
            available_sessions_count=sessions_count,
        )

    def list_models(self) -> List[MLModelSummary]:
        """List all registered models, sorted by creation date descending."""
        if not os.environ.get("PYTEST_CURRENT_TEST"):
            from app.layers.layer08_ai_ml.cicids_bundle import ensure_cicids_model_registered
            ensure_cicids_model_registered(self.db)

        rows = self.db.execute(
            select(MLModelRow).order_by(desc(MLModelRow.created_at))
        ).scalars().all()

        return [
            MLModelSummary(
                id=r.id,
                name=r.name,
                model_type=r.model_type,
                model_version=r.model_version,
                feature_version=r.feature_version,
                preprocessing_version=r.preprocessing_version,
                training_samples=r.training_samples,
                feature_count=r.feature_count,
                status=r.status,
                is_active=r.is_active,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            for r in rows
        ]

    def get_model(self, model_id: str) -> Optional[MLModelDetail]:
        """Retrieve detailed model metadata, configuration, and genuine diagnostics."""
        r = self.db.execute(
            select(MLModelRow).where(MLModelRow.id == model_id)
        ).scalar_one_or_none()

        if not r:
            return None

        config_dict = json.loads(r.configuration_json or "{}")
        metrics_dict = json.loads(r.metrics_json or "{}")
        feature_names = json.loads(r.feature_names_json or "[]")

        diagnostics = MLModelDiagnostics(**metrics_dict) if metrics_dict else None

        return MLModelDetail(
            id=r.id,
            name=r.name,
            model_type=r.model_type,
            model_version=r.model_version,
            feature_version=r.feature_version,
            preprocessing_version=r.preprocessing_version,
            training_samples=r.training_samples,
            feature_count=r.feature_count,
            status=r.status,
            is_active=r.is_active,
            configuration=config_dict,
            metrics=diagnostics,
            feature_names=feature_names,
            model_checksum=r.model_checksum,
            training_dataset_id=r.training_dataset_id,
            baseline_id=r.baseline_id,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )

    def train_model(self, request: MLModelTrainRequest) -> MLModelDetail:
        """Trigger model training on an established baseline."""
        trainer = ModelTrainingService(self.db)
        return trainer.train_model(request)

    def activate_model(self, model_id: str) -> MLModelDetail:
        """Set a specified model version as the active model for inference."""
        from fastapi import HTTPException, status

        target = self.db.execute(
            select(MLModelRow).where(MLModelRow.id == model_id)
        ).scalar_one_or_none()

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model '{model_id}' not found.",
            )

        if target.status not in ("READY", "TRAINED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot activate model in '{target.status}' status.",
            )

        # Deactivate all others
        all_models = self.db.execute(select(MLModelRow)).scalars().all()
        for m in all_models:
            m.is_active = (m.id == model_id)

        self.db.commit()
        self.db.refresh(target)

        # Clear in-memory cache
        model_registry.clear_cache()

        logger.info("Activated model %s (%s)", target.id, target.name)
        detail = self.get_model(model_id)
        assert detail is not None
        return detail

    def list_training_datasets(self) -> List[TrainingDatasetSummary]:
        """List all training datasets."""
        rows = self.db.execute(
            select(TrainingDatasetRow).order_by(desc(TrainingDatasetRow.created_at))
        ).scalars().all()

        return [
            TrainingDatasetSummary(
                id=r.id,
                baseline_id=r.baseline_id,
                dataset_version=r.dataset_version,
                feature_version=r.feature_version,
                sample_count=r.sample_count,
                feature_count=r.feature_count,
                session_ids=json.loads(r.session_ids_json or "[]"),
                created_at=r.created_at,
            )
            for r in rows
        ]

    def get_training_dataset(self, dataset_id: str) -> Optional[TrainingDatasetDetail]:
        """Inspect a specific training dataset snapshot."""
        r = self.db.execute(
            select(TrainingDatasetRow).where(TrainingDatasetRow.id == dataset_id)
        ).scalar_one_or_none()

        if not r:
            return None

        return TrainingDatasetDetail(
            id=r.id,
            baseline_id=r.baseline_id,
            dataset_version=r.dataset_version,
            feature_version=r.feature_version,
            sample_count=r.sample_count,
            feature_count=r.feature_count,
            session_ids=json.loads(r.session_ids_json or "[]"),
            feature_names=json.loads(r.feature_names_json or "[]"),
            missing_data_summary=json.loads(r.missing_data_summary_json or "{}"),
            created_at=r.created_at,
        )

    def run_inference(self, request: AnomalyInferenceRequest) -> AnomalyAnalysisResponse:
        """Run anomaly detection inference on an observed VPN session."""
        inference_service = AnomalyInferenceService(self.db)
        return inference_service.run_inference(request)

    def list_analyses(
        self,
        session_id: Optional[str] = None,
        classification: Optional[str] = None,
        model_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List historical anomaly analyses with optional filtering."""
        query = select(AnomalyAnalysisRow).order_by(desc(AnomalyAnalysisRow.analyzed_at))

        if session_id:
            query = query.where(AnomalyAnalysisRow.session_id == session_id)
        if classification:
            query = query.where(AnomalyAnalysisRow.classification == classification)
        if model_id:
            query = query.where(AnomalyAnalysisRow.model_id == model_id)

        rows = self.db.execute(query.limit(limit).offset(offset)).scalars().all()

        return [
            {
                "id": r.id,
                "session_id": r.session_id,
                "model_id": r.model_id,
                "model_version": r.model_version,
                "feature_version": r.feature_version,
                "classification": r.classification,
                "raw_score": r.raw_score,
                "display_score": r.display_score,
                "features_analyzed": r.features_analyzed,
                "features_anomalous": r.features_anomalous,
                "explanation_summary": r.explanation_summary,
                "analyzed_at": r.analyzed_at.isoformat(),
            }
            for r in rows
        ]

    def get_analysis(self, analysis_id: str) -> Optional[AnomalyAnalysisResponse]:
        """Fetch a full historical anomaly analysis with feature contributions."""
        r = self.db.execute(
            select(AnomalyAnalysisRow).where(AnomalyAnalysisRow.id == analysis_id)
        ).scalar_one_or_none()

        if not r:
            return None

        # Build feature contributions
        contributions = [
            AnomalyFeatureContribution(
                feature_name=fc.feature_name,
                display_name=fc.display_name,
                category=fc.category,
                data_type=fc.data_type,
                observed_value=json.loads(fc.observed_value_json or "null"),
                reference_mean=fc.reference_mean,
                reference_std=fc.reference_std,
                reference_median=fc.reference_median,
                contribution_score=fc.contribution_score,
                deviation=fc.deviation,
                direction=fc.direction,
                evidence_description=fc.evidence_description,
            )
            for fc in r.feature_contributions
        ]

        # 3-signal comparison
        baseline_status = "NO_BASELINE"
        if r.baseline_id:
            link = self.db.execute(
                select(BaselineSessionLinkRow).where(
                    BaselineSessionLinkRow.session_id == r.session_id
                )
            ).scalar_one_or_none()
            baseline_status = "WITHIN_BASELINE" if link else "NO_BASELINE"

        drift_status = "NOT_ANALYZED"
        if r.drift_analysis_id:
            drift_row = self.db.execute(
                select(DriftAnalysisRow).where(DriftAnalysisRow.id == r.drift_analysis_id)
            ).scalar_one_or_none()
            if drift_row:
                drift_status = "DRIFT_DETECTED" if drift_row.features_drifting > 0 else "NO_DRIFT"

        signal_comparison = SignalComparisonSummary(
            baseline_id=r.baseline_id,
            baseline_status=baseline_status,
            drift_analysis_id=r.drift_analysis_id,
            drift_status=drift_status,
            ml_model_id=r.model_id,
            ml_status=r.classification,
        )

        return AnomalyAnalysisResponse(
            id=r.id,
            session_id=r.session_id,
            model_id=r.model_id,
            model_version=r.model_version,
            feature_version=r.feature_version,
            preprocessing_version=r.preprocessing_version,
            classification=r.classification,
            raw_score=r.raw_score,
            display_score=r.display_score,
            features_analyzed=r.features_analyzed,
            features_anomalous=r.features_anomalous,
            explanation_summary=r.explanation_summary,
            feature_contributions=contributions,
            signal_comparison=signal_comparison,
            analyzed_at=r.analyzed_at,
        )

    def get_latest_session_analysis(self, session_id: str) -> Optional[AnomalyAnalysisResponse]:
        """Fetch the most recent anomaly analysis for a given session."""
        latest_row = self.db.execute(
            select(AnomalyAnalysisRow)
            .where(AnomalyAnalysisRow.session_id == session_id)
            .order_by(desc(AnomalyAnalysisRow.analyzed_at))
        ).scalars().first()

        if not latest_row:
            return None

        return self.get_analysis(latest_row.id)
