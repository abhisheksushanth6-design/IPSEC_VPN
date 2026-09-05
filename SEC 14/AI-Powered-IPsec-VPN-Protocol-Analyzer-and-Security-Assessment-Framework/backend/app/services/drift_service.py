"""Application service for Layer 07 Drift Detection.

Bridges FastAPI routes, SQLAlchemy persistence, Section 8 feature vectors,
and Section 9 reference baseline profiles.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db.base import SessionLocal
from app.layers.layer05_feature_engineering.models import EntityType
from app.layers.layer07_drift_detection.config import DEFAULT_DRIFT_CONFIG, DriftThresholdConfig
from app.layers.layer07_drift_detection.models import DriftSeverity, DriftStatus
from app.layers.layer07_drift_detection.service import DriftDetectionDomainService
from app.layers.layer07_drift_detection.validators import DriftPreconditionError
from app.models.baseline import BaselineFeatureRow, BaselineProfileRow
from app.models.drift import DriftAnalysisRow, FeatureDriftRow
from app.schemas.drift import (
    DriftAnalysisSchema,
    DriftAnalysisSummarySchema,
    DriftEngineStatusSchema,
    DriftThresholdConfigSchema,
    FeatureDriftSchema,
)
from app.services.feature_service import feature_service


class DriftService:
    """Coordinates persistence, analysis lifecycle, and historical queries for Layer 07."""

    def __init__(self, config: Optional[DriftThresholdConfig] = None) -> None:
        self.config = config or DEFAULT_DRIFT_CONFIG

    def get_config(self) -> DriftThresholdConfigSchema:
        """Return the current active threshold configuration."""
        d = self.config.to_dict()
        return DriftThresholdConfigSchema(**d)

    def get_status(self) -> DriftEngineStatusSchema:
        """Evaluate and return live engine state and summary metrics."""
        with SessionLocal() as db:
            # Check baseline availability
            active_base = db.scalar(
                select(BaselineProfileRow).where(BaselineProfileRow.is_active.is_(True))
            )

            any_base = db.scalar(select(BaselineProfileRow).limit(1))

            # Query historical metrics
            total_analyses = db.scalar(select(func.count(DriftAnalysisRow.id))) or 0
            distinct_sessions = db.scalar(
                select(func.count(func.distinct(DriftAnalysisRow.session_id)))
            ) or 0
            drifting_sessions = db.scalar(
                select(func.count(func.distinct(DriftAnalysisRow.session_id))).where(
                    DriftAnalysisRow.status == DriftStatus.DRIFT_DETECTED.value
                )
            ) or 0

            # Determine live engine state
            if not any_base or not active_base:
                state = "NOT INITIALIZED"
            elif active_base.session_count < max(active_base.minimum_sessions, self.config.minimum_baseline_samples):
                state = "INSUFFICIENT DATA"
            elif active_base.status not in ("READY", "AVAILABLE", "OPERATIONAL", "ACTIVE"):
                state = "NOT INITIALIZED"
            elif total_analyses > 0:
                state = "AVAILABLE"
            else:
                state = "READY"

            return DriftEngineStatusSchema(
                state=state,
                active_baseline_id=active_base.id if active_base else None,
                active_baseline_name=active_base.name if active_base else None,
                total_analyses=total_analyses,
                sessions_evaluated=distinct_sessions,
                drifting_sessions_count=drifting_sessions,
                feature_schema_version="1.0",
                configuration_version=self.config.config_version,
            )

    def analyze(
        self,
        session_id: str,
        baseline_id: Optional[str] = None,
        config_override: Optional[DriftThresholdConfigSchema] = None,
    ) -> DriftAnalysisSchema:
        """Execute deterministic drift evaluation on an observed session."""
        cfg = (
            DriftThresholdConfig.from_dict(config_override.model_dump())
            if config_override
            else self.config
        )

        with SessionLocal() as db:
            # 1. Fetch baseline
            if baseline_id:
                baseline_row = db.get(BaselineProfileRow, baseline_id)
            else:
                baseline_row = db.scalar(
                    select(BaselineProfileRow).where(BaselineProfileRow.is_active.is_(True))
                )

            if not baseline_row:
                raise DriftPreconditionError(
                    "DRIFT ANALYSIS UNAVAILABLE: No reference baseline profile is available or active."
                )

            # 2. Fetch baseline feature statistical profiles
            base_features = list(
                db.scalars(
                    select(BaselineFeatureRow).where(
                        BaselineFeatureRow.baseline_id == baseline_row.id
                    )
                ).all()
            )

            # 3. Retrieve or extract session feature vector
            vector = None
            try:
                from app.services.fingerprint_service import fingerprint_service
                vector = fingerprint_service.get_or_create_for_session(session_id)
            except Exception:
                vector = None

            if not vector:
                # Fallback: check SessionFingerprintRow
                from types import SimpleNamespace
                from app.models.baseline import SessionFingerprintRow
                fp_row = db.scalar(
                    select(SessionFingerprintRow)
                    .where(SessionFingerprintRow.session_id == session_id)
                    .order_by(SessionFingerprintRow.created_at.desc())
                    .limit(1)
                )
                if fp_row and fp_row.features_json:
                    feats = [SimpleNamespace(**item) for item in json.loads(fp_row.features_json)]
                    vector = SimpleNamespace(
                        feature_version=fp_row.feature_version,
                        features=feats,
                    )

            if not vector:
                # Fallback: check FeatureVectorRow
                from types import SimpleNamespace
                from app.models.feature_vector import FeatureVectorRow
                fv_row = db.scalar(
                    select(FeatureVectorRow)
                    .where(
                        FeatureVectorRow.entity_type == "SESSION",
                        FeatureVectorRow.entity_id == session_id,
                    )
                    .order_by(FeatureVectorRow.extracted_at.desc())
                    .limit(1)
                )
                if fv_row:
                    feats = [
                        SimpleNamespace(
                            name=val.name,
                            display_name=val.name,
                            category="GENERAL",
                            data_type="NUMERIC" if val.num_value is not None else "CATEGORICAL",
                            unit=None,
                            value=val.num_value if val.num_value is not None else (val.text_value if val.text_value is not None else val.bool_value),
                        )
                        for val in fv_row.values
                    ]
                    vector = SimpleNamespace(
                        feature_version=fv_row.feature_version,
                        features=feats,
                    )

            if not vector:
                raise DriftPreconditionError(
                    f"DRIFT ANALYSIS UNAVAILABLE: Unable to locate or extract feature vector for session '{session_id}'."
                )

            # 4. Perform deterministic domain analysis
            domain_service = DriftDetectionDomainService(cfg)
            result = domain_service.analyze_session(
                session_id=session_id,
                feature_vector=vector,
                baseline=baseline_row,
                baseline_features=base_features,
            )

            # 5. Persist analysis to SQLite
            analysis_row = DriftAnalysisRow(
                id=result.analysis_id,
                session_id=result.session_id,
                baseline_id=result.baseline_id,
                baseline_version=result.baseline_version,
                feature_version=result.feature_version,
                configuration_version=result.configuration_version,
                status=result.status.value,
                severity=result.severity.value,
                features_analyzed=result.features_analyzed,
                features_drifting=result.features_drifting,
                config_json=json.dumps(result.thresholds_used),
                analyzed_at=datetime.fromisoformat(result.analyzed_at),
            )
            db.add(analysis_row)

            for feat in result.feature_results:
                f_row = FeatureDriftRow(
                    analysis_id=result.analysis_id,
                    feature_name=feat.feature_name,
                    display_name=feat.display_name,
                    category=feat.category,
                    data_type=feat.data_type,
                    unit=feat.unit,
                    current_value_json=json.dumps(feat.current_value),
                    baseline_mean=feat.baseline_mean,
                    baseline_std=feat.baseline_std,
                    baseline_median=feat.baseline_median,
                    baseline_distribution_json=json.dumps(feat.baseline_distribution)
                    if feat.baseline_distribution
                    else None,
                    deviation=feat.deviation,
                    z_score=feat.z_score,
                    comparison_method=feat.comparison_method.value,
                    drift_detected=feat.drift_detected,
                    severity=feat.severity.value,
                    reason=feat.reason,
                )
                db.add(f_row)

            db.commit()

            # 6. Build response
            return self._build_analysis_schema(result)

    def get_analysis(self, analysis_id: str) -> Optional[DriftAnalysisSchema]:
        """Fetch full drift analysis with feature results by analysis ID."""
        with SessionLocal() as db:
            row = db.get(DriftAnalysisRow, analysis_id)
            if not row:
                return None

            features = list(
                db.scalars(
                    select(FeatureDriftRow)
                    .where(FeatureDriftRow.analysis_id == analysis_id)
                    .order_by(FeatureDriftRow.feature_name)
                ).all()
            )

            feature_schemas = [self._row_to_feature_schema(f) for f in features]
            thresholds = json.loads(row.config_json) if row.config_json else {}

            return DriftAnalysisSchema(
                id=row.id,
                session_id=row.session_id,
                baseline_id=row.baseline_id,
                baseline_version=row.baseline_version,
                feature_version=row.feature_version,
                configuration_version=row.configuration_version,
                status=row.status,
                severity=row.severity,
                features_analyzed=row.features_analyzed,
                features_drifting=row.features_drifting,
                analyzed_at=row.analyzed_at.isoformat(),
                feature_results=feature_schemas,
                thresholds_used=thresholds,
            )

    def list_analyses(
        self,
        session_id: Optional[str] = None,
        baseline_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DriftAnalysisSummarySchema]:
        """List historical drift evaluations with filtering and sorting."""
        with SessionLocal() as db:
            stmt = select(DriftAnalysisRow).order_by(DriftAnalysisRow.analyzed_at.desc())
            if session_id:
                stmt = stmt.where(DriftAnalysisRow.session_id == session_id)
            if baseline_id:
                stmt = stmt.where(DriftAnalysisRow.baseline_id == baseline_id)
            if status:
                stmt = stmt.where(DriftAnalysisRow.status == status)
            if severity:
                stmt = stmt.where(DriftAnalysisRow.severity == severity)

            rows = list(db.scalars(stmt.offset(offset).limit(limit)).all())
            return [
                DriftAnalysisSummarySchema(
                    id=r.id,
                    session_id=r.session_id,
                    baseline_id=r.baseline_id,
                    baseline_version=r.baseline_version,
                    feature_version=r.feature_version,
                    configuration_version=r.configuration_version,
                    status=r.status,
                    severity=r.severity,
                    features_analyzed=r.features_analyzed,
                    features_drifting=r.features_drifting,
                    analyzed_at=r.analyzed_at.isoformat(),
                )
                for r in rows
            ]

    def get_features(self, analysis_id: str) -> List[FeatureDriftSchema]:
        """Retrieve individual feature results for a specific analysis."""
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(FeatureDriftRow)
                    .where(FeatureDriftRow.analysis_id == analysis_id)
                    .order_by(FeatureDriftRow.feature_name)
                ).all()
            )
            return [self._row_to_feature_schema(r) for r in rows]

    def get_latest_for_session(self, session_id: str) -> Optional[DriftAnalysisSchema]:
        """Fetch the most recent drift evaluation for a given session."""
        with SessionLocal() as db:
            row = db.scalar(
                select(DriftAnalysisRow)
                .where(DriftAnalysisRow.session_id == session_id)
                .order_by(DriftAnalysisRow.analyzed_at.desc())
                .limit(1)
            )
            if not row:
                return None
            return self.get_analysis(row.id)

    def clear(self) -> None:
        """Clear all stored drift evaluations (for test resets)."""
        with SessionLocal() as db:
            db.execute(delete(FeatureDriftRow))
            db.execute(delete(DriftAnalysisRow))
            db.commit()

    def _build_analysis_schema(self, res: Any) -> DriftAnalysisSchema:
        feature_schemas = [
            FeatureDriftSchema(
                feature_name=f.feature_name,
                display_name=f.display_name,
                category=f.category,
                data_type=f.data_type,
                unit=f.unit,
                current_value=f.current_value,
                baseline_mean=f.baseline_mean,
                baseline_std=f.baseline_std,
                baseline_median=f.baseline_median,
                baseline_distribution=f.baseline_distribution,
                deviation=f.deviation,
                z_score=f.z_score,
                comparison_method=f.comparison_method.value,
                drift_detected=f.drift_detected,
                severity=f.severity.value,
                reason=f.reason,
            )
            for f in res.feature_results
        ]
        return DriftAnalysisSchema(
            id=res.analysis_id,
            session_id=res.session_id,
            baseline_id=res.baseline_id,
            baseline_version=res.baseline_version,
            feature_version=res.feature_version,
            configuration_version=res.configuration_version,
            status=res.status.value,
            severity=res.severity.value,
            features_analyzed=res.features_analyzed,
            features_drifting=res.features_drifting,
            analyzed_at=res.analyzed_at,
            feature_results=feature_schemas,
            thresholds_used=res.thresholds_used,
        )

    def _row_to_feature_schema(self, row: FeatureDriftRow) -> FeatureDriftSchema:
        curr_val = json.loads(row.current_value_json) if row.current_value_json else None
        b_dist = (
            json.loads(row.baseline_distribution_json)
            if row.baseline_distribution_json
            else None
        )
        return FeatureDriftSchema(
            feature_name=row.feature_name,
            display_name=row.display_name,
            category=row.category,
            data_type=row.data_type,
            unit=row.unit,
            current_value=curr_val,
            baseline_mean=row.baseline_mean,
            baseline_std=row.baseline_std,
            baseline_median=row.baseline_median,
            baseline_distribution=b_dist,
            deviation=row.deviation,
            z_score=row.z_score,
            comparison_method=row.comparison_method,
            drift_detected=row.drift_detected,
            severity=row.severity,
            reason=row.reason,
        )


drift_service = DriftService()
