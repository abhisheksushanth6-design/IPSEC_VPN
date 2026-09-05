"""SQLAlchemy ORM models for Layer 08 AI / ML Anomaly Detection persistence.

Stores persisted ML models, training datasets, anomaly analysis runs, and
factual feature contribution evidence.
Strictly records machine-learning deviations and diagnostics; no security threat
scores, risk fusion, or vulnerability classifications are stored here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MLModelRow(Base):
    """Persisted machine learning anomaly detection model record."""

    __tablename__ = "ml_models"
    __table_args__ = (
        Index("ix_ml_models_status", "status"),
        Index("ix_ml_models_active", "is_active"),
        Index("ix_ml_models_version", "model_version"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    model_type: Mapped[str] = mapped_column(String(64), nullable=False, default="IsolationForest")
    model_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    preprocessing_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    training_dataset_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    baseline_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    training_samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NOT_INITIALIZED")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    configuration_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    metrics_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    feature_names_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    model_artifact_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    model_checksum: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)


class TrainingDatasetRow(Base):
    """Persisted record of an ML training dataset snapshot."""

    __tablename__ = "training_datasets"
    __table_args__ = (
        Index("ix_training_datasets_baseline", "baseline_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    baseline_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    session_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    feature_names_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    missing_data_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)


class AnomalyAnalysisRow(Base):
    """Persisted session anomaly analysis run."""

    __tablename__ = "anomaly_analyses"
    __table_args__ = (
        Index("ix_anomaly_analyses_session", "session_id"),
        Index("ix_anomaly_analyses_model", "model_id"),
        Index("ix_anomaly_analyses_classification", "classification"),
        Index("ix_anomaly_analyses_analyzed_at", "analyzed_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    model_id: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    preprocessing_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    classification: Mapped[str] = mapped_column(String(32), nullable=False)  # NORMAL / ANOMALOUS
    raw_score: Mapped[float] = mapped_column(Float, nullable=False)
    display_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0-100 normalized
    features_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    features_anomalous: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    explanation_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    baseline_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    drift_analysis_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)

    feature_contributions: Mapped[List[AnomalyFeatureContributionRow]] = relationship(
        "AnomalyFeatureContributionRow",
        back_populates="analysis",
        cascade="all, delete-orphan",
        order_by="AnomalyFeatureContributionRow.contribution_score.desc()",
    )


class AnomalyFeatureContributionRow(Base):
    """Evidence record of an individual feature's contribution to anomaly score."""

    __tablename__ = "anomaly_feature_contributions"
    __table_args__ = (
        Index("ix_anom_feat_contrib_analysis", "analysis_id"),
        Index("ix_anom_feat_contrib_name", "feature_name"),
        Index("ix_anom_feat_contrib_direction", "direction"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("anomaly_analyses.id", ondelete="CASCADE"), nullable=False
    )
    feature_name: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    data_type: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_value_json: Mapped[str] = mapped_column(Text, nullable=False, default="null")
    reference_mean: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    reference_std: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    reference_median: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    contribution_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    deviation: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    direction: Mapped[str] = mapped_column(String(32), nullable=False, default="WITHIN_RANGE")
    evidence_description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    analysis: Mapped[AnomalyAnalysisRow] = relationship(
        "AnomalyAnalysisRow",
        back_populates="feature_contributions",
    )
