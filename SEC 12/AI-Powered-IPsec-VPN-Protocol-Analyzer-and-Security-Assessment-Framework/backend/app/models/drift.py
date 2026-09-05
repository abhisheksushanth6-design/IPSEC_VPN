"""SQLAlchemy ORM models for Layer 07 Drift Detection persistence.

Stores deterministic drift evaluations, feature deviations, and threshold configurations.
Strictly records factual comparisons; no security risk scores or threat classifications.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DriftAnalysisRow(Base):
    """Persisted session drift analysis record."""

    __tablename__ = "drift_analyses"
    __table_args__ = (
        Index("ix_drift_analyses_session", "session_id"),
        Index("ix_drift_analyses_baseline", "baseline_id"),
        Index("ix_drift_analyses_status", "status"),
        Index("ix_drift_analyses_severity", "severity"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_id: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    configuration_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    features_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    features_drifting: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)

    feature_drifts: Mapped[List[FeatureDriftRow]] = relationship(
        "FeatureDriftRow",
        back_populates="analysis",
        cascade="all, delete-orphan",
        order_by="FeatureDriftRow.feature_name",
    )


class FeatureDriftRow(Base):
    """Detailed feature comparison record belonging to a drift analysis."""

    __tablename__ = "feature_drifts"
    __table_args__ = (
        Index("ix_feature_drifts_analysis", "analysis_id"),
        Index("ix_feature_drifts_name", "feature_name"),
        Index("ix_feature_drifts_drift", "drift_detected"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("drift_analyses.id"), nullable=False)
    feature_name: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    data_type: Mapped[str] = mapped_column(String(32), nullable=False)
    unit: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    current_value_json: Mapped[str] = mapped_column(Text, nullable=False, default="null")
    baseline_mean: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    baseline_std: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    baseline_median: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    baseline_distribution_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deviation: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    z_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    comparison_method: Mapped[str] = mapped_column(String(64), nullable=False)
    drift_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, default="NONE")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")

    analysis: Mapped[DriftAnalysisRow] = relationship(
        "DriftAnalysisRow",
        back_populates="feature_drifts",
    )
