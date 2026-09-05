"""ORM models for session fingerprints and baseline profiles.

Follows the SQLite schema patterns established in Sections 0–8.
Stored facts are purely descriptive baseline models; no security judgments or
risk classifications are persisted here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SessionFingerprintRow(Base):
    """Persisted behavioral fingerprint for an observed IPsec session."""

    __tablename__ = "session_fingerprints"
    __table_args__ = (
        Index("ix_fingerprints_capture", "capture_id"),
        Index("ix_fingerprints_session", "session_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    features_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)


class BaselineProfileRow(Base):
    """Reference behavioral baseline compiled from observed session fingerprints."""

    __tablename__ = "baseline_profiles"
    __table_args__ = (
        Index("ix_baseline_profiles_active", "is_active"),
        Index("ix_baseline_profiles_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="BUILDING")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    session_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    minimum_sessions: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    first_observation: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    last_observation: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    coverage_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    data_quality_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)

    features: Mapped[list["BaselineFeatureRow"]] = relationship(
        back_populates="baseline",
        cascade="all, delete-orphan",
        order_by="BaselineFeatureRow.name",
    )
    sessions: Mapped[list["BaselineSessionLinkRow"]] = relationship(
        back_populates="baseline",
        cascade="all, delete-orphan",
    )


class BaselineFeatureRow(Base):
    """Descriptive statistics for a single feature within a baseline profile."""

    __tablename__ = "baseline_features"
    __table_args__ = (
        Index("ix_baseline_features_baseline_name", "baseline_id", "name", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    baseline_id: Mapped[str] = mapped_column(
        ForeignKey("baseline_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    data_type: Mapped[str] = mapped_column(String(16), nullable=False)
    unit: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Numerical statistics
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mean: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    median: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    min_val: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    max_val: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    std_dev: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    p25: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    p50: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    p75: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    p95: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Categorical and boolean summaries
    categorical_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    boolean_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Availability and completeness
    total_samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    missing_samples: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completeness_ratio: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    baseline: Mapped[BaselineProfileRow] = relationship(back_populates="features")


class BaselineSessionLinkRow(Base):
    """Link between a baseline profile and an included session observation."""

    __tablename__ = "baseline_sessions"
    __table_args__ = (
        Index("ix_baseline_sessions_link", "baseline_id", "session_id", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    baseline_id: Mapped[str] = mapped_column(
        ForeignKey("baseline_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_id: Mapped[str] = mapped_column(String(64), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)

    baseline: Mapped[BaselineProfileRow] = relationship(back_populates="sessions")
