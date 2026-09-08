"""ORM model for Layer 10 Risk Assessment persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RiskAssessmentRow(Base):
    """Persisted session risk evaluation record."""

    __tablename__ = "risk_assessments"
    __table_args__ = (
        Index("ix_risk_assessments_session", "session_id"),
        Index("ix_risk_assessments_risk_level", "risk_level"),
        Index("ix_risk_assessments_decision", "decision"),
        Index("ix_risk_assessments_evaluated_at", "evaluated_at"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(40), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    decision: Mapped[str] = mapped_column(String(16), nullable=False)    # ALLOW, INSPECT, RESTRICT, TERMINATE
    data_quality: Mapped[str] = mapped_column(String(16), nullable=False)  # COMPLETE, PARTIAL
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    vulnerability_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    ml_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    drift_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    state_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    contributing_signals_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    recommended_actions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    available_signals_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    unavailable_signals_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
