"""ORM model for AI-powered traffic classification within encrypted ESP sessions."""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TrafficClassificationRow(Base):
    """Result of multi-class AI traffic-type prediction for an encrypted ESP flow."""

    __tablename__ = "traffic_classifications"
    __table_args__ = (
        Index("ix_traffic_classifications_capture", "capture_id"),
        Index("ix_traffic_classifications_session", "session_id"),
        Index("ix_traffic_classifications_type", "traffic_type"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    flow_id: Mapped[str] = mapped_column(String(64), nullable=False)
    traffic_type: Mapped[str] = mapped_column(String(32), nullable=False)  # VOIP, WHATSAPP, EMAIL, VIDEO_STREAMING, GENERIC
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    probabilities_json: Mapped[str] = mapped_column(Text, nullable=False)  # {"VOIP": 0.85, ...}
    features_json: Mapped[str] = mapped_column(Text, nullable=False)        # Extracted feature facts
    explainability_json: Mapped[str] = mapped_column(Text, nullable=False)  # Feature importances/contributions
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
