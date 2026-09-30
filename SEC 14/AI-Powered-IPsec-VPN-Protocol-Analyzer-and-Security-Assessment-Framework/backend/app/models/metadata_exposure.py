"""ORM model for metadata exposure and leakage assessments."""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MetadataExposureRow(Base):
    """Evaluation of passive metadata exposure across 5 leakage dimensions."""

    __tablename__ = "metadata_exposure_assessments"
    __table_args__ = (
        Index("ix_metadata_exposure_capture", "capture_id"),
        Index("ix_metadata_exposure_session", "session_id"),
        Index("ix_metadata_exposure_risk", "risk_level"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 to 100.0
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)   # LOW, MEDIUM, HIGH, CRITICAL
    spi_leakage_score: Mapped[float] = mapped_column(Float, nullable=False)
    sequence_leakage_score: Mapped[float] = mapped_column(Float, nullable=False)
    packet_length_leakage_score: Mapped[float] = mapped_column(Float, nullable=False)
    timing_leakage_score: Mapped[float] = mapped_column(Float, nullable=False)
    topology_leakage_score: Mapped[float] = mapped_column(Float, nullable=False)
    findings_json: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
