"""ORM model for Standalone Threat Matrix entries."""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatMatrixRow(Base):
    """Specific threat evaluation mapped to MITRE ATT&CK, NIST SP 800-77, and RFCs."""

    __tablename__ = "threat_matrix_entries"
    __table_args__ = (
        Index("ix_threat_matrix_capture", "capture_id"),
        Index("ix_threat_matrix_session", "session_id"),
        Index("ix_threat_matrix_severity", "severity"),
        Index("ix_threat_matrix_status", "status"),
        Index("ix_threat_matrix_mitre", "mitre_technique_id"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    matrix_id: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g., TM-IPSEC-001
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)   # LOW, MEDIUM, HIGH, CRITICAL
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nist_control: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rfc_reference: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)     # DETECTED, VULNERABLE, MITIGATED, NOT_APPLICABLE
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
