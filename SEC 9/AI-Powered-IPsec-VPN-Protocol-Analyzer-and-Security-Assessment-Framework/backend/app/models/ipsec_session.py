"""ORM models for discovered IPsec sessions and their packet associations."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IPsecSession(Base):
    __tablename__ = "ipsec_sessions"
    __table_args__ = (Index("ix_ipsec_sessions_capture", "capture_id"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    destination: Mapped[str] = mapped_column(String(64), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    correlation: Mapped[str] = mapped_column(String(16), nullable=False)
    start_time: Mapped[str | None] = mapped_column(String(40), nullable=True)
    end_time: Mapped[str | None] = mapped_column(String(40), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    ike_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    esp_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ah_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ike_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    nat_traversal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # JSON documents produced by the correlation engine (IKE/ESP/AH info, timeline, activity).
    detail_json: Mapped[str] = mapped_column(Text, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)

    packets: Mapped[list["SessionPacket"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="SessionPacket.packet_number"
    )


class SessionPacket(Base):
    """Association by packet number, which is stable within a capture."""

    __tablename__ = "session_packets"
    __table_args__ = (Index("ix_session_packets_capture_number", "capture_id", "packet_number", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("ipsec_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    packet_number: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(8), nullable=False)  # IKE / ESP / AH

    session: Mapped[IPsecSession] = relationship(back_populates="packets")
