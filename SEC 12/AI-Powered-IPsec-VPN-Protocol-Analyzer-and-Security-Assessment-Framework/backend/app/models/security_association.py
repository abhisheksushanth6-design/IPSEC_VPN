"""ORM models for discovered Security Associations, lifecycle events and packet links."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityAssociationRow(Base):
    __tablename__ = "security_associations"
    __table_args__ = (Index("ix_security_associations_capture", "capture_id"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[str] = mapped_column(String(8), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    initiator: Mapped[str] = mapped_column(String(64), nullable=False)
    responder: Mapped[str] = mapped_column(String(64), nullable=False)
    ike_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    initiator_spi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    responder_spi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    spi: Mapped[str | None] = mapped_column(String(16), nullable=True)
    start_time: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    nat_traversal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parent_sa_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    association: Mapped[str] = mapped_column(String(16), nullable=False)
    rekey_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    session_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    detail_json: Mapped[str] = mapped_column(Text, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)

    events: Mapped[list["SALifecycleEventRow"]] = relationship(back_populates="sa", cascade="all, delete-orphan", order_by="SALifecycleEventRow.sequence")
    packets: Mapped[list["SAPacketLink"]] = relationship(back_populates="sa", cascade="all, delete-orphan", order_by="SAPacketLink.packet_number")


class SALifecycleEventRow(Base):
    """Append-only lifecycle history; rows are never updated after discovery."""

    __tablename__ = "sa_lifecycle_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sa_id: Mapped[str] = mapped_column(ForeignKey("security_associations.id", ondelete="CASCADE"), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[str | None] = mapped_column(String(40), nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    previous_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    packet_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    spi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    sa: Mapped[SecurityAssociationRow] = relationship(back_populates="events")


class SAPacketLink(Base):
    __tablename__ = "sa_packet_links"
    __table_args__ = (Index("ix_sa_packet_links_capture_number", "capture_id", "packet_number"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sa_id: Mapped[str] = mapped_column(ForeignKey("security_associations.id", ondelete="CASCADE"), nullable=False, index=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    packet_number: Mapped[int] = mapped_column(Integer, nullable=False)

    sa: Mapped[SecurityAssociationRow] = relationship(back_populates="packets")
