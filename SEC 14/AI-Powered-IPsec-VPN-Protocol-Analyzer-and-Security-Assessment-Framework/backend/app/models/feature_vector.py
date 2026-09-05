"""ORM models for extracted feature vectors and their values.

Feature *definitions* are deliberately not stored. The registry in Layer 05
is the single source of truth for what a feature means, and copying it into
the database would create a second one that could drift. Rows here reference
definitions by ``(level, name)`` and carry only the calculated facts.

Values are stored in typed columns rather than as strings, so an integer
count stays an integer and a boolean stays a boolean all the way to the API.
``normalized_value`` exists but is written as NULL: normalization parameters
have to be fitted on real data, which is a later section's work, and the raw
value is never overwritten by one.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FeatureVectorRow(Base):
    """One extraction run for one entity."""

    __tablename__ = "feature_vectors"
    __table_args__ = (
        Index("ix_feature_vectors_capture", "capture_id"),
        Index(
            "ix_feature_vectors_entity",
            "capture_id",
            "entity_type",
            "entity_id",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(8), nullable=False)  # PACKET / SESSION / SA
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_label: Mapped[str] = mapped_column(String(200), nullable=False)
    feature_version: Mapped[str] = mapped_column(String(16), nullable=False)
    generated_at: Mapped[str] = mapped_column(String(40), nullable=False)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unavailable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Source availability for lineage; a small JSON list, not a feature store.
    sources_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    extracted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )

    values: Mapped[list["FeatureValueRow"]] = relationship(
        back_populates="vector",
        cascade="all, delete-orphan",
        order_by="FeatureValueRow.ordinal",
    )


class FeatureValueRow(Base):
    """One calculated feature within a vector, in a type-appropriate column."""

    __tablename__ = "feature_values"
    __table_args__ = (Index("ix_feature_values_name", "vector_id", "name", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vector_id: Mapped[str] = mapped_column(
        ForeignKey("feature_vectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    level: Mapped[str] = mapped_column(String(8), nullable=False)
    data_type: Mapped[str] = mapped_column(String(16), nullable=False)

    value_integer: Mapped[int | None] = mapped_column(Integer, nullable=True)
    value_float: Mapped[float | None] = mapped_column(Float, nullable=True)
    value_boolean: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    value_text: Mapped[str | None] = mapped_column(String(200), nullable=True)

    availability: Mapped[str] = mapped_column(String(16), nullable=False)
    quality: Mapped[str] = mapped_column(String(24), nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalization_method: Mapped[str] = mapped_column(String(24), nullable=False, default="NONE")
    #: Always NULL in Section 8. Raw values are never overwritten in place.
    normalized_value: Mapped[float | None] = mapped_column(Float, nullable=True)

    vector: Mapped[FeatureVectorRow] = relationship(back_populates="values")
