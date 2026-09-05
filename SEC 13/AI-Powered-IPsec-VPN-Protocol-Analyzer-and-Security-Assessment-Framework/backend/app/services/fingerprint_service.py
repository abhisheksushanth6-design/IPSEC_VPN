"""Fingerprint service for generating, persisting, and querying session fingerprints.

Operates over Section 8 feature vectors. Does not invent or fabricate values.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.base import SessionLocal
from app.layers.layer05_feature_engineering.models import FEATURE_VERSION, FeatureVector
from app.layers.layer06_session_fingerprinting.fingerprint import build_session_fingerprint
from app.layers.layer06_session_fingerprinting.models import (
    FingerprintFeature,
    SessionFingerprint,
)
from app.models.baseline import SessionFingerprintRow
from app.models.feature_vector import FeatureVectorRow
from app.models.ipsec_session import IPsecSession
from app.schemas.fingerprint import (
    FingerprintComparisonItemSchema,
    FingerprintComparisonSchema,
    FingerprintFeatureSchema,
    FingerprintSummarySchema,
    SessionFingerprintSchema,
)
from app.services.feature_service import feature_service
from app.services.packet_service import PacketServiceError, packet_service

logger = logging.getLogger(__name__)


class FingerprintService:
    def get_or_create_for_session(self, session_id: str) -> SessionFingerprint:
        """Fetch existing session fingerprint or derive and store a new one."""
        capture_id = packet_service.capture_id
        if not capture_id:
            raise PacketServiceError(
                "PACKET_DATA_UNAVAILABLE",
                "No capture loaded. Load a packet capture first.",
                409,
            )

        with SessionLocal() as db:
            # Check if session exists
            session_row = db.get(IPsecSession, session_id)
            if not session_row or session_row.capture_id != capture_id:
                raise PacketServiceError(
                    "SESSION_NOT_FOUND",
                    f"No session '{session_id}' found for current capture.",
                    404,
                )

            # Check if fingerprint already exists
            fp_row = db.scalar(
                select(SessionFingerprintRow).where(
                    SessionFingerprintRow.session_id == session_id,
                    SessionFingerprintRow.capture_id == capture_id,
                )
            )
            if fp_row:
                return self._row_to_domain(fp_row)

        # Feature vector needed: build it via feature_service
        try:
            vector_schema = feature_service.for_entity("SESSION", session_id)
            # Reconstruct domain FeatureVector from stored values
            vector = self._schema_to_domain_vector(vector_schema)
        except PacketServiceError:
            # Not extracted yet: extract now
            vector_schema = feature_service.extract("SESSION", session_id)
            vector = self._schema_to_domain_vector(vector_schema)

        fingerprint = build_session_fingerprint(vector, capture_id)
        self._persist_fingerprint(fingerprint)
        return fingerprint

    def get(self, fingerprint_id: str) -> SessionFingerprint:
        """Retrieve a single fingerprint by its unique ID."""
        with SessionLocal() as db:
            row = db.get(SessionFingerprintRow, fingerprint_id)
            if not row:
                raise PacketServiceError(
                    "FINGERPRINT_NOT_FOUND",
                    f"No fingerprint found with identifier '{fingerprint_id}'.",
                    404,
                )
            return self._row_to_domain(row)

    def list_all(self, capture_id: Optional[str] = None) -> List[SessionFingerprint]:
        """List session fingerprints, optionally filtered by capture."""
        target_capture = capture_id or packet_service.capture_id
        with SessionLocal() as db:
            stmt = select(SessionFingerprintRow).order_by(SessionFingerprintRow.created_at.desc())
            if target_capture:
                stmt = stmt.where(SessionFingerprintRow.capture_id == target_capture)
            rows = list(db.scalars(stmt))
            return [self._row_to_domain(r) for r in rows]

    def compare(self, id_a: str, id_b: str) -> FingerprintComparisonSchema:
        """Provide factual side-by-side comparison of two fingerprints."""
        fp_a = self.get(id_a)
        fp_b = self.get(id_b)

        # Collect unique feature names across both fingerprints
        names = []
        for f in fp_a.features:
            if f.name not in names:
                names.append(f.name)
        for f in fp_b.features:
            if f.name not in names:
                names.append(f.name)

        items: List[FingerprintComparisonItemSchema] = []
        for name in names:
            fa = fp_a.get_feature(name)
            fb = fp_b.get_feature(name)
            disp = fa.display_name if fa else (fb.display_name if fb else name)
            cat = fa.category if fa else (fb.category if fb else "GENERAL")
            dtype = fa.data_type if fa else (fb.data_type if fb else "STRING")
            unit = fa.unit if fa else (fb.unit if fb else None)

            items.append(
                FingerprintComparisonItemSchema(
                    feature_name=name,
                    display_name=disp,
                    category=cat,
                    data_type=dtype,
                    unit=unit,
                    value_a=fa.value if fa else None,
                    value_b=fb.value if fb else None,
                    availability_a=fa.availability if fa else "UNAVAILABLE",
                    availability_b=fb.availability if fb else "UNAVAILABLE",
                )
            )

        summary_a = FingerprintSummarySchema(
            id=fp_a.fingerprint_id,
            session_id=fp_a.session_id,
            capture_id=fp_a.capture_id,
            feature_version=fp_a.feature_version,
            signature=fp_a.fingerprint_signature,
            created_at=fp_a.created_at,
            feature_count=fp_a.feature_count,
        )
        summary_b = FingerprintSummarySchema(
            id=fp_b.fingerprint_id,
            session_id=fp_b.session_id,
            capture_id=fp_b.capture_id,
            feature_version=fp_b.feature_version,
            signature=fp_b.fingerprint_signature,
            created_at=fp_b.created_at,
            feature_count=fp_b.feature_count,
        )

        return FingerprintComparisonSchema(
            fingerprint_a=summary_a,
            fingerprint_b=summary_b,
            features=items,
        )

    def _persist_fingerprint(self, fp: SessionFingerprint) -> None:
        with SessionLocal() as db:
            # Idempotent overwrite for identical session+capture
            db.execute(
                delete(SessionFingerprintRow).where(
                    SessionFingerprintRow.session_id == fp.session_id,
                    SessionFingerprintRow.capture_id == fp.capture_id,
                )
            )
            features_data = [
                {
                    "name": f.name,
                    "display_name": f.display_name,
                    "category": f.category,
                    "data_type": f.data_type,
                    "unit": f.unit,
                    "value": f.value,
                    "availability": f.availability,
                    "quality": f.quality,
                    "source": f.source,
                }
                for f in fp.features
            ]

            row = SessionFingerprintRow(
                id=fp.fingerprint_id,
                session_id=fp.session_id,
                capture_id=fp.capture_id,
                feature_version=fp.feature_version,
                signature=fp.fingerprint_signature,
                feature_count=fp.feature_count,
                features_json=json.dumps(features_data),
                created_at=datetime.now(timezone.utc),
            )
            db.add(row)
            db.commit()

    @staticmethod
    def _row_to_domain(row: SessionFingerprintRow) -> SessionFingerprint:
        raw_feats = json.loads(row.features_json)
        features = [
            FingerprintFeature(
                name=f["name"],
                display_name=f["display_name"],
                category=f["category"],
                data_type=f["data_type"],
                unit=f.get("unit"),
                value=f.get("value"),
                availability=f["availability"],
                quality=f["quality"],
                source=f["source"],
            )
            for f in raw_feats
        ]
        created_str = (
            row.created_at.isoformat()
            if isinstance(row.created_at, datetime)
            else str(row.created_at)
        )
        return SessionFingerprint(
            fingerprint_id=row.id,
            session_id=row.session_id,
            capture_id=row.capture_id,
            feature_version=row.feature_version,
            fingerprint_signature=row.signature,
            created_at=created_str,
            features=features,
            feature_count=row.feature_count,
        )

    @staticmethod
    def _schema_to_domain_vector(v_schema) -> FeatureVector:
        from app.layers.layer05_feature_engineering.models import (
            FeatureValue,
            SourceAvailability,
        )

        domain_features = [
            FeatureValue(
                name=f.name,
                value=f.value,
                availability=f.availability,  # type: ignore[arg-type]
                quality=f.quality,  # type: ignore[arg-type]
                source=f.source,
                detail=f.detail,
                normalized_value=f.normalized_value,
                normalization_method=f.normalization_method,
            )
            for f in v_schema.features
        ]
        sources = [
            SourceAvailability(name=s.name, available=s.available, detail=s.detail)
            for s in v_schema.sources
        ]
        return FeatureVector(
            entity_id=v_schema.entity_id,
            entity_type=v_schema.entity_type,
            entity_label=v_schema.entity_label,
            capture_id=v_schema.capture_id,
            feature_version=v_schema.feature_version,
            generated_at=v_schema.generated_at,
            features=domain_features,
            sources=sources,
        )


fingerprint_service = FingerprintService()
