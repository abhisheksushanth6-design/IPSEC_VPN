"""Baseline service for managing, persisting, and querying baseline profiles.

Coordinates factual descriptive statistics over observed session fingerprints.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.db.base import SessionLocal
from app.layers.layer05_feature_engineering.models import FEATURE_VERSION
from app.layers.layer06_session_fingerprinting.models import (
    BaselineCoverage,
    BaselineDataQuality,
    BaselineFeatureProfile,
    BaselineProfile,
    BaselineStatus,
    BooleanStatistics,
    CategoricalStatistics,
    NumericStatistics,
    SessionFingerprint,
)
from app.layers.layer06_session_fingerprinting.service import build_baseline_profile
from app.models.baseline import (
    BaselineFeatureRow,
    BaselineProfileRow,
    BaselineSessionLinkRow,
    SessionFingerprintRow,
)
from app.models.ipsec_session import IPsecSession
from app.schemas.baseline import (
    BaselineBuildRequestSchema,
    BaselineComparisonItemSchema,
    BaselineComparisonSchema,
    BaselineCoverageSchema,
    BaselineDataQualitySchema,
    BaselineEngineStatusSchema,
    BaselineFeatureProfileSchema,
    BaselineProfileSchema,
    BaselineSessionItemSchema,
    BaselineSummarySchema,
    BooleanStatisticsSchema,
    CategoricalStatisticsSchema,
    NumericStatisticsSchema,
)
from app.services.fingerprint_service import fingerprint_service
from app.services.packet_service import PacketServiceError, packet_service

logger = logging.getLogger(__name__)


class BaselineService:
    def __init__(self) -> None:
        self._building = False
        self._last_error: Optional[str] = None

    def status(self) -> BaselineEngineStatusSchema:
        """Report actual state and factual summary metrics."""
        capture_id = packet_service.capture_id
        with SessionLocal() as db:
            active_row = db.scalar(
                select(BaselineProfileRow).where(BaselineProfileRow.is_active.is_(True))
            )
            total_baselines = db.scalar(select(func.count(BaselineProfileRow.id))) or 0
            total_fps = db.scalar(select(func.count(SessionFingerprintRow.id))) or 0
            total_sessions_profiled = (
                db.scalar(select(func.count(func.distinct(BaselineSessionLinkRow.session_id))))
                or 0
            )
            total_features_profiled = (
                db.scalar(select(func.count(BaselineFeatureRow.id))) or 0
            )

            # Check available sessions in capture
            session_count = 0
            if capture_id:
                session_count = (
                    db.scalar(
                        select(func.count(IPsecSession.id)).where(
                            IPsecSession.capture_id == capture_id
                        )
                    )
                    or 0
                )

        if self._last_error:
            state = "ERROR"
        elif self._building:
            state = "BUILDING"
        elif total_baselines > 0:
            state = "AVAILABLE"
        elif capture_id and session_count > 0:
            state = "READY"
        elif capture_id:
            state = "COLLECTING"
        else:
            state = "NOT INITIALIZED"

        return BaselineEngineStatusSchema(
            state=state,
            feature_version=FEATURE_VERSION,
            active_baseline_id=active_row.id if active_row else None,
            active_baseline_name=active_row.name if active_row else None,
            total_baselines=total_baselines,
            total_fingerprints=total_fps,
            total_sessions_profiled=total_sessions_profiled,
            total_features_profiled=total_features_profiled,
            last_error=self._last_error,
        )

    def create_or_build(self, request: BaselineBuildRequestSchema) -> BaselineProfileSchema:
        """Build and persist a new baseline profile from session observations."""
        capture_id = packet_service.capture_id
        if not capture_id:
            raise PacketServiceError(
                "PACKET_DATA_UNAVAILABLE",
                "No capture loaded. Load a packet capture first.",
                409,
            )

        self._building = True
        try:
            with SessionLocal() as db:
                if request.session_ids:
                    # Validate explicit sessions
                    session_rows = list(
                        db.scalars(
                            select(IPsecSession).where(
                                IPsecSession.id.in_(request.session_ids),
                                IPsecSession.capture_id == capture_id,
                            )
                        )
                    )
                    if len(session_rows) != len(request.session_ids):
                        raise PacketServiceError(
                            "SESSION_NOT_FOUND",
                            "One or more requested sessions do not exist in the current capture.",
                            404,
                        )
                else:
                    session_rows = list(
                        db.scalars(
                            select(IPsecSession).where(IPsecSession.capture_id == capture_id)
                        )
                    )

                if not session_rows:
                    raise PacketServiceError(
                        "INSUFFICIENT_DATA",
                        "No session observations available in current capture to build a baseline.",
                        422,
                    )

                # Determine next version
                max_ver = (
                    db.scalar(
                        select(func.max(BaselineProfileRow.version)).where(
                            BaselineProfileRow.name == request.name
                        )
                    )
                    or 0
                )
                version = max_ver + 1

            # Compile fingerprints for each session
            fingerprints: List[SessionFingerprint] = []
            for s in session_rows:
                fp = fingerprint_service.get_or_create_for_session(s.id)
                fingerprints.append(fp)

            baseline_id = f"BL-{uuid.uuid4().hex[:12].upper()}"

            profile = build_baseline_profile(
                baseline_id=baseline_id,
                name=request.name,
                fingerprints=fingerprints,
                description=request.description,
                version=version,
                minimum_sessions=request.minimum_sessions,
                is_active=request.activate,
            )

            self._persist_profile(profile, fingerprints, request.activate)
            self._last_error = None
            return self._domain_to_schema(profile)

        except PacketServiceError:
            raise
        except Exception as exc:
            self._last_error = f"Baseline build failed: {type(exc).__name__} {exc}"
            logger.exception("Baseline build failure")
            raise PacketServiceError(
                "BASELINE_BUILD_FAILED", f"Baseline build failed: {exc}", 500
            ) from exc
        finally:
            self._building = False

    def activate(self, baseline_id: str) -> BaselineSummarySchema:
        """Mark exactly one baseline as active."""
        with SessionLocal() as db:
            row = db.get(BaselineProfileRow, baseline_id)
            if not row:
                raise PacketServiceError(
                    "BASELINE_NOT_FOUND",
                    f"No baseline profile found with identifier '{baseline_id}'.",
                    404,
                )
            # Deactivate all
            db.execute(update(BaselineProfileRow).values(is_active=False))
            row.is_active = True
            db.commit()
            db.refresh(row)
            return self._row_to_summary_schema(row)

    def get(self, baseline_id: str) -> BaselineProfileSchema:
        """Fetch full baseline profile with feature distributions and data quality."""
        with SessionLocal() as db:
            row = db.get(BaselineProfileRow, baseline_id)
            if not row:
                raise PacketServiceError(
                    "BASELINE_NOT_FOUND",
                    f"No baseline profile found with identifier '{baseline_id}'.",
                    404,
                )
            return self._row_to_profile_schema(row)

    def list_all(self) -> List[BaselineSummarySchema]:
        """List summary info for all stored baseline profiles."""
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(BaselineProfileRow).order_by(
                        BaselineProfileRow.version.desc(),
                        BaselineProfileRow.created_at.desc(),
                    )
                )
            )
            return [self._row_to_summary_schema(r) for r in rows]

    def features(self, baseline_id: str) -> List[BaselineFeatureProfileSchema]:
        """Return factual descriptive statistics for all features of a baseline."""
        profile = self.get(baseline_id)
        return profile.features

    def sessions(self, baseline_id: str) -> List[BaselineSessionItemSchema]:
        """List sessions included in a baseline profile."""
        with SessionLocal() as db:
            links = list(
                db.scalars(
                    select(BaselineSessionLinkRow).where(
                        BaselineSessionLinkRow.baseline_id == baseline_id
                    )
                )
            )
            if not links:
                return []
            session_ids = [link.session_id for link in links]
            fp_map = {link.session_id: link.fingerprint_id for link in links}

            session_rows = list(
                db.scalars(select(IPsecSession).where(IPsecSession.id.in_(session_ids)))
            )
            items = []
            for s in session_rows:
                items.append(
                    BaselineSessionItemSchema(
                        session_id=s.id,
                        fingerprint_id=fp_map.get(s.id, ""),
                        start_time=s.start_time,
                        end_time=s.end_time,
                        duration=s.duration_seconds,
                        packets=s.packet_count,
                        bytes=s.byte_count,
                        source=s.source,
                        destination=s.destination,
                        state=s.state,
                        ike_version=s.ike_version,
                    )
                )
            return items

    def compare_with_fingerprint(
        self, baseline_id: str, fingerprint_id: str
    ) -> BaselineComparisonSchema:
        """Provide descriptive comparison between observed fingerprint and baseline statistics."""
        baseline = self.get(baseline_id)
        fp = fingerprint_service.get(fingerprint_id)

        items: List[BaselineComparisonItemSchema] = []
        for feat_prof in baseline.features:
            observed_feat = fp.get_feature(feat_prof.name)
            observed_val = observed_feat.value if observed_feat else None
            avail = observed_feat.availability if observed_feat else "UNAVAILABLE"

            mean_val = (
                feat_prof.numeric_stats.mean if feat_prof.numeric_stats else None
            )
            median_val = (
                feat_prof.numeric_stats.median if feat_prof.numeric_stats else None
            )
            min_val = (
                feat_prof.numeric_stats.min if feat_prof.numeric_stats else None
            )
            max_val = (
                feat_prof.numeric_stats.max if feat_prof.numeric_stats else None
            )
            std_dev_val = (
                feat_prof.numeric_stats.std_dev if feat_prof.numeric_stats else None
            )
            mode_val = (
                feat_prof.categorical_stats.mode
                if feat_prof.categorical_stats
                else None
            )

            items.append(
                BaselineComparisonItemSchema(
                    feature_name=feat_prof.name,
                    display_name=feat_prof.display_name,
                    category=feat_prof.category,
                    data_type=feat_prof.data_type,
                    unit=feat_prof.unit,
                    observed_value=observed_val,
                    baseline_mean=mean_val,
                    baseline_median=median_val,
                    baseline_min=min_val,
                    baseline_max=max_val,
                    baseline_std_dev=std_dev_val,
                    baseline_mode=mode_val,
                    availability=avail,
                )
            )

        return BaselineComparisonSchema(
            fingerprint_id=fp.fingerprint_id,
            session_id=fp.session_id,
            baseline_id=baseline.id,
            baseline_name=baseline.name,
            baseline_version=baseline.version,
            features=items,
        )

    def _persist_profile(
        self,
        profile: BaselineProfile,
        fingerprints: Sequence[SessionFingerprint],
        activate: bool,
    ) -> None:
        with SessionLocal() as db:
            if activate:
                db.execute(update(BaselineProfileRow).values(is_active=False))

            cov_dict = {
                "sessions_included": profile.coverage.sessions_included if profile.coverage else [],
                "total_sessions": profile.coverage.total_sessions if profile.coverage else 0,
                "features_profiled": profile.coverage.features_profiled if profile.coverage else 0,
                "features_available": profile.coverage.features_available if profile.coverage else 0,
                "features_missing": profile.coverage.features_missing if profile.coverage else 0,
                "feature_completeness": profile.coverage.feature_completeness if profile.coverage else 0.0,
                "first_observation": profile.coverage.first_observation if profile.coverage else None,
                "last_observation": profile.coverage.last_observation if profile.coverage else None,
            }
            dq_dict = {
                "complete_sessions": profile.data_quality.complete_sessions if profile.data_quality else 0,
                "partial_sessions": profile.data_quality.partial_sessions if profile.data_quality else 0,
                "missing_data_features": profile.data_quality.missing_data_features if profile.data_quality else 0,
                "invalid_records": profile.data_quality.invalid_records if profile.data_quality else 0,
                "quality_rating": profile.data_quality.quality_rating if profile.data_quality else "INSUFFICIENT",
            }

            p_row = BaselineProfileRow(
                id=profile.baseline_id,
                name=profile.name,
                description=profile.description,
                version=profile.version,
                feature_version=profile.feature_version,
                status=profile.status,
                is_active=activate,
                session_count=profile.session_count,
                feature_count=profile.feature_count,
                minimum_sessions=profile.minimum_sessions,
                first_observation=profile.first_observation,
                last_observation=profile.last_observation,
                coverage_json=json.dumps(cov_dict),
                data_quality_json=json.dumps(dq_dict),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(p_row)

            # Persist features
            for feat in profile.features:
                cat_json = (
                    json.dumps(
                        {
                            "count": feat.categorical_stats.count,
                            "unique_count": feat.categorical_stats.unique_count,
                            "frequencies": feat.categorical_stats.frequencies,
                            "relative_frequencies": feat.categorical_stats.relative_frequencies,
                            "mode": feat.categorical_stats.mode,
                        }
                    )
                    if feat.categorical_stats
                    else None
                )
                bool_json = (
                    json.dumps(
                        {
                            "count": feat.boolean_stats.count,
                            "true_count": feat.boolean_stats.true_count,
                            "false_count": feat.boolean_stats.false_count,
                            "true_ratio": feat.boolean_stats.true_ratio,
                            "false_ratio": feat.boolean_stats.false_ratio,
                        }
                    )
                    if feat.boolean_stats
                    else None
                )

                f_row = BaselineFeatureRow(
                    baseline_id=profile.baseline_id,
                    name=feat.name,
                    display_name=feat.display_name,
                    category=feat.category,
                    data_type=feat.data_type,
                    unit=feat.unit,
                    count=feat.numeric_stats.count if feat.numeric_stats else (
                        feat.categorical_stats.count if feat.categorical_stats else (
                            feat.boolean_stats.count if feat.boolean_stats else 0
                        )
                    ),
                    mean=feat.numeric_stats.mean if feat.numeric_stats else None,
                    median=feat.numeric_stats.median if feat.numeric_stats else None,
                    min_val=feat.numeric_stats.min if feat.numeric_stats else None,
                    max_val=feat.numeric_stats.max if feat.numeric_stats else None,
                    std_dev=feat.numeric_stats.std_dev if feat.numeric_stats else None,
                    p25=feat.numeric_stats.p25 if feat.numeric_stats else None,
                    p50=feat.numeric_stats.p50 if feat.numeric_stats else None,
                    p75=feat.numeric_stats.p75 if feat.numeric_stats else None,
                    p95=feat.numeric_stats.p95 if feat.numeric_stats else None,
                    categorical_json=cat_json,
                    boolean_json=bool_json,
                    total_samples=feat.total_samples,
                    available_samples=feat.available_samples,
                    missing_samples=feat.missing_samples,
                    completeness_ratio=feat.completeness_ratio,
                )
                db.add(f_row)

            # Persist session links
            for fp in fingerprints:
                link_row = BaselineSessionLinkRow(
                    baseline_id=profile.baseline_id,
                    session_id=fp.session_id,
                    fingerprint_id=fp.fingerprint_id,
                    added_at=datetime.now(timezone.utc),
                )
                db.add(link_row)

            db.commit()

    @staticmethod
    def _row_to_summary_schema(row: BaselineProfileRow) -> BaselineSummarySchema:
        created_str = (
            row.created_at.isoformat()
            if isinstance(row.created_at, datetime)
            else str(row.created_at)
        )
        updated_str = (
            row.updated_at.isoformat()
            if isinstance(row.updated_at, datetime)
            else str(row.updated_at)
        )
        return BaselineSummarySchema(
            id=row.id,
            name=row.name,
            description=row.description,
            version=row.version,
            feature_version=row.feature_version,
            status=row.status,
            is_active=bool(row.is_active),
            session_count=row.session_count,
            feature_count=row.feature_count,
            minimum_sessions=row.minimum_sessions,
            first_observation=row.first_observation,
            last_observation=row.last_observation,
            created_at=created_str,
            updated_at=updated_str,
        )

    def _row_to_profile_schema(self, row: BaselineProfileRow) -> BaselineProfileSchema:
        cov_data = json.loads(row.coverage_json or "{}")
        coverage = BaselineCoverageSchema(
            sessions_included=cov_data.get("sessions_included", []),
            total_sessions=cov_data.get("total_sessions", 0),
            features_profiled=cov_data.get("features_profiled", 0),
            features_available=cov_data.get("features_available", 0),
            features_missing=cov_data.get("features_missing", 0),
            feature_completeness=cov_data.get("feature_completeness", 0.0),
            first_observation=cov_data.get("first_observation"),
            last_observation=cov_data.get("last_observation"),
        )
        dq_data = json.loads(row.data_quality_json or "{}")
        data_quality = BaselineDataQualitySchema(
            complete_sessions=dq_data.get("complete_sessions", 0),
            partial_sessions=dq_data.get("partial_sessions", 0),
            missing_data_features=dq_data.get("missing_data_features", 0),
            invalid_records=dq_data.get("invalid_records", 0),
            quality_rating=dq_data.get("quality_rating", "INSUFFICIENT"),
        )

        features: List[BaselineFeatureProfileSchema] = []
        for f in row.features:
            num_stats = None
            if f.mean is not None:
                num_stats = NumericStatisticsSchema(
                    count=f.count,
                    mean=f.mean,
                    median=f.median if f.median is not None else f.mean,
                    min=f.min_val if f.min_val is not None else f.mean,
                    max=f.max_val if f.max_val is not None else f.mean,
                    std_dev=f.std_dev if f.std_dev is not None else 0.0,
                    p25=f.p25 if f.p25 is not None else f.mean,
                    p50=f.p50 if f.p50 is not None else f.mean,
                    p75=f.p75 if f.p75 is not None else f.mean,
                    p95=f.p95 if f.p95 is not None else f.mean,
                )
            cat_stats = None
            if f.categorical_json:
                cd = json.loads(f.categorical_json)
                cat_stats = CategoricalStatisticsSchema(
                    count=cd.get("count", 0),
                    unique_count=cd.get("unique_count", 0),
                    frequencies=cd.get("frequencies", {}),
                    relative_frequencies=cd.get("relative_frequencies", {}),
                    mode=cd.get("mode"),
                )
            bool_stats = None
            if f.boolean_json:
                bd = json.loads(f.boolean_json)
                bool_stats = BooleanStatisticsSchema(
                    count=bd.get("count", 0),
                    true_count=bd.get("true_count", 0),
                    false_count=bd.get("false_count", 0),
                    true_ratio=bd.get("true_ratio", 0.0),
                    false_ratio=bd.get("false_ratio", 0.0),
                )

            features.append(
                BaselineFeatureProfileSchema(
                    name=f.name,
                    display_name=f.display_name,
                    category=f.category,
                    data_type=f.data_type,
                    unit=f.unit,
                    numeric_stats=num_stats,
                    categorical_stats=cat_stats,
                    boolean_stats=bool_stats,
                    total_samples=f.total_samples,
                    available_samples=f.available_samples,
                    missing_samples=f.missing_samples,
                    completeness_ratio=f.completeness_ratio,
                )
            )

        summary = self._row_to_summary_schema(row)
        return BaselineProfileSchema(
            **summary.model_dump(),
            coverage=coverage,
            data_quality=data_quality,
            features=features,
        )

    def _domain_to_schema(self, profile: BaselineProfile) -> BaselineProfileSchema:
        coverage = BaselineCoverageSchema(
            sessions_included=profile.coverage.sessions_included if profile.coverage else [],
            total_sessions=profile.coverage.total_sessions if profile.coverage else 0,
            features_profiled=profile.coverage.features_profiled if profile.coverage else 0,
            features_available=profile.coverage.features_available if profile.coverage else 0,
            features_missing=profile.coverage.features_missing if profile.coverage else 0,
            feature_completeness=profile.coverage.feature_completeness if profile.coverage else 0.0,
            first_observation=profile.coverage.first_observation if profile.coverage else None,
            last_observation=profile.coverage.last_observation if profile.coverage else None,
        )
        data_quality = BaselineDataQualitySchema(
            complete_sessions=profile.data_quality.complete_sessions if profile.data_quality else 0,
            partial_sessions=profile.data_quality.partial_sessions if profile.data_quality else 0,
            missing_data_features=profile.data_quality.missing_data_features if profile.data_quality else 0,
            invalid_records=profile.data_quality.invalid_records if profile.data_quality else 0,
            quality_rating=profile.data_quality.quality_rating if profile.data_quality else "INSUFFICIENT",
        )
        features: List[BaselineFeatureProfileSchema] = []
        for feat in profile.features:
            num_stats = None
            if feat.numeric_stats:
                num_stats = NumericStatisticsSchema(
                    count=feat.numeric_stats.count,
                    mean=feat.numeric_stats.mean,
                    median=feat.numeric_stats.median,
                    min=feat.numeric_stats.min,
                    max=feat.numeric_stats.max,
                    std_dev=feat.numeric_stats.std_dev,
                    p25=feat.numeric_stats.p25,
                    p50=feat.numeric_stats.p50,
                    p75=feat.numeric_stats.p75,
                    p95=feat.numeric_stats.p95,
                )
            cat_stats = None
            if feat.categorical_stats:
                cat_stats = CategoricalStatisticsSchema(
                    count=feat.categorical_stats.count,
                    unique_count=feat.categorical_stats.unique_count,
                    frequencies=feat.categorical_stats.frequencies,
                    relative_frequencies=feat.categorical_stats.relative_frequencies,
                    mode=feat.categorical_stats.mode,
                )
            bool_stats = None
            if feat.boolean_stats:
                bool_stats = BooleanStatisticsSchema(
                    count=feat.boolean_stats.count,
                    true_count=feat.boolean_stats.true_count,
                    false_count=feat.boolean_stats.false_count,
                    true_ratio=feat.boolean_stats.true_ratio,
                    false_ratio=feat.boolean_stats.false_ratio,
                )
            features.append(
                BaselineFeatureProfileSchema(
                    name=feat.name,
                    display_name=feat.display_name,
                    category=feat.category,
                    data_type=feat.data_type,
                    unit=feat.unit,
                    numeric_stats=num_stats,
                    categorical_stats=cat_stats,
                    boolean_stats=bool_stats,
                    total_samples=feat.total_samples,
                    available_samples=feat.available_samples,
                    missing_samples=feat.missing_samples,
                    completeness_ratio=feat.completeness_ratio,
                )
            )

        return BaselineProfileSchema(
            id=profile.baseline_id,
            name=profile.name,
            description=profile.description,
            version=profile.version,
            feature_version=profile.feature_version,
            status=profile.status,
            is_active=profile.is_active,
            session_count=profile.session_count,
            feature_count=profile.feature_count,
            minimum_sessions=profile.minimum_sessions,
            first_observation=profile.first_observation,
            last_observation=profile.last_observation,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
            coverage=coverage,
            data_quality=data_quality,
            features=features,
        )

    def clear(self) -> None:
        """Clear all stored baseline profiles, features, and session fingerprints."""
        with SessionLocal() as db:
            db.execute(delete(BaselineSessionLinkRow))
            db.execute(delete(BaselineFeatureRow))
            db.execute(delete(BaselineProfileRow))
            db.execute(delete(SessionFingerprintRow))
            db.commit()
        self._last_error = None


baseline_service = BaselineService()
