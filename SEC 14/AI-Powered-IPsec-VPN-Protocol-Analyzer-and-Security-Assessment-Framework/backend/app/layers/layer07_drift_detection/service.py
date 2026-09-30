"""Domain orchestration service for Layer 07 Drift Detection.

Executes deterministic feature-by-feature drift evaluation and aggregates
session-level deviation results.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.layers.layer07_drift_detection.config import DEFAULT_DRIFT_CONFIG, DriftThresholdConfig
from app.layers.layer07_drift_detection.evaluator import DriftEvaluator
from app.layers.layer07_drift_detection.models import (
    ComparisonMethod,
    DriftSeverity,
    FeatureDriftResult,
    SessionDriftResult,
)
from app.layers.layer07_drift_detection.validators import (
    validate_baseline_for_drift,
    validate_feature_version_compatibility,
    validate_session_vector_for_drift,
)


class DriftDetectionDomainService:
    """Orchestrates validation, feature comparison, and session drift synthesis."""

    def __init__(self, config: Optional[DriftThresholdConfig] = None) -> None:
        self.config = config or DEFAULT_DRIFT_CONFIG
        self.evaluator = DriftEvaluator(self.config)

    def analyze_session(
        self,
        session_id: str,
        feature_vector: Any,
        baseline: Any,
        baseline_features: List[Any],
        analysis_id: Optional[str] = None,
    ) -> SessionDriftResult:
        """Perform deterministic drift analysis comparing session features against baseline."""
        # 1. Precondition checks
        validate_baseline_for_drift(baseline, minimum_sessions=self.config.minimum_baseline_samples)
        validate_session_vector_for_drift(feature_vector)
        validate_feature_version_compatibility(
            session_version=getattr(feature_vector, "feature_version", "1.0"),
            baseline_version=getattr(baseline, "feature_version", "1.0"),
        )

        now_str = datetime.now(timezone.utc).isoformat()
        aid = analysis_id or f"DA-{uuid.uuid4().hex[:12].upper()}"

        # 2. Index observed session features by name
        vector_feats: Dict[str, Any] = {}
        for feat in getattr(feature_vector, "features", []):
            vector_feats[getattr(feat, "name", "")] = feat

        # 3. Index baseline feature statistical profiles by name
        base_feats: Dict[str, Any] = {}
        for bf in baseline_features:
            base_feats[getattr(bf, "name", "")] = bf

        feature_results: List[FeatureDriftResult] = []

        # 4. Compare all baseline features against observed session values
        for feat_name, bf in base_feats.items():
            obs_feat = vector_feats.get(feat_name)
            curr_val = getattr(obs_feat, "value", None) if obs_feat else None
            data_type = getattr(bf, "data_type", "NUMERIC")
            display_name = getattr(bf, "display_name", feat_name)
            category = getattr(bf, "category", "GENERAL")
            unit = getattr(bf, "unit", None)

            if obs_feat is None or curr_val is None:
                # Missing from current session vector
                res = FeatureDriftResult(
                    feature_name=feat_name,
                    display_name=display_name,
                    category=category,
                    data_type=data_type,
                    unit=unit,
                    current_value=None,
                    baseline_mean=getattr(bf, "mean", None),
                    baseline_std=getattr(bf, "std_dev", None),
                    baseline_median=getattr(bf, "median", None),
                    baseline_distribution=None,
                    deviation=None,
                    z_score=None,
                    comparison_method=ComparisonMethod.FEATURE_UNAVAILABLE,
                    drift_detected=False,
                    severity=DriftSeverity.NONE,
                    reason="Feature was not observed in current session vector.",
                )
                feature_results.append(res)
                continue

            if data_type == "NUMERIC":
                mean = getattr(bf, "mean", None)
                std = getattr(bf, "std_dev", None)
                med = getattr(bf, "median", None)
                p25 = getattr(bf, "p25", None)
                p75 = getattr(bf, "p75", None)
                p05 = getattr(bf, "p05", None)
                p95 = getattr(bf, "p95", None)
                res = self.evaluator.evaluate_numerical(
                    name=feat_name,
                    display_name=display_name,
                    category=category,
                    unit=unit,
                    current_value=float(curr_val) if isinstance(curr_val, (int, float)) else None,
                    mean=mean,
                    std_dev=std,
                    median=med,
                    p25=p25,
                    p75=p75,
                    p05=p05,
                    p95=p95,
                )
                feature_results.append(res)

            elif data_type == "CATEGORICAL":
                dist = getattr(bf, "categorical_distribution", None) or getattr(bf, "categorical_json", None)
                if isinstance(dist, str):
                    import json
                    try:
                        dist = json.loads(dist)
                    except Exception:
                        dist = {}
                res = self.evaluator.evaluate_categorical(
                    name=feat_name,
                    display_name=display_name,
                    category=category,
                    current_value=str(curr_val),
                    baseline_distribution=dist,
                )
                feature_results.append(res)

            elif data_type == "BOOLEAN":
                b_dist = getattr(bf, "boolean_distribution", None) or getattr(bf, "boolean_json", None)
                if isinstance(b_dist, str):
                    import json
                    try:
                        b_dist = json.loads(b_dist)
                    except Exception:
                        b_dist = {}
                res = self.evaluator.evaluate_boolean(
                    name=feat_name,
                    display_name=display_name,
                    category=category,
                    current_value=bool(curr_val),
                    baseline_distribution=b_dist,
                )
                feature_results.append(res)

        # 5. Check any features present in current vector but not in baseline
        for feat_name, obs_feat in vector_feats.items():
            if feat_name not in base_feats:
                curr_val = getattr(obs_feat, "value", None)
                res = FeatureDriftResult(
                    feature_name=feat_name,
                    display_name=getattr(obs_feat, "display_name", feat_name),
                    category=getattr(obs_feat, "category", "GENERAL"),
                    data_type="UNKNOWN",
                    unit=getattr(obs_feat, "unit", None),
                    current_value=curr_val,
                    baseline_mean=None,
                    baseline_std=None,
                    baseline_median=None,
                    baseline_distribution=None,
                    deviation=None,
                    z_score=None,
                    comparison_method=ComparisonMethod.BASELINE_UNAVAILABLE,
                    drift_detected=False,
                    severity=DriftSeverity.NONE,
                    reason="Feature was observed in session but has no reference baseline statistics.",
                )
                feature_results.append(res)

        # 6. Synthesize session-level drift result
        return self.evaluator.evaluate_session(
            analysis_id=aid,
            session_id=session_id,
            baseline_id=getattr(baseline, "id", "UNKNOWN"),
            baseline_version=getattr(baseline, "version", 1),
            feature_version=getattr(feature_vector, "feature_version", "1.0"),
            analyzed_at=now_str,
            feature_results=feature_results,
        )

    def get_layer_status(self) -> str:
        """Return operational readiness of the drift detection engine."""
        if self.evaluator is not None and self.config is not None:
            return "OPERATIONAL"
        return "READY"


_drift_service: Optional[DriftDetectionDomainService] = None


def get_drift_domain_service() -> DriftDetectionDomainService:
    """Singleton provider for DriftDetectionDomainService."""
    global _drift_service
    if _drift_service is None:
        _drift_service = DriftDetectionDomainService()
    return _drift_service

