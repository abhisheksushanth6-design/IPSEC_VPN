"""Deterministic drift evaluator for Layer 07.

Compares observed protocol features against baseline statistical distributions.
Contains zero machine learning, heuristic anomaly scores, or threat ratings.
All comparison rules produce mathematically reproducible deviations and explainable reasons.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from app.layers.layer07_drift_detection.config import DEFAULT_DRIFT_CONFIG, DriftThresholdConfig
from app.layers.layer07_drift_detection.models import (
    ComparisonMethod,
    DriftSeverity,
    DriftStatus,
    FeatureDriftResult,
    SessionDriftResult,
)


class DriftEvaluator:
    """Evaluates individual features and aggregate session drift against reference baselines."""

    def __init__(self, config: Optional[DriftThresholdConfig] = None) -> None:
        self.config = config or DEFAULT_DRIFT_CONFIG

    def evaluate_numerical(
        self,
        name: str,
        display_name: str,
        category: str,
        unit: Optional[str],
        current_value: Optional[float],
        mean: Optional[float],
        std_dev: Optional[float],
        median: Optional[float],
        p25: Optional[float],
        p75: Optional[float],
        p05: Optional[float] = None,
        p95: Optional[float] = None,
    ) -> FeatureDriftResult:
        """Evaluate numerical feature against baseline Gaussian parameters and percentiles."""
        if current_value is None:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="NUMERIC",
                unit=unit,
                current_value=None,
                baseline_mean=mean,
                baseline_std=std_dev,
                baseline_median=median,
                baseline_distribution=None,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.FEATURE_UNAVAILABLE,
                drift_detected=False,
                severity=DriftSeverity.NONE,
                reason="Feature observation unavailable in current session vector.",
            )

        if mean is None:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="NUMERIC",
                unit=unit,
                current_value=current_value,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=None,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.BASELINE_UNAVAILABLE,
                drift_detected=False,
                severity=DriftSeverity.NONE,
                reason="Baseline statistics unavailable for this feature.",
            )

        deviation = float(current_value - mean)

        # 1. Zero-Variance Feature Handling
        if std_dev is None or math.isclose(std_dev, 0.0, abs_tol=1e-9):
            if math.isclose(deviation, 0.0, abs_tol=1e-9):
                return FeatureDriftResult(
                    feature_name=name,
                    display_name=display_name,
                    category=category,
                    data_type="NUMERIC",
                    unit=unit,
                    current_value=current_value,
                    baseline_mean=mean,
                    baseline_std=0.0,
                    baseline_median=median,
                    baseline_distribution={"invariant_value": mean},
                    deviation=0.0,
                    z_score=0.0,
                    comparison_method=ComparisonMethod.ZERO_VARIANCE,
                    drift_detected=False,
                    severity=DriftSeverity.NONE,
                    reason=f"Observed value {current_value} exactly matches invariant baseline reference ({mean}).",
                )
            else:
                # Invariant deviation detected
                rel_diff = abs(deviation) / abs(mean) if not math.isclose(mean, 0.0, abs_tol=1e-9) else 1.0
                severity = (
                    DriftSeverity.HIGH
                    if rel_diff >= 1.0
                    else (DriftSeverity.MODERATE if rel_diff >= 0.5 else DriftSeverity.LOW)
                )
                unit_str = f" {unit}" if unit else ""
                return FeatureDriftResult(
                    feature_name=name,
                    display_name=display_name,
                    category=category,
                    data_type="NUMERIC",
                    unit=unit,
                    current_value=current_value,
                    baseline_mean=mean,
                    baseline_std=0.0,
                    baseline_median=median,
                    baseline_distribution={"invariant_value": mean},
                    deviation=deviation,
                    z_score=None,
                    comparison_method=ComparisonMethod.ZERO_VARIANCE,
                    drift_detected=True,
                    severity=severity,
                    reason=(
                        f"Observed value {current_value}{unit_str} deviates by {deviation:+.2f}{unit_str} "
                        f"from invariant baseline reference ({mean}{unit_str})."
                    ),
                )

        # 2. Gaussian Standard Deviation / Z-Score
        z = deviation / std_dev
        abs_z = abs(z)
        unit_str = f" {unit}" if unit else ""

        if abs_z >= self.config.z_score_high:
            severity = DriftSeverity.HIGH
            drift_detected = True
            direction = "exceeds" if z > 0 else "falls below"
            reason = (
                f"Observed value {current_value}{unit_str} {direction} baseline mean {mean:.2f}{unit_str} "
                f"by {abs_z:.2f} standard deviations (|z| >= {self.config.z_score_high:.1f})."
            )
        elif abs_z >= self.config.z_score_moderate:
            severity = DriftSeverity.MODERATE
            drift_detected = True
            direction = "exceeds" if z > 0 else "falls below"
            reason = (
                f"Observed value {current_value}{unit_str} {direction} baseline mean {mean:.2f}{unit_str} "
                f"by {abs_z:.2f} standard deviations (|z| >= {self.config.z_score_moderate:.1f})."
            )
        elif abs_z >= self.config.z_score_low:
            severity = DriftSeverity.LOW
            drift_detected = True
            direction = "exceeds" if z > 0 else "falls below"
            reason = (
                f"Observed value {current_value}{unit_str} {direction} baseline mean {mean:.2f}{unit_str} "
                f"by {abs_z:.2f} standard deviations (|z| >= {self.config.z_score_low:.1f})."
            )
        else:
            # Check percentile range if enabled and available
            if self.config.enable_percentile_check and p25 is not None and p75 is not None and p75 > p25:
                iqr = p75 - p25
                iqr_lower = p25 - (self.config.iqr_multiplier * iqr)
                iqr_upper = p75 + (self.config.iqr_multiplier * iqr)
                if current_value < iqr_lower or current_value > iqr_upper:
                    severity = DriftSeverity.LOW
                    drift_detected = True
                    reason = (
                        f"Observed value {current_value}{unit_str} lies outside the interquartile range "
                        f"[{iqr_lower:.2f}, {iqr_upper:.2f}]."
                    )
                else:
                    severity = DriftSeverity.NONE
                    drift_detected = False
                    reason = (
                        f"Observed value {current_value}{unit_str} is within baseline reference range "
                        f"(mean {mean:.2f}{unit_str}, |z| = {abs_z:.2f} < {self.config.z_score_low:.1f})."
                    )
            else:
                severity = DriftSeverity.NONE
                drift_detected = False
                reason = (
                    f"Observed value {current_value}{unit_str} is within expected baseline distribution "
                    f"(mean {mean:.2f}{unit_str}, |z| = {abs_z:.2f} < {self.config.z_score_low:.1f})."
                )

        return FeatureDriftResult(
            feature_name=name,
            display_name=display_name,
            category=category,
            data_type="NUMERIC",
            unit=unit,
            current_value=current_value,
            baseline_mean=mean,
            baseline_std=std_dev,
            baseline_median=median,
            baseline_distribution={
                "p25": p25,
                "median": median,
                "p75": p75,
                "p05": p05,
                "p95": p95,
            },
            deviation=deviation,
            z_score=z,
            comparison_method=ComparisonMethod.Z_SCORE,
            drift_detected=drift_detected,
            severity=severity,
            reason=reason,
        )

    def evaluate_categorical(
        self,
        name: str,
        display_name: str,
        category: str,
        current_value: Optional[str],
        baseline_distribution: Optional[Dict[str, Any]],
    ) -> FeatureDriftResult:
        """Evaluate categorical feature against observed baseline frequency distribution."""
        if current_value is None:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="CATEGORICAL",
                unit=None,
                current_value=None,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=baseline_distribution,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.FEATURE_UNAVAILABLE,
                drift_detected=False,
                severity=DriftSeverity.NONE,
                reason="Categorical feature value unavailable in current session vector.",
            )

        if not baseline_distribution:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="CATEGORICAL",
                unit=None,
                current_value=current_value,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=None,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.BASELINE_UNAVAILABLE,
                drift_detected=False,
                severity=DriftSeverity.NONE,
                reason="Baseline distribution unavailable for this categorical feature.",
            )

        frequencies = baseline_distribution.get("frequencies", {})
        total_samples = baseline_distribution.get("total_samples", 0)

        # Unseen category evaluation
        if current_value not in frequencies:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="CATEGORICAL",
                unit=None,
                current_value=current_value,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=baseline_distribution,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.CATEGORICAL_FREQUENCY,
                drift_detected=True,
                severity=self.config.unseen_category_severity,
                reason=(
                    f"Observed category '{current_value}' was not present in the reference baseline profile."
                ),
            )

        # Existing category frequency check
        count = frequencies[current_value]
        ratio = count / total_samples if total_samples > 0 else 0.0

        if ratio < self.config.category_rare_threshold:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="CATEGORICAL",
                unit=None,
                current_value=current_value,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=baseline_distribution,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.CATEGORICAL_FREQUENCY,
                drift_detected=True,
                severity=DriftSeverity.LOW,
                reason=(
                    f"Observed category '{current_value}' occurs with rare frequency ({ratio * 100:.1f}%) "
                    f"in the reference baseline profile."
                ),
            )

        return FeatureDriftResult(
            feature_name=name,
            display_name=display_name,
            category=category,
            data_type="CATEGORICAL",
            unit=None,
            current_value=current_value,
            baseline_mean=None,
            baseline_std=None,
            baseline_median=None,
            baseline_distribution=baseline_distribution,
            deviation=None,
            z_score=None,
            comparison_method=ComparisonMethod.CATEGORICAL_FREQUENCY,
            drift_detected=False,
            severity=DriftSeverity.NONE,
            reason=(
                f"Observed category '{current_value}' is consistent with common baseline distribution "
                f"({ratio * 100:.1f}% frequency)."
            ),
        )

    def evaluate_boolean(
        self,
        name: str,
        display_name: str,
        category: str,
        current_value: Optional[bool],
        baseline_distribution: Optional[Dict[str, Any]],
    ) -> FeatureDriftResult:
        """Evaluate boolean flag against baseline observed frequency ratio."""
        if current_value is None:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="BOOLEAN",
                unit=None,
                current_value=None,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=baseline_distribution,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.FEATURE_UNAVAILABLE,
                drift_detected=False,
                severity=DriftSeverity.NONE,
                reason="Boolean feature value unavailable in current session vector.",
            )

        if not baseline_distribution:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="BOOLEAN",
                unit=None,
                current_value=current_value,
                baseline_mean=None,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=None,
                deviation=None,
                z_score=None,
                comparison_method=ComparisonMethod.BASELINE_UNAVAILABLE,
                drift_detected=False,
                severity=DriftSeverity.NONE,
                reason="Baseline distribution unavailable for this boolean feature.",
            )

        true_ratio = baseline_distribution.get("true_ratio", 0.0)

        # Baseline 0% true, observed True
        if math.isclose(true_ratio, 0.0, abs_tol=1e-6) and current_value is True:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="BOOLEAN",
                unit=None,
                current_value=True,
                baseline_mean=true_ratio,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=baseline_distribution,
                deviation=1.0,
                z_score=None,
                comparison_method=ComparisonMethod.BOOLEAN_RATIO,
                drift_detected=True,
                severity=self.config.boolean_flip_severity,
                reason="Observed state TRUE was never observed in reference baseline profile (0% baseline frequency).",
            )

        # Baseline 100% true, observed False
        if math.isclose(true_ratio, 1.0, abs_tol=1e-6) and current_value is False:
            return FeatureDriftResult(
                feature_name=name,
                display_name=display_name,
                category=category,
                data_type="BOOLEAN",
                unit=None,
                current_value=False,
                baseline_mean=true_ratio,
                baseline_std=None,
                baseline_median=None,
                baseline_distribution=baseline_distribution,
                deviation=-1.0,
                z_score=None,
                comparison_method=ComparisonMethod.BOOLEAN_RATIO,
                drift_detected=True,
                severity=self.config.boolean_flip_severity,
                reason="Observed state FALSE was never observed in reference baseline profile (100% baseline frequency).",
            )

        return FeatureDriftResult(
            feature_name=name,
            display_name=display_name,
            category=category,
            data_type="BOOLEAN",
            unit=None,
            current_value=current_value,
            baseline_mean=true_ratio,
            baseline_std=None,
            baseline_median=None,
            baseline_distribution=baseline_distribution,
            deviation=0.0,
            z_score=None,
            comparison_method=ComparisonMethod.BOOLEAN_RATIO,
            drift_detected=False,
            severity=DriftSeverity.NONE,
            reason=(
                f"Observed boolean state {current_value} is consistent with baseline frequencies "
                f"({true_ratio * 100:.1f}% TRUE)."
            ),
        )

    def evaluate_session(
        self,
        analysis_id: str,
        session_id: str,
        baseline_id: str,
        baseline_version: int,
        feature_version: str,
        analyzed_at: str,
        feature_results: List[FeatureDriftResult],
    ) -> SessionDriftResult:
        """Aggregate feature-level evaluations into a holistic session drift evaluation."""
        features_analyzed = len(feature_results)
        drifting_features = [f for f in feature_results if f.drift_detected]
        features_drifting = len(drifting_features)

        # Overall Status
        if features_drifting > 0:
            status = DriftStatus.DRIFT_DETECTED
        else:
            status = DriftStatus.WITHIN_BASELINE

        # Overall Severity (Hierarchical deterministic derivation)
        has_high = any(f.severity == DriftSeverity.HIGH for f in drifting_features)
        has_mod = any(f.severity == DriftSeverity.MODERATE for f in drifting_features)
        has_low = any(f.severity == DriftSeverity.LOW for f in drifting_features)

        if has_high:
            severity = DriftSeverity.HIGH
        elif has_mod:
            severity = DriftSeverity.MODERATE
        elif has_low:
            severity = DriftSeverity.LOW
        else:
            severity = DriftSeverity.NONE

        return SessionDriftResult(
            analysis_id=analysis_id,
            session_id=session_id,
            baseline_id=baseline_id,
            baseline_version=baseline_version,
            feature_version=feature_version,
            configuration_version=self.config.config_version,
            analyzed_at=analyzed_at,
            status=status,
            severity=severity,
            features_analyzed=features_analyzed,
            features_drifting=features_drifting,
            feature_results=feature_results,
            thresholds_used=self.config.to_dict(),
        )
