"""Explainability and feature contribution engine for Layer 08.

Derives model-based evidence and feature deviations from real observations
against reference training distributions. Strictly avoids fabricated attack
narratives or speculative threat claims.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np
from app.layers.layer08_ai_ml.preprocessing import (
    FEATURE_LOOKUP,
    PreprocessingPipeline,
)
from app.layers.layer08_ai_ml.schemas import AnomalyFeatureContribution


class AnomalyExplanationService:
    """Computes factual, mathematical feature contributions for anomaly results."""

    @staticmethod
    def explain_session(
        observed_features: Dict[str, float],
        pipeline: PreprocessingPipeline,
        baseline_stats: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Tuple[List[AnomalyFeatureContribution], str, int]:
        """Generate feature-level contribution evidence and summary narrative.
        
        Returns:
            (contributions_list, summary_narrative, anomalous_feature_count)
        """
        contributions: List[AnomalyFeatureContribution] = []
        deviations: Dict[str, float] = {}
        raw_diffs: Dict[str, float] = {}

        total_abs_z = 0.0

        for fname in pipeline.feature_names:
            lookup = FEATURE_LOOKUP.get(fname, (fname, fname.replace("_", " ").title(), "GENERAL", "FLOAT"))
            _, display_name, category, data_type = lookup

            obs_val = observed_features.get(fname, 0.0)
            ref_mean = pipeline.feature_means.get(fname, 0.0)
            ref_std = pipeline.feature_stds.get(fname, 1.0)
            ref_median = pipeline.imputation_values.get(fname, ref_mean)

            diff = obs_val - ref_mean
            raw_diffs[fname] = diff

            z_score = diff / ref_std if ref_std > 1e-6 else 0.0
            deviations[fname] = z_score
            total_abs_z += abs(z_score)

        # Calculate relative percentage contributions
        anomalous_features_count = 0
        for fname in pipeline.feature_names:
            lookup = FEATURE_LOOKUP.get(fname, (fname, fname.replace("_", " ").title(), "GENERAL", "FLOAT"))
            _, display_name, category, data_type = lookup

            obs_val = observed_features.get(fname, 0.0)
            ref_mean = pipeline.feature_means.get(fname, 0.0)
            ref_std = pipeline.feature_stds.get(fname, 1.0)
            ref_median = pipeline.imputation_values.get(fname, ref_mean)

            z = deviations[fname]
            abs_z = abs(z)

            # Direction
            if z > 1.5:
                direction = "ABOVE_REFERENCE"
                anomalous_features_count += 1
            elif z < -1.5:
                direction = "BELOW_REFERENCE"
                anomalous_features_count += 1
            else:
                direction = "WITHIN_RANGE"

            # Relative contribution score (0 - 100%)
            if total_abs_z > 1e-6:
                contrib_score = round((abs_z / total_abs_z) * 100.0, 2)
            else:
                contrib_score = round(100.0 / len(pipeline.feature_names), 2)

            # Factual evidence description
            if direction == "WITHIN_RANGE":
                evidence = (
                    f"Observed value {obs_val:g} is within normal reference distribution "
                    f"(mean: {ref_mean:.2f}, std: {ref_std:.2f}, z: {z:+.2f})."
                )
            elif direction == "ABOVE_REFERENCE":
                evidence = (
                    f"Observed value {obs_val:g} is elevated ({z:+.2f} standard deviations "
                    f"above baseline mean {ref_mean:.2f})."
                )
            else:
                evidence = (
                    f"Observed value {obs_val:g} is depressed ({z:+.2f} standard deviations "
                    f"below baseline mean {ref_mean:.2f})."
                )

            contributions.append(
                AnomalyFeatureContribution(
                    feature_name=fname,
                    display_name=display_name,
                    category=category,
                    data_type=data_type,
                    observed_value=obs_val,
                    reference_mean=round(ref_mean, 3),
                    reference_std=round(ref_std, 3),
                    reference_median=round(ref_median, 3),
                    contribution_score=contrib_score,
                    deviation=round(z, 3),
                    direction=direction,
                    evidence_description=evidence,
                )
            )

        # Sort contributions descending by contribution_score
        contributions.sort(key=lambda c: c.contribution_score, reverse=True)

        # Build summary narrative
        top_deviations = [c for c in contributions if c.direction != "WITHIN_RANGE"]
        if top_deviations:
            top_names = ", ".join([f"{c.display_name} ({c.direction}, {c.deviation:+.2f}σ)" for c in top_deviations[:3]])
            summary = (
                f"Statistical deviations observed across {len(top_deviations)} of {len(pipeline.feature_names)} "
                f"monitored behavioral features. Most prominent deviations: {top_names}."
            )
        else:
            summary = (
                f"All {len(pipeline.feature_names)} monitored features fall within normal behavioral "
                f"thresholds (±1.5σ) of the reference baseline."
            )

        return contributions, summary, anomalous_features_count

    @staticmethod
    def explain_cicids_vector(
        feature_names: Sequence[str],
        raw_values: np.ndarray,
        scaled_values: np.ndarray,
        importances: Optional[np.ndarray] = None,
        attack_probability: float = 0.0,
    ) -> Tuple[List[AnomalyFeatureContribution], str, int]:
        """Rank CICFlowMeter features by |scaled value| × XGBoost importance."""
        names = list(feature_names)
        raw = np.asarray(raw_values, dtype=np.float64).reshape(-1)
        scaled = np.asarray(scaled_values, dtype=np.float64).reshape(-1)
        if importances is None:
            weights = np.ones(len(names), dtype=np.float64)
        else:
            weights = np.asarray(importances, dtype=np.float64).reshape(-1)
        if len(weights) != len(names):
            weights = np.ones(len(names), dtype=np.float64)

        magnitude = np.abs(scaled) * (weights + 1e-9)
        total = float(np.sum(magnitude))
        contributions: List[AnomalyFeatureContribution] = []
        anomalous_count = 0
        for idx, name in enumerate(names):
            z = float(scaled[idx]) if idx < len(scaled) else 0.0
            obs = float(raw[idx]) if idx < len(raw) else 0.0
            if z > 1.5:
                direction = "ABOVE_REFERENCE"
                anomalous_count += 1
            elif z < -1.5:
                direction = "BELOW_REFERENCE"
                anomalous_count += 1
            else:
                direction = "WITHIN_RANGE"
            share = (float(magnitude[idx]) / total * 100.0) if total > 0 else 0.0
            contributions.append(
                AnomalyFeatureContribution(
                    feature_name=name,
                    display_name=name,
                    category="FLOW",
                    data_type="FLOAT",
                    observed_value=obs,
                    reference_mean=0.0,
                    reference_std=1.0,
                    reference_median=0.0,
                    contribution_score=round(share, 2),
                    deviation=round(z, 3),
                    direction=direction,
                    evidence_description=(
                        f"CIC-IDS flow feature '{name}' observed {obs:g} "
                        f"(standardized {z:+.2f}; local XGBoost attack probability "
                        f"{attack_probability:.3f})."
                    ),
                )
            )
        contributions.sort(key=lambda c: c.contribution_score, reverse=True)
        top = [c for c in contributions if c.direction != "WITHIN_RANGE"][:3]
        if attack_probability >= 0.5:
            summary = (
                f"Local CIC-IDS2017 XGBoost classified this session as attack-like "
                f"(p={attack_probability:.3f}). Strongest flow deviations: "
                + (", ".join(f"{c.display_name} ({c.deviation:+.2f}σ)" for c in top) or "none")
                + "."
            )
        else:
            summary = (
                f"Local CIC-IDS2017 XGBoost classified this session as benign-like "
                f"(p={attack_probability:.3f}). "
                f"{len(top)} of {len(names)} flow features exceed ±1.5σ."
            )
        return contributions, summary, anomalous_count
