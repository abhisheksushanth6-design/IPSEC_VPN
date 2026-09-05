"""Centralized, versioned threshold configuration for Layer 07 Drift Detection.

Avoids hard-coded, unexplained threshold magic numbers. All comparison rules
reference this centralized configuration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict

from app.layers.layer07_drift_detection.models import DriftSeverity


@dataclass
class DriftThresholdConfig:
    """Versioned threshold parameters for deterministic drift detection."""

    config_version: str = "1.0"
    z_score_low: float = 2.0
    z_score_moderate: float = 3.0
    z_score_high: float = 4.0
    enable_percentile_check: bool = True
    iqr_multiplier: float = 1.5
    unseen_category_severity: DriftSeverity = DriftSeverity.MODERATE
    boolean_flip_severity: DriftSeverity = DriftSeverity.LOW
    category_rare_threshold: float = 0.05
    minimum_baseline_samples: int = 3

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to serializable dictionary."""
        data = asdict(self)
        data["unseen_category_severity"] = self.unseen_category_severity.value
        data["boolean_flip_severity"] = self.boolean_flip_severity.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DriftThresholdConfig:
        """Instantiate configuration from dictionary with enum parsing."""
        kwargs = dict(data)
        if "unseen_category_severity" in kwargs and isinstance(kwargs["unseen_category_severity"], str):
            kwargs["unseen_category_severity"] = DriftSeverity(kwargs["unseen_category_severity"])
        if "boolean_flip_severity" in kwargs and isinstance(kwargs["boolean_flip_severity"], str):
            kwargs["boolean_flip_severity"] = DriftSeverity(kwargs["boolean_flip_severity"])
        return cls(**kwargs)


DEFAULT_DRIFT_CONFIG = DriftThresholdConfig()
