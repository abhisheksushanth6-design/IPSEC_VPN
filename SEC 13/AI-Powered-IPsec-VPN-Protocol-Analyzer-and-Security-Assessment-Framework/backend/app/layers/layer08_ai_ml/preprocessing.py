"""Deterministic preprocessing pipeline for Layer 08 AI / ML Anomaly Detection.

Extracts numerical and boolean behavioral features from session feature vectors,
handles missing values explicitly via baseline/training distribution imputation,
and scales features with recorded pipeline parameters for reproducible inference.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

# Authoritative feature list curated for Isolation Forest behavioral anomaly detection.
# Only session-level features with direct numerical or boolean behavioral interpretations.
SELECTED_MODEL_FEATURES: List[Tuple[str, str, str, str]] = [
    # (feature_name, display_name, category, data_type)
    # TRAFFIC
    ("packet_count", "Total Packet Count", "TRAFFIC", "INTEGER"),
    ("byte_count", "Total Byte Count", "TRAFFIC", "INTEGER"),
    ("ike_packet_count", "IKE Packet Count", "TRAFFIC", "INTEGER"),
    ("esp_packet_count", "ESP Packet Count", "TRAFFIC", "INTEGER"),
    ("ah_packet_count", "AH Packet Count", "TRAFFIC", "INTEGER"),
    ("inbound_packet_count", "Inbound Packet Count", "TRAFFIC", "INTEGER"),
    ("outbound_packet_count", "Outbound Packet Count", "TRAFFIC", "INTEGER"),
    ("inbound_byte_count", "Inbound Byte Count", "TRAFFIC", "INTEGER"),
    ("outbound_byte_count", "Outbound Byte Count", "TRAFFIC", "INTEGER"),

    # TIMING
    ("session_duration_seconds", "Session Duration (s)", "TIMING", "FLOAT"),
    ("mean_interarrival_time", "Mean Interarrival Time", "TIMING", "FLOAT"),
    ("min_interarrival_time", "Min Interarrival Time", "TIMING", "FLOAT"),
    ("max_interarrival_time", "Max Interarrival Time", "TIMING", "FLOAT"),
    ("interarrival_variance", "Interarrival Variance", "TIMING", "FLOAT"),

    # STATISTICAL
    ("average_packet_size", "Average Packet Size", "STATISTICAL", "FLOAT"),
    ("median_packet_size", "Median Packet Size", "STATISTICAL", "FLOAT"),
    ("minimum_packet_size", "Minimum Packet Size", "STATISTICAL", "INTEGER"),
    ("maximum_packet_size", "Maximum Packet Size", "STATISTICAL", "INTEGER"),
    ("packet_size_variance", "Packet Size Variance", "STATISTICAL", "FLOAT"),
    ("packet_size_standard_deviation", "Packet Size Std Dev", "STATISTICAL", "FLOAT"),
    ("packet_rate", "Packet Rate (pkts/s)", "STATISTICAL", "FLOAT"),
    ("byte_rate", "Byte Rate (bytes/s)", "STATISTICAL", "FLOAT"),

    # DIRECTIONAL
    ("traffic_symmetry_ratio", "Traffic Symmetry Ratio", "DIRECTIONAL", "FLOAT"),

    # IPSEC & SA LIFECYCLE
    ("nat_traversal_observed", "NAT-T Observed", "IPSEC", "BOOLEAN"),
    ("rekey_count", "Rekey Event Count", "SA_LIFECYCLE", "INTEGER"),
    ("ike_sa_count", "IKE SA Count", "SA_LIFECYCLE", "INTEGER"),
    ("child_sa_count", "Child SA Count", "SA_LIFECYCLE", "INTEGER"),
]

FEATURE_NAMES: List[str] = [f[0] for f in SELECTED_MODEL_FEATURES]
FEATURE_LOOKUP: Dict[str, Tuple[str, str, str, str]] = {f[0]: f for f in SELECTED_MODEL_FEATURES}


class PreprocessingPipeline:
    """Deterministic feature extractor, missing-value imputer, and scaler."""

    def __init__(
        self,
        feature_names: Optional[List[str]] = None,
        imputation_values: Optional[Dict[str, float]] = None,
        feature_means: Optional[Dict[str, float]] = None,
        feature_stds: Optional[Dict[str, float]] = None,
        preprocessing_version: str = "1.0",
    ):
        self.feature_names = feature_names or list(FEATURE_NAMES)
        self.imputation_values = imputation_values or {}
        self.feature_means = feature_means or {}
        self.feature_stds = feature_stds or {}
        self.preprocessing_version = preprocessing_version
        self.is_fitted = bool(self.imputation_values and self.feature_means and self.feature_stds)

    def fit(self, raw_session_features: List[Dict[str, Any]]) -> "PreprocessingPipeline":
        """Compute imputation statistics (medians) and scaling parameters (mean, std)."""
        if not raw_session_features:
            raise ValueError("Cannot fit preprocessing pipeline on empty dataset.")

        self.imputation_values = {}
        self.feature_means = {}
        self.feature_stds = {}

        # Collect observations per feature
        for name in self.feature_names:
            valid_vals: List[float] = []
            for row in raw_session_features:
                val = row.get(name)
                if val is not None:
                    if isinstance(val, bool):
                        valid_vals.append(1.0 if val else 0.0)
                    elif isinstance(val, (int, float)) and not math.isnan(val):
                        valid_vals.append(float(val))

            if valid_vals:
                median_val = float(np.median(valid_vals))
                mean_val = float(np.mean(valid_vals))
                std_val = float(np.std(valid_vals))
                # Avoid zero variance division
                if std_val < 1e-6:
                    std_val = 1.0
            else:
                median_val = 0.0
                mean_val = 0.0
                std_val = 1.0

            self.imputation_values[name] = median_val
            self.feature_means[name] = mean_val
            self.feature_stds[name] = std_val

        self.is_fitted = True
        return self

    def transform_single(self, session_features: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
        """Transform a single session's feature dict into a scaled feature vector.
        
        Returns:
            (scaled_array, imputed_raw_values_dict)
        """
        if not self.is_fitted:
            raise RuntimeError("PreprocessingPipeline must be fitted before transform.")

        imputed_raw: Dict[str, float] = {}
        scaled_row: List[float] = []

        for name in self.feature_names:
            val = session_features.get(name)
            if val is None:
                numeric_val = self.imputation_values.get(name, 0.0)
            elif isinstance(val, bool):
                numeric_val = 1.0 if val else 0.0
            elif isinstance(val, (int, float)) and not math.isnan(val):
                numeric_val = float(val)
            else:
                numeric_val = self.imputation_values.get(name, 0.0)

            imputed_raw[name] = numeric_val
            mean = self.feature_means.get(name, 0.0)
            std = self.feature_stds.get(name, 1.0)
            scaled = (numeric_val - mean) / std
            scaled_row.append(scaled)

        return np.array(scaled_row, dtype=np.float64).reshape(1, -1), imputed_raw

    def transform_batch(self, session_features_list: List[Dict[str, Any]]) -> np.ndarray:
        """Transform a list of session feature dicts into a 2D numpy matrix."""
        if not self.is_fitted:
            raise RuntimeError("PreprocessingPipeline must be fitted before transform.")

        matrix: List[List[float]] = []
        for row in session_features_list:
            scaled_vector, _ = self.transform_single(row)
            matrix.append(scaled_vector[0].tolist())

        return np.array(matrix, dtype=np.float64)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize pipeline parameters for model metadata storage."""
        return {
            "preprocessing_version": self.preprocessing_version,
            "feature_names": self.feature_names,
            "imputation_values": self.imputation_values,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PreprocessingPipeline":
        """Reconstruct a fitted pipeline from serialized parameters."""
        return cls(
            feature_names=data.get("feature_names", list(FEATURE_NAMES)),
            imputation_values=data.get("imputation_values", {}),
            feature_means=data.get("feature_means", {}),
            feature_stds=data.get("feature_stds", {}),
            preprocessing_version=data.get("preprocessing_version", "1.0"),
        )
