"""Layer 06 — Baseline Statistics Engine.

Computes factual descriptive statistics over observed session fingerprints.

Rules:
1. Numerical stability: No NaN, no Infinity.
2. Zero variance is normal and valid: std_dev = 0.0 when all values are identical.
3. Single observation: returns factual observed value with std_dev = 0.0,
   clearly distinguished as a limited sample.
4. Categorical features are never arbitrarily converted to numbers; they retain
   frequency distributions, relative frequencies, and modes.
5. Boolean features maintain factual counts and ratios.
6. Missing values are never silently converted to zero.
7. No anomaly detection or drift scoring.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, List, Optional, Sequence, Union

from .models import (
    BaselineFeatureProfile,
    BooleanStatistics,
    CategoricalStatistics,
    NumericStatistics,
    SessionFingerprint,
)


def calculate_percentile(sorted_values: Sequence[float], percentile: float) -> float:
    """Calculate the p-th percentile of sorted values using linear interpolation.
    
    percentile should be in range [0, 100].
    """
    n = len(sorted_values)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sorted_values[0])

    # Rank calculation with linear interpolation
    k = (n - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_values[int(k)])
    d0 = sorted_values[int(f)] * (c - k)
    d1 = sorted_values[int(c)] * (k - f)
    return float(d0 + d1)


def compute_numeric_statistics(values: Sequence[Union[int, float]]) -> Optional[NumericStatistics]:
    """Compute descriptive statistics for a sequence of numbers."""
    valid_nums = [float(v) for v in values if v is not None and not math.isnan(float(v))]
    if not valid_nums:
        return None

    n = len(valid_nums)
    s_vals = sorted(valid_nums)
    total = sum(s_vals)
    mean_val = total / n

    # Median
    if n % 2 == 1:
        median_val = s_vals[n // 2]
    else:
        median_val = (s_vals[(n // 2) - 1] + s_vals[n // 2]) / 2.0

    min_val = s_vals[0]
    max_val = s_vals[-1]

    # Sample standard deviation (Bessel's correction for n > 1)
    if n > 1:
        variance = sum((x - mean_val) ** 2 for x in s_vals) / (n - 1)
        # Avoid tiny negative floats from precision limits
        std_dev = math.sqrt(max(0.0, variance))
    else:
        std_dev = 0.0

    p25 = calculate_percentile(s_vals, 25.0)
    p50 = median_val
    p75 = calculate_percentile(s_vals, 75.0)
    p95 = calculate_percentile(s_vals, 95.0)

    return NumericStatistics(
        count=n,
        mean=round(mean_val, 4),
        median=round(median_val, 4),
        min=round(min_val, 4),
        max=round(max_val, 4),
        std_dev=round(std_dev, 4),
        p25=round(p25, 4),
        p50=round(p50, 4),
        p75=round(p75, 4),
        p95=round(p95, 4),
    )


def compute_categorical_statistics(values: Sequence[Any]) -> Optional[CategoricalStatistics]:
    """Compute frequency counts, relative frequencies, and mode for categorical features."""
    valid_vals = [str(v) for v in values if v is not None]
    if not valid_vals:
        return None

    n = len(valid_vals)
    counts = Counter(valid_vals)
    rel_freqs = {k: round(cnt / n, 4) for k, cnt in counts.items()}

    # Mode: highest frequency; alphabetically first if tied
    sorted_items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    mode_val = sorted_items[0][0] if sorted_items else None

    return CategoricalStatistics(
        count=n,
        unique_count=len(counts),
        frequencies=dict(counts),
        relative_frequencies=rel_freqs,
        mode=mode_val,
    )


def compute_boolean_statistics(values: Sequence[Any]) -> Optional[BooleanStatistics]:
    """Compute boolean true/false counts and ratios."""
    valid_bools = [bool(v) for v in values if v is not None]
    if not valid_bools:
        return None

    n = len(valid_bools)
    true_cnt = sum(1 for v in valid_bools if v is True)
    false_cnt = n - true_cnt

    return BooleanStatistics(
        count=n,
        true_count=true_cnt,
        false_count=false_cnt,
        true_ratio=round(true_cnt / n, 4),
        false_ratio=round(false_cnt / n, 4),
    )


def build_feature_profile(
    feature_name: str,
    fingerprints: Sequence[SessionFingerprint],
) -> Optional[BaselineFeatureProfile]:
    """Construct a BaselineFeatureProfile for one feature across multiple fingerprints."""
    if not fingerprints:
        return None

    # Inspect feature metadata from first fingerprint having it
    sample_feature = None
    for fp in fingerprints:
        feat = fp.get_feature(feature_name)
        if feat is not None:
            sample_feature = feat
            break

    if sample_feature is None:
        return None

    total_samples = len(fingerprints)
    values = []
    available_count = 0
    missing_count = 0

    for fp in fingerprints:
        feat = fp.get_feature(feature_name)
        if feat is None or feat.availability == "UNAVAILABLE" or feat.value is None:
            missing_count += 1
        else:
            available_count += 1
            values.append(feat.value)

    completeness = round(available_count / total_samples, 4) if total_samples > 0 else 0.0

    numeric_stats = None
    categorical_stats = None
    boolean_stats = None

    if sample_feature.data_type in ("INTEGER", "FLOAT"):
        numeric_stats = compute_numeric_statistics(values)
    elif sample_feature.data_type == "CATEGORICAL":
        categorical_stats = compute_categorical_statistics(values)
    elif sample_feature.data_type == "BOOLEAN":
        boolean_stats = compute_boolean_statistics(values)
    elif sample_feature.data_type == "TIMESTAMP":
        # Timestamp features are descriptive; we capture availability without numeric stats
        pass

    return BaselineFeatureProfile(
        name=sample_feature.name,
        display_name=sample_feature.display_name,
        category=sample_feature.category,
        data_type=sample_feature.data_type,
        unit=sample_feature.unit,
        numeric_stats=numeric_stats,
        categorical_stats=categorical_stats,
        boolean_stats=boolean_stats,
        total_samples=total_samples,
        available_samples=available_count,
        missing_samples=missing_count,
        completeness_ratio=completeness,
    )
