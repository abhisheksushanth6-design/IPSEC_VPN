"""Tests for Layer 07 numerical feature drift evaluation.

Verifies:
- Values equal to baseline mean (no drift)
- Values within Gaussian baseline range (no drift)
- Low, moderate, and high drift classifications based on Z-score
- Large positive and negative deviations
- Zero standard deviation (invariant feature) handling without division by zero
- Missing data safety (missing mean, missing std, missing current value)
"""

from app.layers.layer07_drift_detection.config import DEFAULT_DRIFT_CONFIG
from app.layers.layer07_drift_detection.evaluator import DriftEvaluator
from app.layers.layer07_drift_detection.models import ComparisonMethod, DriftSeverity


def test_numerical_value_equal_to_mean():
    """When observed value equals baseline mean, deviation is zero and no drift is detected."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="bytes_total",
        display_name="Total Bytes",
        category="TRAFFIC",
        unit="bytes",
        current_value=1000.0,
        mean=1000.0,
        std_dev=100.0,
        median=1000.0,
        p25=950.0,
        p75=1050.0,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.deviation == 0.0
    assert res.z_score == 0.0
    assert res.comparison_method == ComparisonMethod.Z_SCORE


def test_numerical_value_inside_normal_range():
    """When |z| < 2.0 and value is inside normal range, no drift is flagged."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="packet_rate",
        display_name="Packet Rate",
        category="TRAFFIC",
        unit="pps",
        current_value=115.0,
        mean=100.0,
        std_dev=10.0,  # z = +1.5
        median=100.0,
        p25=92.0,
        p75=108.0,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.z_score == 1.5


def test_numerical_low_drift_positive_deviation():
    """Z-score between 2.0 and 3.0 produces LOW drift with positive direction reason."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="rekey_duration",
        display_name="Rekey Duration",
        category="TIMING",
        unit="s",
        current_value=24.5,
        mean=20.0,
        std_dev=2.0,  # z = +2.25
        median=20.0,
        p25=18.5,
        p75=21.5,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.LOW
    assert round(res.z_score, 2) == 2.25
    assert "exceeds" in res.reason


def test_numerical_moderate_drift_negative_deviation():
    """Z-score between -3.0 and -4.0 produces MODERATE drift with negative direction reason."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="throughput",
        display_name="Throughput",
        category="TRAFFIC",
        unit="Mbps",
        current_value=65.0,
        mean=100.0,
        std_dev=10.0,  # z = -3.5
        median=100.0,
        p25=92.0,
        p75=108.0,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.MODERATE
    assert round(res.z_score, 2) == -3.50
    assert "falls below" in res.reason


def test_numerical_high_drift_large_deviation():
    """Z-score >= 4.0 produces HIGH drift."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="failed_exchanges",
        display_name="Failed Exchanges",
        category="PROTOCOL",
        unit="count",
        current_value=45.0,
        mean=5.0,
        std_dev=8.0,  # z = +5.0
        median=4.0,
        p25=2.0,
        p75=7.0,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.HIGH
    assert res.z_score == 5.0


def test_numerical_zero_variance_exact_match():
    """When std dev is 0 and observed matches mean, no drift and comparison method is ZERO_VARIANCE."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="key_size",
        display_name="Key Size",
        category="IPSEC",
        unit="bits",
        current_value=256.0,
        mean=256.0,
        std_dev=0.0,
        median=256.0,
        p25=256.0,
        p75=256.0,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.deviation == 0.0
    assert res.z_score == 0.0
    assert res.comparison_method == ComparisonMethod.ZERO_VARIANCE


def test_numerical_zero_variance_deviation():
    """When std dev is 0 and observed deviates, drift is detected without division by zero."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="key_size",
        display_name="Key Size",
        category="IPSEC",
        unit="bits",
        current_value=128.0,
        mean=256.0,
        std_dev=0.0,
        median=256.0,
        p25=256.0,
        p75=256.0,
    )
    assert res.drift_detected is True
    assert res.severity in (DriftSeverity.MODERATE, DriftSeverity.HIGH)
    assert res.deviation == -128.0
    assert res.z_score is None  # no NaN or Infinity!
    assert res.comparison_method == ComparisonMethod.ZERO_VARIANCE


def test_numerical_missing_baseline_statistics():
    """When baseline mean is None, returns BASELINE_UNAVAILABLE and does NOT flag drift."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="jitter",
        display_name="Jitter",
        category="TIMING",
        unit="ms",
        current_value=12.5,
        mean=None,
        std_dev=None,
        median=None,
        p25=None,
        p75=None,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.comparison_method == ComparisonMethod.BASELINE_UNAVAILABLE


def test_numerical_missing_observed_value():
    """When current value is None, returns FEATURE_UNAVAILABLE and does NOT flag drift."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_numerical(
        name="jitter",
        display_name="Jitter",
        category="TIMING",
        unit="ms",
        current_value=None,
        mean=10.0,
        std_dev=2.0,
        median=10.0,
        p25=8.0,
        p75=12.0,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.comparison_method == ComparisonMethod.FEATURE_UNAVAILABLE
