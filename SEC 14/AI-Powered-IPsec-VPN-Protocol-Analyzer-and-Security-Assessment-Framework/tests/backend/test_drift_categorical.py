"""Tests for Layer 07 categorical and discrete feature drift evaluation."""

from app.layers.layer07_drift_detection.evaluator import DriftEvaluator
from app.layers.layer07_drift_detection.models import ComparisonMethod, DriftSeverity


def test_categorical_common_category_matches():
    """Observed category with high frequency in baseline is not flagged as drift."""
    evaluator = DriftEvaluator()
    dist = {
        "frequencies": {"AES-CBC-256": 45, "AES-GCM-256": 5},
        "total_samples": 50,
        "mode": "AES-CBC-256",
    }
    res = evaluator.evaluate_categorical(
        name="cipher_suite",
        display_name="Cipher Suite",
        category="PROTOCOL",
        current_value="AES-CBC-256",
        baseline_distribution=dist,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.comparison_method == ComparisonMethod.CATEGORICAL_FREQUENCY


def test_categorical_unseen_category_produces_drift():
    """Category never seen in baseline is flagged as behavioral drift (NEW_CATEGORY)."""
    evaluator = DriftEvaluator()
    dist = {
        "frequencies": {"AES-CBC-256": 50},
        "total_samples": 50,
        "mode": "AES-CBC-256",
    }
    res = evaluator.evaluate_categorical(
        name="cipher_suite",
        display_name="Cipher Suite",
        category="PROTOCOL",
        current_value="3DES-CBC",
        baseline_distribution=dist,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.MODERATE
    assert "not present in the reference baseline" in res.reason
    assert res.comparison_method == ComparisonMethod.CATEGORICAL_FREQUENCY


def test_categorical_rare_category_produces_low_drift():
    """Category present but with very low frequency (< 5%) produces LOW drift."""
    evaluator = DriftEvaluator()
    dist = {
        "frequencies": {"IKEv2": 98, "IKEv1": 2},
        "total_samples": 100,
        "mode": "IKEv2",
    }
    res = evaluator.evaluate_categorical(
        name="ike_version",
        display_name="IKE Version",
        category="IKE",
        current_value="IKEv1",
        baseline_distribution=dist,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.LOW
    assert "rare frequency" in res.reason


def test_categorical_missing_distribution():
    """When baseline categorical distribution is empty, returns BASELINE_UNAVAILABLE."""
    evaluator = DriftEvaluator()
    res = evaluator.evaluate_categorical(
        name="ike_version",
        display_name="IKE Version",
        category="IKE",
        current_value="IKEv2",
        baseline_distribution=None,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.comparison_method == ComparisonMethod.BASELINE_UNAVAILABLE
