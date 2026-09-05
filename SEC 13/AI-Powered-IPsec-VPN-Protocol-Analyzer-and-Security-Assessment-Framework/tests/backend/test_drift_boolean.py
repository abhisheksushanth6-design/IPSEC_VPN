"""Tests for Layer 07 boolean feature drift evaluation."""

from app.layers.layer07_drift_detection.evaluator import DriftEvaluator
from app.layers.layer07_drift_detection.models import ComparisonMethod, DriftSeverity


def test_boolean_matching_ratio_no_drift():
    """Boolean state matching baseline probability is not flagged as drift."""
    evaluator = DriftEvaluator()
    dist = {"true_ratio": 0.5, "false_ratio": 0.5, "total_samples": 40}
    res = evaluator.evaluate_boolean(
        name="nat_traversal_active",
        display_name="NAT Traversal Active",
        category="PROTOCOL",
        current_value=True,
        baseline_distribution=dist,
    )
    assert res.drift_detected is False
    assert res.severity == DriftSeverity.NONE
    assert res.comparison_method == ComparisonMethod.BOOLEAN_RATIO


def test_boolean_flip_from_never_observed():
    """Boolean TRUE when baseline was 0% TRUE produces behavioral drift."""
    evaluator = DriftEvaluator()
    dist = {"true_ratio": 0.0, "false_ratio": 1.0, "total_samples": 30}
    res = evaluator.evaluate_boolean(
        name="rekey_failed",
        display_name="Rekey Failed",
        category="TIMING",
        current_value=True,
        baseline_distribution=dist,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.LOW
    assert "was never observed in reference baseline" in res.reason


def test_boolean_flip_from_always_observed():
    """Boolean FALSE when baseline was 100% TRUE produces behavioral drift."""
    evaluator = DriftEvaluator()
    dist = {"true_ratio": 1.0, "false_ratio": 0.0, "total_samples": 30}
    res = evaluator.evaluate_boolean(
        name="encryption_enabled",
        display_name="Encryption Enabled",
        category="IPSEC",
        current_value=False,
        baseline_distribution=dist,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.LOW
    assert "was never observed in reference baseline" in res.reason
