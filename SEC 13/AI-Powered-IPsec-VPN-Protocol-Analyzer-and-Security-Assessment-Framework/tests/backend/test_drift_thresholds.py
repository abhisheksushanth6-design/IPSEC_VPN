"""Tests for Layer 07 threshold configuration and deterministic reproducibility."""

from app.layers.layer07_drift_detection.config import DriftThresholdConfig
from app.layers.layer07_drift_detection.evaluator import DriftEvaluator
from app.layers.layer07_drift_detection.models import DriftSeverity, DriftStatus


def test_threshold_config_override():
    """Evaluator adheres to customized Z-score threshold cutoffs."""
    # Stricter configuration: low at 1.5 sigma, mod at 2.5 sigma, high at 3.5 sigma
    custom_cfg = DriftThresholdConfig(
        config_version="custom-1.1",
        z_score_low=1.5,
        z_score_moderate=2.5,
        z_score_high=3.5,
    )
    evaluator = DriftEvaluator(custom_cfg)

    # z = 1.8 would be NONE under default (2.0), but is LOW under custom (1.5)
    res = evaluator.evaluate_numerical(
        name="bytes",
        display_name="Bytes",
        category="TRAFFIC",
        unit="bytes",
        current_value=118.0,
        mean=100.0,
        std_dev=10.0,
        median=100.0,
        p25=95.0,
        p75=105.0,
    )
    assert res.drift_detected is True
    assert res.severity == DriftSeverity.LOW


def test_drift_determinism():
    """Given identical inputs and configuration, the drift result is 100% identical."""
    evaluator = DriftEvaluator()

    args = dict(
        name="packet_rate",
        display_name="Packet Rate",
        category="TRAFFIC",
        unit="pps",
        current_value=135.0,
        mean=100.0,
        std_dev=10.0,
        median=100.0,
        p25=92.0,
        p75=108.0,
    )

    res1 = evaluator.evaluate_numerical(**args)
    res2 = evaluator.evaluate_numerical(**args)

    assert res1.drift_detected == res2.drift_detected
    assert res1.severity == res2.severity
    assert res1.deviation == res2.deviation
    assert res1.z_score == res2.z_score
    assert res1.reason == res2.reason


def test_session_overall_severity_aggregation():
    """Session overall severity is deterministically derived from feature results."""
    evaluator = DriftEvaluator()

    f1 = evaluator.evaluate_numerical("f1", "F1", "TRAFFIC", None, 100.0, 100.0, 10.0, 100.0, 95.0, 105.0)  # NONE
    f2 = evaluator.evaluate_numerical("f2", "F2", "TRAFFIC", None, 125.0, 100.0, 10.0, 100.0, 95.0, 105.0)  # LOW
    f3 = evaluator.evaluate_numerical("f3", "F3", "TRAFFIC", None, 135.0, 100.0, 10.0, 100.0, 95.0, 105.0)  # MODERATE

    session_res = evaluator.evaluate_session(
        analysis_id="DA-TEST",
        session_id="SESS-1",
        baseline_id="BASE-1",
        baseline_version=1,
        feature_version="1.0",
        analyzed_at="2026-09-03T12:00:00Z",
        feature_results=[f1, f2, f3],
    )

    assert session_res.status == DriftStatus.DRIFT_DETECTED
    assert session_res.severity == DriftSeverity.MODERATE
    assert session_res.features_analyzed == 3
    assert session_res.features_drifting == 2
