"""Tests for Layer 08 AI / ML Anomaly Detection Engine.

Covers:
- Preprocessing pipeline (imputation, scaling, serialization)
- Normalized anomaly score calculation & monotonicity
- Insufficient training data rejection
- Model training & genuine diagnostics (no fake metrics)
- Model artifact serialization & SHA-256 integrity checks
- Model versioning & activation
- Session anomaly inference & explainable feature evidence
- 3-signal comparison panel (Baseline, Drift, ML)
- Feature version mismatch validation
- Full FastAPI API endpoints (/api/ml/*)
"""

from __future__ import annotations

import json
import os
import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.db.base import SessionLocal
from app.db.init_db import initialize_database
from app.layers.layer08_ai_ml.explainability import AnomalyExplanationService
from app.layers.layer08_ai_ml.inference import compute_normalized_display_score
from app.layers.layer08_ai_ml.preprocessing import (
    FEATURE_NAMES,
    PreprocessingPipeline,
)
from app.layers.layer08_ai_ml.registry import ModelIntegrityError, model_registry
from app.layers.layer08_ai_ml.schemas import MLModelConfiguration, MLModelTrainRequest, AnomalyInferenceRequest
from app.layers.layer08_ai_ml.service import AIAnomalyService
from app.layers.layer08_ai_ml.validators import (
    IncompatibleFeatureVersionError,
    InsufficientTrainingDataError,
    MissingFeatureVectorError,
)
from app.main import create_app
from app.models.baseline import BaselineFeatureRow, BaselineProfileRow, BaselineSessionLinkRow
from app.models.drift import DriftAnalysisRow
from app.models.feature_vector import FeatureValueRow, FeatureVectorRow
from app.models.ipsec_session import IPsecSession
from app.models.ml_anomaly import (
    MLModelRow,
    TrainingDatasetRow,
    AnomalyAnalysisRow,
    AnomalyFeatureContributionRow,
)


@pytest.fixture(autouse=True)
def setup_database():
    """Ensure database tables exist and clean ML test data before/after each test."""
    initialize_database()
    db = SessionLocal()
    try:
        db.query(AnomalyFeatureContributionRow).delete()
        db.query(AnomalyAnalysisRow).delete()
        db.query(MLModelRow).delete()
        db.query(TrainingDatasetRow).delete()
        db.query(DriftAnalysisRow).delete()
        db.query(BaselineSessionLinkRow).delete()
        db.query(BaselineFeatureRow).delete()
        db.query(BaselineProfileRow).delete()
        db.query(FeatureValueRow).delete()
        db.query(FeatureVectorRow).delete()
        db.query(IPsecSession).delete()
        db.commit()
    finally:
        db.close()
    model_registry.clear_cache()
    yield
    model_registry.clear_cache()


def _populate_session_with_vector(
    db,
    session_id: str,
    packet_count: int = 100,
    byte_count: int = 50000,
    duration: float = 10.0,
    packet_rate: float = 10.0,
    byte_rate: float = 5000.0,
    avg_pkt_size: float = 500.0,
    feature_version: str = "1.0",
):
    """Helper to persist a session and its session-level feature vector."""
    # Session
    sess = IPsecSession(
        id=session_id,
        capture_id="cap_01",
        ordinal=1,
        source="192.168.1.1",
        destination="192.168.1.2",
        direction="BIDIRECTIONAL",
        state="ESTABLISHED",
        correlation="IKE_AND_ESP",
        start_time="2026-09-04T00:00:00Z",
        end_time="2026-09-04T00:00:10Z",
        duration_seconds=duration,
        packet_count=packet_count,
        byte_count=byte_count,
        detail_json="{}",
    )
    db.add(sess)

    # Feature Vector
    vec_id = f"vec_{session_id}"
    vec = FeatureVectorRow(
        id=vec_id,
        capture_id="cap_01",
        entity_type="SESSION",
        entity_id=session_id,
        entity_label=f"Session {session_id}",
        feature_version=feature_version,
        generated_at="2026-09-04T00:00:00Z",
        feature_count=len(FEATURE_NAMES),
        available_count=len(FEATURE_NAMES),
    )
    db.add(vec)

    # Feature Values
    feat_data = {
        "packet_count": (packet_count, "INTEGER"),
        "byte_count": (byte_count, "INTEGER"),
        "ike_packet_count": (4, "INTEGER"),
        "esp_packet_count": (packet_count - 4, "INTEGER"),
        "ah_packet_count": (0, "INTEGER"),
        "inbound_packet_count": (packet_count // 2, "INTEGER"),
        "outbound_packet_count": (packet_count // 2, "INTEGER"),
        "inbound_byte_count": (byte_count // 2, "INTEGER"),
        "outbound_byte_count": (byte_count // 2, "INTEGER"),
        "session_duration_seconds": (duration, "FLOAT"),
        "mean_interarrival_time": (0.1, "FLOAT"),
        "min_interarrival_time": (0.01, "FLOAT"),
        "max_interarrival_time": (0.2, "FLOAT"),
        "interarrival_variance": (0.005, "FLOAT"),
        "average_packet_size": (avg_pkt_size, "FLOAT"),
        "median_packet_size": (avg_pkt_size, "FLOAT"),
        "minimum_packet_size": (64, "INTEGER"),
        "maximum_packet_size": (1400, "INTEGER"),
        "packet_size_variance": (1000.0, "FLOAT"),
        "packet_size_standard_deviation": (31.62, "FLOAT"),
        "packet_rate": (packet_rate, "FLOAT"),
        "byte_rate": (byte_rate, "FLOAT"),
        "traffic_symmetry_ratio": (1.0, "FLOAT"),
        "nat_traversal_observed": (False, "BOOLEAN"),
        "rekey_count": (0, "INTEGER"),
        "ike_sa_count": (1, "INTEGER"),
        "child_sa_count": (1, "INTEGER"),
    }

    for idx, fname in enumerate(FEATURE_NAMES):
        val, dtype = feat_data.get(fname, (0, "INTEGER"))
        vrow = FeatureValueRow(
            vector_id=vec_id,
            ordinal=idx,
            name=fname,
            level="SESSION",
            data_type=dtype,
            value_integer=int(val) if dtype == "INTEGER" else None,
            value_float=float(val) if dtype == "FLOAT" else None,
            value_boolean=bool(val) if dtype == "BOOLEAN" else None,
            availability="AVAILABLE",
            quality="COMPLETE",
            source="Test generator",
        )
        db.add(vrow)

    db.commit()


def _create_sample_baseline(db, baseline_id: str, session_ids: list[str]) -> BaselineProfileRow:
    """Helper to persist a baseline profile linked to sessions."""
    bp = BaselineProfileRow(
        id=baseline_id,
        name=f"Baseline {baseline_id}",
        version=1,
        feature_version="1.0",
        status="ACTIVE",
        is_active=True,
        session_count=len(session_ids),
        feature_count=len(FEATURE_NAMES),
        minimum_sessions=2,
    )
    db.add(bp)

    for sid in session_ids:
        link = BaselineSessionLinkRow(
            baseline_id=baseline_id,
            session_id=sid,
            fingerprint_id=f"fp_{sid}",
        )
        db.add(link)

    # Add baseline feature statistics
    for fname in FEATURE_NAMES:
        bf = BaselineFeatureRow(
            baseline_id=baseline_id,
            name=fname,
            display_name=fname.replace("_", " ").title(),
            category="TRAFFIC",
            data_type="FLOAT",
            count=len(session_ids),
            mean=100.0,
            std_dev=10.0,
            median=100.0,
            total_samples=len(session_ids),
            available_samples=len(session_ids),
        )
        db.add(bf)

    db.commit()
    db.refresh(bp)
    return bp


# --------------------------------------------------------------------------- #
# Unit Tests: Preprocessing & Scoring Math
# --------------------------------------------------------------------------- #

def test_preprocessing_pipeline_fit_transform():
    """Verify deterministic preprocessing, median imputation, and standard scaling."""
    pipeline = PreprocessingPipeline(feature_names=["packet_count", "byte_count"])
    data = [
        {"packet_count": 100, "byte_count": 1000},
        {"packet_count": 200, "byte_count": None},  # missing byte_count
        {"packet_count": 300, "byte_count": 3000},
    ]

    pipeline.fit(data)
    assert pipeline.is_fitted
    assert pipeline.imputation_values["packet_count"] == 200.0
    assert pipeline.imputation_values["byte_count"] == 2000.0  # median of [1000, 3000]

    # Transform single row with missing value
    scaled, imputed = pipeline.transform_single({"packet_count": 200, "byte_count": None})
    assert imputed["byte_count"] == 2000.0
    assert scaled.shape == (1, 2)

    # Test serialization to dict and reconstruction
    d = pipeline.to_dict()
    reconstructed = PreprocessingPipeline.from_dict(d)
    assert reconstructed.is_fitted
    assert reconstructed.imputation_values == pipeline.imputation_values


def test_normalized_score_calculation():
    """Verify display score derivation, monotonicity, and mathematical bounds [0-100]."""
    # Raw score 0.0 is the exact decision threshold -> must equal 50.0
    assert compute_normalized_display_score(0.0) == 50.0

    # Normal inliers (positive raw score) -> display_score < 50.0
    score_normal = compute_normalized_display_score(0.1)
    assert score_normal < 50.0

    # Strong anomalies (negative raw score) -> display_score > 50.0
    score_anom = compute_normalized_display_score(-0.1)
    assert score_anom > 50.0

    # Monotonic check: s1 < s2 => score(s1) > score(s2)
    assert compute_normalized_display_score(-0.3) > compute_normalized_display_score(-0.1)
    assert compute_normalized_display_score(0.0) > compute_normalized_display_score(0.2)

    # Extreme bounds check
    assert compute_normalized_display_score(10.0) == 0.0
    assert compute_normalized_display_score(-10.0) == 100.0


# --------------------------------------------------------------------------- #
# Training & Validation Tests
# --------------------------------------------------------------------------- #

def test_model_training_insufficient_samples():
    """Verify that training rejects datasets with fewer than minimum_training_samples."""
    db = SessionLocal()
    try:
        # Create baseline with only 1 session
        _populate_session_with_vector(db, "SESS-01")
        _create_sample_baseline(db, "BASE-MIN", ["SESS-01"])

        service = AIAnomalyService(db)
        req = MLModelTrainRequest(
            baseline_id="BASE-MIN",
            minimum_training_samples=3,
        )

        with pytest.raises(InsufficientTrainingDataError) as exc_info:
            service.train_model(req)

        assert "INSUFFICIENT TRAINING DATA" in exc_info.value.detail
        assert "contains only 1" in exc_info.value.detail
    finally:
        db.close()


def test_model_training_and_diagnostics():
    """Verify model training, genuine diagnostics, joblib artifact persistence, and checksum."""
    db = SessionLocal()
    try:
        # Populate 3 sessions for training
        _populate_session_with_vector(db, "SESS-01", packet_count=100, byte_count=50000)
        _populate_session_with_vector(db, "SESS-02", packet_count=120, byte_count=55000)
        _populate_session_with_vector(db, "SESS-03", packet_count=110, byte_count=52000)
        _create_sample_baseline(db, "BASE-01", ["SESS-01", "SESS-02", "SESS-03"])

        service = AIAnomalyService(db)
        req = MLModelTrainRequest(
            baseline_id="BASE-01",
            name="Test Model v1.0",
            minimum_training_samples=3,
            configuration=MLModelConfiguration(contamination=0.05, n_estimators=50, random_state=42),
        )

        detail = service.train_model(req)

        assert detail.id.startswith("model_isoforest_")
        assert detail.model_type == "IsolationForest"
        assert detail.status == "READY"
        assert detail.is_active is True
        assert detail.training_samples == 3
        assert detail.feature_count == len(FEATURE_NAMES)
        assert detail.model_checksum is not None

        # Verify genuine diagnostics (NO fake classification accuracy!)
        assert detail.metrics is not None
        assert detail.metrics.sample_count == 3
        assert detail.metrics.contamination == 0.05
        assert isinstance(detail.metrics.score_mean, float)
        assert isinstance(detail.metrics.score_min, float)
        assert isinstance(detail.metrics.score_max, float)

        # Verify artifact on disk
        model_obj, meta = model_registry.load_model(
            model_id=detail.id,
            artifact_path_str="",
            expected_checksum=detail.model_checksum,
        )
        assert model_obj is not None
        assert meta["feature_version"] == "1.0"
    finally:
        db.close()


def test_model_integrity_verification():
    """Verify that tampering with a model artifact triggers ModelIntegrityError."""
    db = SessionLocal()
    try:
        _populate_session_with_vector(db, "SESS-01")
        _populate_session_with_vector(db, "SESS-02")
        _populate_session_with_vector(db, "SESS-03")
        _create_sample_baseline(db, "BASE-01", ["SESS-01", "SESS-02", "SESS-03"])

        service = AIAnomalyService(db)
        detail = service.train_model(MLModelTrainRequest(baseline_id="BASE-01", minimum_training_samples=3))

        # Tamper with expected checksum
        with pytest.raises(ModelIntegrityError) as exc_info:
            model_registry.load_model(
                model_id=detail.id,
                artifact_path_str="",
                expected_checksum="deadbeef" * 8,
            )
        assert "integrity check failed" in str(exc_info.value)
    finally:
        db.close()


def test_model_activation_and_versioning():
    """Verify multiple models receive distinct versions and activation switches cleanly."""
    db = SessionLocal()
    try:
        _populate_session_with_vector(db, "SESS-01")
        _populate_session_with_vector(db, "SESS-02")
        _populate_session_with_vector(db, "SESS-03")
        _create_sample_baseline(db, "BASE-01", ["SESS-01", "SESS-02", "SESS-03"])

        service = AIAnomalyService(db)
        m1 = service.train_model(MLModelTrainRequest(baseline_id="BASE-01", minimum_training_samples=3))
        m2 = service.train_model(MLModelTrainRequest(baseline_id="BASE-01", minimum_training_samples=3))

        assert m1.id != m2.id
        assert m1.model_version != m2.model_version

        # Activate m1
        service.activate_model(m1.id)
        st = service.get_status()
        assert st.active_model is not None
        assert st.active_model.id == m1.id

        # Activate m2
        service.activate_model(m2.id)
        st2 = service.get_status()
        assert st2.active_model is not None
        assert st2.active_model.id == m2.id
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Inference & Explainability Tests
# --------------------------------------------------------------------------- #

def test_inference_normal_and_anomalous():
    """Verify inference returns scores, classification, explainability, and 3-signal comparison."""
    db = SessionLocal()
    try:
        # 1. Train model on baseline with 8 typical sessions
        for i in range(1, 9):
            _populate_session_with_vector(
                db,
                f"TRAIN-{i:02d}",
                packet_count=90 + i * 4,
                byte_count=45000 + i * 2000,
                duration=9.0 + i * 0.3,
                packet_rate=10.0 + i * 0.2,
                byte_rate=5000.0 + i * 50.0,
                avg_pkt_size=480.0 + i * 5.0,
            )
        train_ids = [f"TRAIN-{i:02d}" for i in range(1, 9)]
        _create_sample_baseline(db, "BASE-01", train_ids)

        service = AIAnomalyService(db)
        service.train_model(MLModelTrainRequest(baseline_id="BASE-01", minimum_training_samples=3))

        # 2. Populate a normal session similar to baseline
        _populate_session_with_vector(
            db,
            "NORMAL-SESS",
            packet_count=105,
            byte_count=52000,
            duration=10.0,
            packet_rate=10.5,
            byte_rate=5200.0,
            avg_pkt_size=495.0,
        )
        res_normal = service.run_inference(AnomalyInferenceRequest(session_id="NORMAL-SESS"))

        assert res_normal.session_id == "NORMAL-SESS"
        assert res_normal.classification == "NORMAL"
        assert res_normal.display_score < 50.0
        assert res_normal.signal_comparison.ml_status == "NORMAL"

        # 3. Populate a heavily anomalous session (massive traffic burst)
        _populate_session_with_vector(
            db,
            "ANOM-SESS",
            packet_count=50000,
            byte_count=50000000,
            duration=0.5,
            packet_rate=100000.0,
            byte_rate=100000000.0,
        )
        res_anom = service.run_inference(AnomalyInferenceRequest(session_id="ANOM-SESS"))

        assert res_anom.session_id == "ANOM-SESS"
        assert res_anom.classification == "ANOMALOUS"
        assert res_anom.display_score >= 50.0
        assert res_anom.features_anomalous > 0
        assert "deviations observed" in res_anom.explanation_summary

        # Check feature contributions
        top_contrib = res_anom.feature_contributions[0]
        assert top_contrib.contribution_score > 0
        assert top_contrib.direction in ("ABOVE_REFERENCE", "BELOW_REFERENCE")
        assert len(top_contrib.evidence_description) > 0
    finally:
        db.close()


def test_feature_version_mismatch():
    """Verify that sessions with incompatible feature version schemas are rejected."""
    db = SessionLocal()
    try:
        _populate_session_with_vector(db, "TRAIN-01")
        _populate_session_with_vector(db, "TRAIN-02")
        _populate_session_with_vector(db, "TRAIN-03")
        _create_sample_baseline(db, "BASE-01", ["TRAIN-01", "TRAIN-02", "TRAIN-03"])

        service = AIAnomalyService(db)
        service.train_model(MLModelTrainRequest(baseline_id="BASE-01", minimum_training_samples=3))

        # Vector with version 2.0
        _populate_session_with_vector(db, "SESS-V2", feature_version="2.0")

        with pytest.raises(IncompatibleFeatureVersionError) as exc_info:
            service.run_inference(AnomalyInferenceRequest(session_id="SESS-V2"))
        assert "INCOMPATIBLE FEATURE VERSION" in exc_info.value.detail
    finally:
        db.close()


def test_missing_feature_vector():
    """Verify that a session without feature extraction raises MissingFeatureVectorError."""
    db = SessionLocal()
    try:
        _populate_session_with_vector(db, "TRAIN-01")
        _populate_session_with_vector(db, "TRAIN-02")
        _populate_session_with_vector(db, "TRAIN-03")
        _create_sample_baseline(db, "BASE-01", ["TRAIN-01", "TRAIN-02", "TRAIN-03"])

        service = AIAnomalyService(db)
        service.train_model(MLModelTrainRequest(baseline_id="BASE-01", minimum_training_samples=3))

        with pytest.raises(MissingFeatureVectorError) as exc_info:
            service.run_inference(AnomalyInferenceRequest(session_id="NON_EXISTENT_SESSION"))
        assert "INVALID FEATURE VECTOR" in exc_info.value.detail
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# FastAPI Endpoint Integration Tests
# --------------------------------------------------------------------------- #

def test_api_ml_endpoints():
    """Verify all /api/ml/* endpoints via TestClient."""
    app = create_app()
    client = TestClient(app)

    # 1. Initial status -> NOT INITIALIZED
    r = client.get("/api/ml/status")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] in ("NOT INITIALIZED", "NOT_INITIALIZED", "READY")
    assert data["total_models"] == 0

    # 2. Populate DB
    db = SessionLocal()
    try:
        _populate_session_with_vector(db, "S-01")
        _populate_session_with_vector(db, "S-02")
        _populate_session_with_vector(db, "S-03")
        _create_sample_baseline(db, "BASE-API", ["S-01", "S-02", "S-03"])
    finally:
        db.close()

    # 3. Train model via POST /api/ml/models/train
    train_payload = {
        "baseline_id": "BASE-API",
        "name": "API Test Model",
        "minimum_training_samples": 3,
        "configuration": {"contamination": 0.05, "n_estimators": 50, "random_state": 42},
    }
    r = client.post("/api/ml/models/train", json=train_payload)
    assert r.status_code == 201
    model_data = r.json()
    model_id = model_data["id"]
    assert model_data["status"] == "READY"

    # 4. List models via GET /api/ml/models
    r = client.get("/api/ml/models")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # 5. Get model detail via GET /api/ml/models/{id}
    r = client.get(f"/api/ml/models/{model_id}")
    assert r.status_code == 200
    assert r.json()["id"] == model_id

    # 6. Run inference via POST /api/ml/analyze
    r = client.post("/api/ml/analyze", json={"session_id": "S-01"})
    assert r.status_code == 200
    anom_res = r.json()
    analysis_id = anom_res["id"]
    assert anom_res["classification"] in ("NORMAL", "ANOMALOUS")
    assert "feature_contributions" in anom_res
    assert "signal_comparison" in anom_res

    # 7. List anomalies via GET /api/ml/anomalies
    r = client.get("/api/ml/anomalies")
    assert r.status_code == 200
    assert len(r.json()) >= 1

    # 8. Get specific anomaly via GET /api/ml/anomalies/{id}
    r = client.get(f"/api/ml/anomalies/{analysis_id}")
    assert r.status_code == 200
    assert r.json()["id"] == analysis_id

    # 9. Get latest session analysis
    r = client.get("/api/ml/anomalies/session/S-01/latest")
    assert r.status_code == 200
    assert r.json()["session_id"] == "S-01"

    # 10. List datasets
    r = client.get("/api/ml/datasets")
    assert r.status_code == 200
    assert len(r.json()) == 1
