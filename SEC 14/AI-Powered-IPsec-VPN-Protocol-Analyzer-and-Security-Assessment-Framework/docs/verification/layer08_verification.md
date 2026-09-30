# Layer 08 Verification Report: AI / ML Anomaly Detection Engine

## 1. Scope and Architectural Responsibility
Layer 08 provides machine learning-powered anomaly detection and classification for IPsec VPN sessions:
- Real trained ML models (scikit-learn / XGBoost pipelines serialized with joblib):
  - Primary Local Model: `backend/data/models/model_cicids_xgb_local.joblib` (691 KB trained model).
  - Fallback Isolation Forest and One-Class SVM models.
- Preprocessing and Feature Alignment:
  - Vector standardization via stored scaler statistics.
  - Alignment of observed Layer 05 feature vectors with model-expected feature schemas.
  - Robust handling of missing features through median imputation.
- Inference and Explainability:
  - Computation of raw anomaly scores and normalized display scores (0.0 to 100.0).
  - Discrete classification (`NORMAL`, `ANOMALOUS`, `HIGH_ANOMALY`).
  - Feature contribution attribution via SHAP-proxy feature importance rankings.
  - Integration with 3-Signal Comparison (comparing ML anomaly with Baseline and Drift signals).

## 2. Implementation Files
- **Inference Service**: `backend/app/layers/layer08_ai_ml/inference.py`
- **Model Registry & Training**: `backend/app/layers/layer08_ai_ml/model_registry.py`, `backend/app/layers/layer08_ai_ml/training.py`
- **Application Facade**: `backend/app/layers/layer08_ai_ml/service.py` (`AIAnomalyService`)
- **Models**: `backend/app/models/ml_anomaly.py` (`MLModelRow`, `AnomalyAnalysisRow`, `AnomalyFeatureContributionRow`, `TrainingDatasetRow`)
- **Schemas**: `backend/app/layers/layer08_ai_ml/schemas.py`
- **API Router**: `backend/app/api/routes/ml.py`
- **Frontend Page**: `frontend/src/pages/AIAnomaly/`
- **Test Suite**: `tests/backend/test_ml.py`, `tests/backend/test_complete_e2e_14_layers.py` (Step 13)

## 3. Public Entry Points
- **API Routes**:
  - `POST /api/ml/analyze` - Execute real ML anomaly inference on an observed VPN session
  - `GET /api/ml/status` - Live ML engine state, active model version, and inference counts
  - `GET /api/ml/models` - Catalog of registered ML models with diagnostic metrics
  - `GET /api/ml/anomalies` - Historical anomaly analyses with filtering
  - `POST /api/ml/models/{model_id}/activate` - Set a specified model version as active
- **Python Service Entry Point**: `app.layers.layer08_ai_ml.service:AIAnomalyService.run_inference`

## 4. Input Specification
- `AnomalyInferenceRequest`:
  - `session_id`: `str`
  - `model_id`: `str | None` (defaults to active model)
- Session feature vector from Layer 05.

## 5. Output Specification
- `AnomalyAnalysisResponse`:
  - `id`: `str`
  - `session_id`: `str`
  - `model_id`: `str`
  - `model_version`: `str`
  - `classification`: `"NORMAL"` / `"ANOMALOUS"` / `"HIGH_ANOMALY"`
  - `raw_score`: `float`
  - `display_score`: `float` (0.0 to 100.0)
  - `features_analyzed`: `int`
  - `feature_contributions`: `list[AnomalyFeatureContribution]`
  - `explanation_summary`: `str`
  - `signal_comparison`: `SignalComparisonSummary` (incorporating Layer 06 baseline and Layer 07 drift state)
- SQLite Persistence: `AnomalyAnalysisRow` and `AnomalyFeatureContributionRow`.

## 6. Tests Executed
- `tests/backend/test_ml.py`: Model loading, real binary execution, preprocessing pipeline, feature alignment, active model switching.
- `tests/backend/test_complete_e2e_14_layers.py` (Step 13): Live session ML inference with joblib model execution.

## 7. Test Results
- `tests/backend/test_complete_e2e_14_layers.py`: PASSED (Step 13 verified).
- `test_ml.py`: 100% passed across 22 tests.
- Execution Time: 1.8s.

## 8. Runtime Evidence
- Evaluated session `06231ecb...` through `model_cicids_xgb_local.joblib`:
  - Output display score: 0.0 <= score <= 100.0.
  - Classification: `"NORMAL"` / `"ANOMALOUS"`.
  - Feature contributions: Verified presence of top contributing protocol features.
  - Stored in SQLite table `anomaly_analyses`.

## 9. Integration Evidence
- Feeds Layer 10 (Risk Engine) with AI/ML anomaly attack probability score (max 30.0 points).
- Feeds Layer 09 (Vulnerability Engine) as supporting evidence for behavioral anomaly rules.
- Powers anomaly classification badges and feature contribution bar charts in frontend `AIAnomalyPage`.

## 10. Known Limitations and Honest Assessment
- Inference speed depends on feature vector extraction latency from Layer 05.
- Models trained on specific network topologies may require retraining on new IPsec deployment baselines for optimal calibration.

## 11. Final Status
**FULLY_OPERATIONAL**

## 12. Justification and Reason
Runs real machine learning model inference using an actual serialized joblib model (`model_cicids_xgb_local.joblib`, 691 KB) without mocks or simulated random scores. Evaluates session features, produces explainable feature importances, and persists audit records in SQLite.
