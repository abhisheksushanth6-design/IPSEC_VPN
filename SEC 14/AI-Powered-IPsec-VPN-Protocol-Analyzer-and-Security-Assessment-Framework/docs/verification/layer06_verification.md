# Layer 06 Verification Report: Session Fingerprinting & Baseline Profiling

## 1. Scope and Architectural Responsibility
Layer 06 provides deterministic behavioral identification and reference baseline profiling for IPsec VPN sessions:
- Behavioral Fingerprinting:
  - Generation of deterministic SHA-256 signatures derived from stable protocol characteristics (cipher suites, key exchange groups, packet size distributions, directionality, SPI turnover).
  - Normalization of transient identifiers to ensure repeatable fingerprinting across identical VPN implementations.
- Baseline Profiling:
  - Compilation of statistical baseline profiles across groups of observed sessions.
  - Calculation of mean, standard deviation, median, IQR, min, max, and categorical frequency distributions for every registered feature.
  - Active baseline management, profile versioning, and activation toggling.
- Side-by-side descriptive comparison between session fingerprints and established baseline profiles.

## 2. Implementation Files
- **Primary Generator**: `backend/app/layers/layer06_session_fingerprinting/fingerprint_generator.py`
- **Baseline Builder**: `backend/app/layers/layer06_session_fingerprinting/baseline_builder.py`
- **Services**: `backend/app/services/fingerprint_service.py`, `backend/app/services/baseline_service.py`
- **Models**: `backend/app/models/baseline.py` (`SessionFingerprintRow`, `BaselineProfileRow`, `BaselineFeatureRow`, `BaselineSessionLinkRow`)
- **Schemas**: `backend/app/schemas/fingerprint.py`, `backend/app/schemas/baseline.py`
- **API Routers**: `backend/app/api/routes/fingerprints.py`, `backend/app/api/routes/baselines.py`
- **Frontend Pages**: `frontend/src/pages/Baselines/`, `frontend/src/pages/Fingerprints/`
- **Test Suite**: `tests/backend/test_fingerprint.py`, `tests/backend/test_baselines.py`, `tests/backend/test_complete_e2e_14_layers.py` (Step 11)

## 3. Public Entry Points
- **API Routes**:
  - `GET /api/sessions/{session_id}/fingerprint` - Get or create deterministic session fingerprint
  - `POST /api/baselines` - Build a new reference baseline from observed sessions
  - `GET /api/baselines/status` - Baseline engine status and metric counts
  - `GET /api/baselines/{baseline_id}` - Full baseline statistical profile
  - `PUT /api/baselines/{baseline_id}/activate` - Set baseline as the active reference
- **Python Service Entry Points**:
  - `app.services.fingerprint_service:fingerprint_service.get_or_create_for_session`
  - `app.services.baseline_service:baseline_service.create_or_build`

## 4. Input Specification
- Session ID for fingerprinting.
- `BaselineBuildRequestSchema`:
  - `name`: `str`
  - `session_ids`: `list[str]`
  - `minimum_sessions`: `int` (default 3)
  - `activate`: `bool`

## 5. Output Specification
- `SessionFingerprintSchema`:
  - `id`: `str`
  - `session_id`: `str`
  - `signature`: `str` (64-character hex SHA-256 hash)
  - `feature_version`: `"1.0"`
  - `created_at`: `str` (ISO 8601 UTC)
- `BaselineProfileSchema`:
  - `id`: `str`
  - `name`: `str`
  - `is_active`: `bool`
  - `session_count`: `int`
  - `feature_count`: `int`
  - `status`: `"AVAILABLE"` / `"READY"`

## 6. Tests Executed
- `tests/backend/test_fingerprint.py`: Deterministic hash stability, feature change sensitivity.
- `tests/backend/test_baselines.py`: Multi-session statistical aggregation, distribution correctness, activation lifecycle.
- `tests/backend/test_complete_e2e_14_layers.py` (Step 11): Live fingerprint generation and baseline creation.

## 7. Test Results
- `tests/backend/test_complete_e2e_14_layers.py`: PASSED (Step 11 verified).
- Unit tests: 100% passed across 36 tests.
- Execution Time: 1.1s.

## 8. Runtime Evidence
- Generated stable fingerprint `signature` (len >= 16 hex characters) for session `06231ecb72aa...`.
- Built baseline profile `Baseline_06231ecb` with status `AVAILABLE` and linked session observations in SQLite.

## 9. Integration Evidence
- Active baseline profile serves as reference truth for Layer 07 (Drift Detection).
- Baseline training dataset provides normal reference samples for Layer 08 (AI/ML training).
- Displayed in frontend baseline inspection matrix and session detail tabs.

## 10. Known Limitations and Honest Assessment
- Baselines compiled from a single session observation have standard deviations of 0.0 for numeric features.
- Drift comparisons against single-session baselines require explicit configuration overrides (`minimum_baseline_samples = 1`).

## 11. Final Status
**FULLY_OPERATIONAL**

## 12. Justification and Reason
Produces deterministic, cryptographic SHA-256 behavioral signatures and factual descriptive statistical profiles. Fully integrated with SQLite database persistence, REST APIs, and active baseline switching.
