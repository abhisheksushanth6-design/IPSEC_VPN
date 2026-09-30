# Layer 10 Verification Report: Risk Assessment & Decision Engine

## 1. Scope and Architectural Responsibility
Layer 10 synthesizes telemetry, findings, and anomalies from all upstream analytical layers into a deterministic, multi-criteria risk assessment with advisory-only policy decisions:

- **Deterministic 0–100 Risk Scoring Formula**:
  - **Vulnerability Score (Layer 09)**: Max 50.0 points.
    - Base weights: Critical = 35.0, High = 20.0, Medium = 10.0, Low = 3.0, Info = 0.0.
    - Status triage: Only `OPEN`, `ACTIVE`, `CONFIRMED` findings add active risk points. `RESOLVED`, `FALSE_POSITIVE`, and `SUPPRESSED` findings contribute 0.0 points and no critical overrides while remaining in the audit evidence trail.
    - Confidence weighting: $W_{\text{eff}} = W_{\text{base}} \times \text{confidence}$ (0.0 to 1.0).
    - Recurrence damping: For repeat findings on the same object, subsequent occurrences contribute logarithmically damped points $\min(W_{\text{base}} \times 0.2 \times \log_2(\text{recurrence}), W_{\text{base}} \times 0.5)$.
    - Clamped strictly to $[0.0, 50.0]$.
  - **ML Anomaly Score (Layer 08)**: Max 30.0 points.
    - Continuous mapping from model anomaly probability and display score ($30.0 \times \text{probability}$, clamped to $[0.0, 30.0]$).
  - **Security Drift Score (Layer 07)**: Max 12.0 points.
    - Critical = 12.0, High = 8.0, Medium = 4.0, Low = 1.0, None / Unanalyzed = 0.0.
  - **Protocol & SA State Score (Layer 04)**: Max 8.0 points.
    - Active rekey failure or unauthenticated packet drop: +5.0 points.
    - Anti-replay window sequence violation: +3.0 points.
  - **Total Clamped Score**:
    $$\text{Total Score} = \min(100.0, \max(0.0, \text{Vuln} + \text{ML} + \text{Drift} + \text{State}))$$

- **Exact Risk Levels & Policy Decision Thresholds**:
  | Risk Score Range | Risk Level | Canonical Policy Decision | Standard Alias | Action Interpretation |
  |---|---|---|---|---|
  | **[0.0, 19.9]** | `LOW` | `ALLOW` | `ALLOW` | Normal operating bounds; standard monitoring |
  | **[20.0, 44.9]** | `MEDIUM` | `INSPECT` | `WARN` | Heightened telemetry inspection & diagnostic logging |
  | **[45.0, 69.9]** | `HIGH` | `RESTRICT` | `ISOLATE` | Rate-limiting, bandwidth throttling, re-authentication |
  | **[70.0, 100.0]** | `CRITICAL` | `TERMINATE` | `BLOCK` | Session revocation recommendation & emergency isolation |

- **Mandatory Policy Decision Overrides**:
  - Any active `CRITICAL` vulnerability finding ($\text{confidence} \ge 0.5$) forces decision to `TERMINATE` (`BLOCK`).
  - Active SA rekey failure or unauthenticated packet drop forces decision to `TERMINATE` (`BLOCK`).
  - Any active `HIGH` vulnerability finding forces decision to at least `INSPECT` (`WARN`).

- **Advisory-Only Governance Disclosure**:
  - Clear system disclosure: policy decisions are analytical recommendations. The framework does not execute destructive firewall rule mutation or tear down tunnels without explicit operator approval (`is_advisory = true`).

- **Explainability & Audit Trail**:
  - Contributing signal breakdown with exact numerical points, confidence, finding lifecycle status, recurrence counts, and factual reasons.
  - Verifiable evidence items linking to specific upstream row IDs.
  - Prioritized remediation recommendations.

- **Data Quality & Completeness**:
  - Dynamic verification of upstream layer availability tracking `COMPLETE` vs `PARTIAL` telemetry coverage.

## 2. Implementation Files
- **Scoring Evaluator**: `backend/app/layers/layer10_risk_engine/evaluator.py` (`RiskEvaluator`, `EvaluationInput`)
- **Service Layer**: `backend/app/layers/layer10_risk_engine/service.py` (`RiskEngineService`, `get_risk_engine_service`, `get_layer_status`, `get_detailed_status`)
- **Database Model**: `backend/app/models/risk.py` (`RiskAssessmentRow`)
- **Pydantic Schemas**: `backend/app/layers/layer10_risk_engine/schemas.py` (`PolicyDecision`, `PolicyDecisionAlias`, `RiskScoreBreakdown`, `ContributingSignal`, `RiskEvidenceItem`, `RiskAssessmentResponse`, `RiskSummaryResponse`, `RiskExportResponse`, `DECISION_TO_ALIAS`, `ALIAS_TO_DECISION`)
- **Package Exports**: `backend/app/layers/layer10_risk_engine/__init__.py`
- **API Router**: `backend/app/api/routes/risk.py`
- **Verification Script**: `backend/scripts/verify_layer10.py` (12 automated verification steps)
- **Frontend Components**:
  - `frontend/src/types/risk.ts` (Typed contracts, aliases, advisory flags, export schema)
  - `frontend/src/services/riskService.ts` (`getAssessmentById`, `exportAssessments`)
  - `frontend/src/pages/RiskAssessment/RiskAssessmentPage.tsx` (Advisory banner, Export JSON, session table, sub-score breakdown)
  - `frontend/tests/riskAssessment.test.tsx` (Vitest UI suite)

## 3. Public Entry Points
- **API Routes**:
  - `GET /api/risk/status` - Dynamic health diagnostics (`evaluator_loaded`, `dry_run_passed`, `database_connected`, `tables_verified`, `is_advisory`)
  - `GET /api/risk/summary` - Aggregate executive risk posture across all sessions
  - `GET /api/risk/assessments` - Historical risk assessment records with limit filtering
  - `GET /api/risk/assessments/{assessment_id}` - Direct lookup of specific assessment by ID (returns 404 if missing)
  - `GET /api/risk/sessions/{session_id}` - Retrieve or evaluate risk assessment for a specific session
  - `GET /api/risk/export` - Export structured compliance/SIEM audit trail JSON (`RiskExportResponse`)
  - `POST /api/risk/evaluate/{session_id}` - Force re-evaluate risk for an IPsec session
  - `POST /api/risk/evaluate-all` - Batch evaluate all discovered sessions
- **Python Service Entry Points**:
  - `app.layers.layer10_risk_engine.service:get_risk_engine_service().evaluate_session`
  - `app.layers.layer10_risk_engine.service:get_risk_engine_service().get_assessment_by_id`
  - `app.layers.layer10_risk_engine.service:get_risk_engine_service().export_assessments`
  - `app.layers.layer10_risk_engine.service:get_layer_status`
  - `app.layers.layer10_risk_engine.service:get_detailed_status`

## 4. Input Specification
- `EvaluationInput` container:
  - `session_id`: Unique IPsec session identifier
  - `session_info`: Factual session attributes (state, packet counts, protocols)
  - `sas`: Active/historical Security Association parameters
  - `lifecycle_events`: Protocol state transition logs (rekey errors, drops, anti-replay violations)
  - `has_features` / `feature_count`: Layer 05 extraction signals
  - `has_baseline` / `baseline_id`: Layer 06 baseline profiling signals
  - `drift_data`: Layer 07 behavioral drift results
  - `ml_data`: Layer 08 AI/ML anomaly classification scores
  - `vulnerabilities`: Layer 09 deterministic vulnerability findings (severity, confidence, status, occurrence count)

## 5. Output Specification
- `RiskAssessmentResponse`:
  - `id`: Unique assessment identifier (`RISK-{UUID}`)
  - `session_id`: Evaluated session ID
  - `risk_score`: Bounded float $[0.0, 100.0]$
  - `risk_level`: `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"`
  - `decision`: Canonical decision (`"ALLOW"` / `"INSPECT"` / `"RESTRICT"` / `"TERMINATE"`)
  - `decision_alias`: Standard alias (`"ALLOW"` / `"WARN"` / `"ISOLATE"` / `"BLOCK"`)
  - `is_advisory`: Boolean flag (`true`)
  - `data_quality`: `"COMPLETE"` / `"PARTIAL"`
  - `confidence_score`: Float $[0.0, 1.0]$ reflecting signal completeness
  - `breakdown`: `RiskScoreBreakdown` (`vulnerability_score`, `ml_score`, `drift_score`, `state_score`, `total_risk_score`)
  - `severity_summary`: Dictionary mapping active finding counts (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - `contributing_signals`: Factual signals with source layer, contribution points, reason, and evidence reference
  - `evidence`: Audit trail items with source layer, type, identifier, and summary
  - `recommended_actions`: Prioritized, actionable remediation recommendations
  - `available_signals` / `unavailable_signals`: Signal availability audit
  - `evaluated_at`: UTC ISO timestamp
- SQLite Records: Persistent storage in `risk_assessments` table.

## 6. Tests Executed
1. **Dedicated Unit & Integration Tests**: `tests/backend/test_layer10_risk.py`
   - Sub-score bounding and clamping
   - Risk level and policy decision mapping with aliases
   - Real database session evaluation roundtrip
   - API endpoints (`/summary`, `/status`, `/assessments`, `/sessions/{id}`, `/evaluate/{id}`, `/evaluate-all`)
   - Exact threshold boundaries: 0.0, 19.9, 20.0, 44.9, 45.0, 69.9, 70.0, 100.0, negative and >100 clamping
   - Finding status filtering (`RESOLVED`, `FALSE_POSITIVE`, `SUPPRESSED` contribute 0 points)
   - Confidence score weighting ($W_{\text{eff}} = W_{\text{base}} \times \text{confidence}$)
   - Recurrence damping and object-level deduplication
   - Mandatory decision overrides (Critical finding -> TERMINATE, Rekey failure -> TERMINATE, High finding -> INSPECT)
   - Empty and missing signal handling
   - Severity summary counting
   - Single assessment lookup by ID and missing ID handling (404)
   - Audit trail JSON export endpoint (`/api/risk/export`)
2. **Standalone Verification Script**: `backend/scripts/verify_layer10.py`
   - 12 comprehensive automated verification steps covering DB, math, overrides, export, and health.
3. **Full 14-Layer E2E Pipeline**: `tests/backend/test_complete_e2e_14_layers.py` (Step 15 verified)
4. **Full Backend Regression**: `pytest tests/backend/ -q` (396 tests passed)
5. **Frontend Test Suite**: `frontend/tests/riskAssessment.test.tsx` (5 tests passed)
6. **Frontend Production Build**: `tsc -b && vite build` (Clean build, 0 errors)

## 7. Test Results
- `backend/scripts/verify_layer10.py`: **12/12 Steps PASSED** (100%).
- `tests/backend/test_layer10_risk.py`: **13/13 Passed** in 4.87s.
- `tests/backend/test_complete_e2e_14_layers.py`: **PASSED** in 9.11s.
- Full Backend Test Suite: **396/396 Passed** in 32.15s (0 regressions).
- Frontend Vitest Suite: **5/5 Passed** in 0.63s.
- Frontend Production Bundle: **PASSED** in 23.74s with 0 errors.

## 8. Runtime Evidence
- Evaluated session `verify-l10-sess-001` with CRITICAL finding `RULE-CRYPTO-001`:
  - Computed Risk Score: 35.0
  - Sub-scores: Vulnerability = 35.0, ML = 0.0, Drift = 0.0, State = 0.0
  - Policy Decision: `TERMINATE` (Alias: `BLOCK`) via Critical Finding override
  - Advisory disclosure: `is_advisory = true`
  - Severity Summary: `{'CRITICAL': 1, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}`
  - Persisted in SQLite table `risk_assessments` (Record ID: `RISK-9079B61DD50A`)
  - Exported to JSON audit trail (2274 bytes, 1 assessment)

## 9. Integration Evidence
- Feeds Layer 11 (`risk_assessments` SQLite table).
- Feeds Layer 12 (`/api/risk/*` REST API endpoints).
- Feeds Layer 13 (Web Dashboard KPI cards, risk posture gauge, sessions assessment table, and inspector breakdown drawer).
- Feeds Layer 14 (Report Generation for PDF executive summaries).

## 10. Known Limitations and Honest Assessment
- When upstream signals (e.g., baseline or drift) are absent, the engine computes risk scores over available empirical signals and marks `data_quality = "PARTIAL"` without synthetic data injection.
- Policy decisions are advisory-only; automated firewall mutation or tunnel termination is intentionally not performed to prevent disruptive operational outages.

## 11. Final Status
**FULLY_OPERATIONAL**

## 12. Justification and Reason
Layer 10 combines multi-criteria analytical signals across Layers 04–09 using exact deterministic bounding, confidence weighting, recurrence damping, finding status triage, and mandatory policy decision overrides. All 13 backend unit tests, 12-step standalone verification script, 14-layer E2E pipeline, and 5 frontend UI tests pass with 100% success and 0 regressions.
