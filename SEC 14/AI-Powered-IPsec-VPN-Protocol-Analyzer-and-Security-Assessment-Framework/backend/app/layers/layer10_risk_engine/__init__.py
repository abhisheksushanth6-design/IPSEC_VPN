"""Layer 10 — Risk Assessment & Decision Engine.

Status: OPERATIONAL.
Consolidates empirical security signals across Layers 04-09 into deterministic,
explainable risk scores, discrete risk bands, and actionable policy decisions.
"""

from __future__ import annotations

from app.layers.layer10_risk_engine.evaluator import EvaluationInput, RiskEvaluator
from app.layers.layer10_risk_engine.schemas import (
    DECISION_TO_ALIAS,
    ALIAS_TO_DECISION,
    PolicyDecision,
    PolicyDecisionAlias,
    ContributingSignal,
    RiskAssessmentResponse,
    RiskEvidenceItem,
    RiskExportResponse,
    RiskScoreBreakdown,
    RiskSummaryResponse,
)
from app.layers.layer10_risk_engine.service import (
    RiskEngineService,
    get_detailed_status,
    get_layer_status,
    get_risk_engine_service,
)

LAYER_NUMBER = 10
LAYER_NAME = "Risk Assessment & Decision Engine"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "DECISION_TO_ALIAS",
    "ALIAS_TO_DECISION",
    "PolicyDecision",
    "PolicyDecisionAlias",
    "EvaluationInput",
    "RiskEvaluator",
    "ContributingSignal",
    "RiskEvidenceItem",
    "RiskExportResponse",
    "RiskScoreBreakdown",
    "RiskAssessmentResponse",
    "RiskSummaryResponse",
    "RiskEngineService",
    "get_risk_engine_service",
    "get_layer_status",
    "get_detailed_status",
]
