"""Layer 10 — Risk Assessment & Decision Engine.

Status: OPERATIONAL.
Consolidates empirical security signals across Layers 04-09 into deterministic,
explainable risk scores, discrete risk bands, and actionable policy decisions.
"""

from __future__ import annotations

from app.layers.layer10_risk_engine.evaluator import EvaluationInput, RiskEvaluator
from app.layers.layer10_risk_engine.schemas import (
    ContributingSignal,
    RiskAssessmentResponse,
    RiskEvidenceItem,
    RiskScoreBreakdown,
    RiskSummaryResponse,
)
from app.layers.layer10_risk_engine.service import (
    RiskEngineService,
    get_risk_engine_service,
)

LAYER_NUMBER = 10
LAYER_NAME = "Risk Assessment & Decision Engine"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "EvaluationInput",
    "RiskEvaluator",
    "ContributingSignal",
    "RiskEvidenceItem",
    "RiskScoreBreakdown",
    "RiskAssessmentResponse",
    "RiskSummaryResponse",
    "RiskEngineService",
    "get_risk_engine_service",
]
