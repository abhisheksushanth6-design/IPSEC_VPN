"""FastAPI route handlers for Layer 06 AI-Powered Security Analysis."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Query, status

from app.layers.layer06_session_fingerprinting.ai_analysis_service import (
    get_ai_security_analysis_service,
)
from app.schemas.ai_security_analysis import (
    AISecurityAnalysisRequest,
    AISecurityAnalysisResponse,
    ExecutiveSummarySchema,
    RemediationStepSchema,
    TechnicalSummarySchema,
)

router = APIRouter(prefix="/ai-analysis", tags=["AI Security Analysis"])


@router.get(
    "",
    response_model=AISecurityAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Get AI-Powered Security Analysis for the active capture",
)
def get_ai_security_analysis(
    provider: Optional[str] = Query(None, description="Optional provider preference ('deterministic' or 'real_llm')"),
) -> AISecurityAnalysisResponse:
    """Retrieve comprehensive AI-powered security analysis for the currently loaded capture."""
    service = get_ai_security_analysis_service()
    analysis = service.analyze_current_capture(provider_preference=provider)
    return AISecurityAnalysisResponse.model_validate(analysis)


@router.get(
    "/executive-summary",
    response_model=ExecutiveSummarySchema,
    status_code=status.HTTP_200_OK,
    summary="Get Executive Summary briefing for leadership",
)
def get_executive_summary() -> ExecutiveSummarySchema:
    """Retrieve the high-level executive security briefing for CISO and leadership."""
    service = get_ai_security_analysis_service()
    analysis = service.analyze_current_capture()
    return ExecutiveSummarySchema.model_validate(analysis.executive_summary)


@router.get(
    "/remediation",
    response_model=List[RemediationStepSchema],
    status_code=status.HTTP_200_OK,
    summary="Get Phased Remediation Roadmap",
)
def get_remediation_roadmap(
    phase: Optional[str] = Query(None, description="Optional filter by phase (PHASE_1_IMMEDIATE, PHASE_2_HARDENING, PHASE_3_ARCHITECTURAL)"),
) -> List[RemediationStepSchema]:
    """Retrieve the phased actionable remediation roadmap with concrete configuration directives."""
    service = get_ai_security_analysis_service()
    analysis = service.analyze_current_capture()
    steps = analysis.remediation_steps
    if phase:
        steps = [s for s in steps if s.phase.upper() == phase.upper()]
    return [RemediationStepSchema.model_validate(s) for s in steps]


@router.get(
    "/technical-summary",
    response_model=TechnicalSummarySchema,
    status_code=status.HTTP_200_OK,
    summary="Get SOC Technical Analyst Dossier",
)
def get_technical_summary() -> TechnicalSummarySchema:
    """Retrieve in-depth technical analysis dossier including RFC citations and sequence integrity."""
    service = get_ai_security_analysis_service()
    analysis = service.analyze_current_capture()
    return TechnicalSummarySchema.model_validate(analysis.technical_summary)


@router.post(
    "/analyze",
    response_model=AISecurityAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger on-demand AI Security Analysis",
)
def trigger_ai_analysis(
    request: Optional[AISecurityAnalysisRequest] = None,
) -> AISecurityAnalysisResponse:
    """Trigger on-demand generation of AI security analysis with optional provider selection."""
    service = get_ai_security_analysis_service()
    pref = request.provider if request else None
    analysis = service.analyze_current_capture(provider_preference=pref)
    return AISecurityAnalysisResponse.model_validate(analysis)
