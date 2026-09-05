"""Baseline Profiling API endpoints (Layer 06).

Purely descriptive baseline reference models and statistical profiles.
No drift scores, no anomaly scores, no vulnerability labels.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter

from app.api.routes.packets import ERROR_RESPONSES
from app.schemas.baseline import (
    BaselineBuildRequestSchema,
    BaselineComparisonSchema,
    BaselineEngineStatusSchema,
    BaselineFeatureProfileSchema,
    BaselineProfileSchema,
    BaselineSessionItemSchema,
    BaselineSummarySchema,
)
from app.services.baseline_service import baseline_service

router = APIRouter(prefix="/baselines", tags=["baselines"])


@router.get("/status", response_model=BaselineEngineStatusSchema, summary="Baseline engine status and summary metrics")
def read_status() -> BaselineEngineStatusSchema:
    return baseline_service.status()


@router.get("", response_model=List[BaselineSummarySchema], summary="List all baseline profiles")
def list_baselines() -> List[BaselineSummarySchema]:
    return baseline_service.list_all()


@router.post("", response_model=BaselineProfileSchema, responses=ERROR_RESPONSES, summary="Construct a new baseline profile")
def create_baseline(request: BaselineBuildRequestSchema) -> BaselineProfileSchema:
    return baseline_service.create_or_build(request)


@router.delete("", response_model=BaselineEngineStatusSchema, summary="Clear stored baselines and fingerprints")
def clear_baselines() -> BaselineEngineStatusSchema:
    baseline_service.clear()
    return baseline_service.status()


@router.get("/{baseline_id}", response_model=BaselineProfileSchema, responses=ERROR_RESPONSES, summary="Get full baseline profile details")
def get_baseline(baseline_id: str) -> BaselineProfileSchema:
    return baseline_service.get(baseline_id)


@router.post("/{baseline_id}/activate", response_model=BaselineSummarySchema, responses=ERROR_RESPONSES, summary="Activate a baseline profile")
def activate_baseline(baseline_id: str) -> BaselineSummarySchema:
    return baseline_service.activate(baseline_id)


@router.get("/{baseline_id}/features", response_model=List[BaselineFeatureProfileSchema], responses=ERROR_RESPONSES, summary="Get descriptive statistics for baseline features")
def get_baseline_features(baseline_id: str) -> List[BaselineFeatureProfileSchema]:
    return baseline_service.features(baseline_id)


@router.get("/{baseline_id}/sessions", response_model=List[BaselineSessionItemSchema], responses=ERROR_RESPONSES, summary="Get sessions included in a baseline profile")
def get_baseline_sessions(baseline_id: str) -> List[BaselineSessionItemSchema]:
    return baseline_service.sessions(baseline_id)


@router.get("/{baseline_id}/compare/{fingerprint_id}", response_model=BaselineComparisonSchema, responses=ERROR_RESPONSES, summary="Descriptive side-by-side comparison of fingerprint vs baseline")
def compare_fingerprint_with_baseline(baseline_id: str, fingerprint_id: str) -> BaselineComparisonSchema:
    return baseline_service.compare_with_fingerprint(baseline_id, fingerprint_id)
