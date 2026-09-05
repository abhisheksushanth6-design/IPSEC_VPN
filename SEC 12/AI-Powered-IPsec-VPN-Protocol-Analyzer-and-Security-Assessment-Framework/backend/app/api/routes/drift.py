"""FastAPI routes for Layer 07 — Security Drift Detection.

Provides deterministic endpoints for drift evaluation, historical analysis retrieval,
threshold inspection, and engine status.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.layers.layer07_drift_detection.validators import DriftPreconditionError, FeatureVersionMismatchError
from app.schemas.drift import (
    DriftAnalysisSchema,
    DriftAnalysisSummarySchema,
    DriftAnalyzeRequestSchema,
    DriftEngineStatusSchema,
    DriftThresholdConfigSchema,
    FeatureDriftSchema,
)
from app.services.drift_service import drift_service

router = APIRouter(prefix="/drift", tags=["Security Drift Detection"])


@router.get(
    "/status",
    response_model=DriftEngineStatusSchema,
    summary="Get drift detection engine status",
)
def get_drift_engine_status() -> DriftEngineStatusSchema:
    """Return live engine state and summary metrics for Layer 07."""
    return drift_service.get_status()


@router.get(
    "/config",
    response_model=DriftThresholdConfigSchema,
    summary="Get active threshold configuration",
)
def get_drift_threshold_config() -> DriftThresholdConfigSchema:
    """Return the active versioned threshold configuration."""
    return drift_service.get_config()


@router.post(
    "/analyze",
    response_model=DriftAnalysisSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Evaluate session for behavioral drift",
)
def analyze_session_drift(payload: DriftAnalyzeRequestSchema) -> DriftAnalysisSchema:
    """Execute deterministic drift evaluation comparing session features against baseline."""
    try:
        return drift_service.analyze(
            session_id=payload.session_id,
            baseline_id=payload.baseline_id,
            config_override=payload.config_override,
        )
    except FeatureVersionMismatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "FEATURE_VERSION_MISMATCH", "message": str(exc)},
        ) from exc
    except DriftPreconditionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "DRIFT_PRECONDITION_FAILED", "message": str(exc)},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "DRIFT_ANALYSIS_FAILED", "message": str(exc)},
        ) from exc


@router.get(
    "",
    response_model=List[DriftAnalysisSummarySchema],
    summary="List historical drift evaluations",
)
def list_drift_analyses(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    baseline_id: Optional[str] = Query(None, description="Filter by baseline ID"),
    status: Optional[str] = Query(None, description="Filter by status (WITHIN BASELINE, DRIFT DETECTED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (NONE, LOW, MODERATE, HIGH)"),
    limit: int = Query(50, ge=1, le=200, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> List[DriftAnalysisSummarySchema]:
    """Retrieve historical drift evaluations ordered by analysis time descending."""
    return drift_service.list_analyses(
        session_id=session_id,
        baseline_id=baseline_id,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{analysis_id}",
    response_model=DriftAnalysisSchema,
    summary="Get drift analysis details",
)
def get_drift_analysis(analysis_id: str) -> DriftAnalysisSchema:
    """Retrieve a specific drift analysis including all feature-level deviations."""
    analysis = drift_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "DRIFT_ANALYSIS_NOT_FOUND", "message": f"Analysis '{analysis_id}' not found."},
        )
    return analysis


@router.get(
    "/{analysis_id}/features",
    response_model=List[FeatureDriftSchema],
    summary="Get feature drift details for an analysis",
)
def get_drift_analysis_features(analysis_id: str) -> List[FeatureDriftSchema]:
    """Retrieve individual feature results for a specific analysis."""
    features = drift_service.get_features(analysis_id)
    if not features:
        # Check if analysis exists
        if not drift_service.get_analysis(analysis_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "DRIFT_ANALYSIS_NOT_FOUND", "message": f"Analysis '{analysis_id}' not found."},
            )
    return features


@router.get(
    "/session/{session_id}",
    response_model=DriftAnalysisSchema,
    summary="Get latest drift analysis for a session",
)
def get_session_latest_drift(session_id: str) -> DriftAnalysisSchema:
    """Retrieve the most recent drift evaluation for a given session."""
    analysis = drift_service.get_latest_for_session(session_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NO_DRIFT_ANALYSIS_FOR_SESSION", "message": f"No drift evaluation recorded for session '{session_id}'."},
        )
    return analysis


@router.delete(
    "",
    summary="Clear all drift analysis records",
)
def clear_drift_analyses() -> dict:
    """Clear all stored drift evaluations (for test cleanup)."""
    drift_service.clear()
    return {"status": "CLEARED"}
