"""Session Fingerprinting API endpoints (Layer 06).

Provides deterministic behavioral fingerprints for observed IPsec sessions.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter

from app.api.routes.packets import ERROR_RESPONSES
from app.schemas.fingerprint import (
    FingerprintComparisonSchema,
    SessionFingerprintSchema,
)
from app.services.fingerprint_service import fingerprint_service

router = APIRouter(tags=["fingerprints"])


@router.get("/fingerprints", response_model=List[SessionFingerprintSchema], summary="List all generated session fingerprints")
def list_fingerprints() -> List[SessionFingerprintSchema]:
    fps = fingerprint_service.list_all()
    return [SessionFingerprintSchema.model_validate(fp) for fp in fps]


@router.get("/fingerprints/{fingerprint_id}", response_model=SessionFingerprintSchema, responses=ERROR_RESPONSES, summary="Get session fingerprint details")
def get_fingerprint(fingerprint_id: str) -> SessionFingerprintSchema:
    fp = fingerprint_service.get(fingerprint_id)
    return SessionFingerprintSchema.model_validate(fp)


@router.get("/fingerprints/{id_a}/compare/{id_b}", response_model=FingerprintComparisonSchema, responses=ERROR_RESPONSES, summary="Descriptive side-by-side inspection of two fingerprints")
def compare_fingerprints(id_a: str, id_b: str) -> FingerprintComparisonSchema:
    return fingerprint_service.compare(id_a, id_b)


@router.get("/sessions/{session_id}/fingerprint", response_model=SessionFingerprintSchema, responses=ERROR_RESPONSES, summary="Get or generate fingerprint for an IPsec session")
def get_session_fingerprint(session_id: str) -> SessionFingerprintSchema:
    fp = fingerprint_service.get_or_create_for_session(session_id)
    return SessionFingerprintSchema.model_validate(fp)
