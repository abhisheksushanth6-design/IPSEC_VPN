"""API router for AI Traffic Classification inside ESP (Layer 08)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer08_ai_ml.traffic_classifier import TrafficClassificationService
from app.models.ipsec_session import IPsecSession
from app.models.traffic_classification import TrafficClassificationRow
from app.schemas.traffic_classification import (
    TrafficClassificationPageSchema,
    TrafficClassificationSchema,
    TrafficClassificationSummarySchema,
)

router = APIRouter(prefix="/traffic-analysis", tags=["Traffic Analysis"])


def _row_to_schema(r: TrafficClassificationRow) -> TrafficClassificationSchema:
    return TrafficClassificationSchema(
        id=r.id,
        capture_id=r.capture_id,
        session_id=r.session_id,
        flow_id=r.flow_id,
        traffic_type=r.traffic_type,
        confidence=r.confidence,
        probabilities=json.loads(r.probabilities_json) if r.probabilities_json else {},
        features=json.loads(r.features_json) if r.features_json else {},
        explainability=json.loads(r.explainability_json) if r.explainability_json else [],
        created_at=r.created_at.isoformat() if r.created_at else "",
    )


@router.get("/capture/{capture_id}", response_model=List[TrafficClassificationSchema])
def get_capture_classifications(capture_id: str, db: Session = Depends(get_db)) -> List[TrafficClassificationSchema]:
    """Retrieve all traffic classifications for a given capture."""
    svc = TrafficClassificationService(db)
    rows = svc.get_by_capture(capture_id)
    return [_row_to_schema(r) for r in rows]


@router.get("/summary/{capture_id}", response_model=TrafficClassificationSummarySchema)
def get_classification_summary(capture_id: str, db: Session = Depends(get_db)) -> TrafficClassificationSummarySchema:
    """Retrieve summary breakdown of traffic types identified inside ESP."""
    svc = TrafficClassificationService(db)
    summary = svc.get_summary(capture_id)
    return TrafficClassificationSummarySchema(**summary)


@router.post("/classify/{capture_id}", response_model=List[TrafficClassificationSchema])
def trigger_classification(capture_id: str, db: Session = Depends(get_db)) -> List[TrafficClassificationSchema]:
    """Trigger ML traffic classification across all sessions in the capture."""
    svc = TrafficClassificationService(db)
    rows = svc.classify_capture(capture_id)
    return [_row_to_schema(r) for r in rows]


@router.get("/summary", response_model=TrafficClassificationSummarySchema)
@router.get("/distribution", response_model=TrafficClassificationSummarySchema)
def get_global_classification_summary(db: Session = Depends(get_db)) -> TrafficClassificationSummarySchema:
    from app.services.packet_service import packet_service
    capture_id = packet_service.capture_id or "default"
    svc = TrafficClassificationService(db)
    summary = svc.get_summary(capture_id)
    return TrafficClassificationSummarySchema(**summary)


@router.get("/session/{session_id}", response_model=TrafficClassificationSchema)
@router.get("/classify/{session_id}", response_model=TrafficClassificationSchema)
def get_session_classification(session_id: str, db: Session = Depends(get_db)) -> TrafficClassificationSchema:
    """Retrieve traffic classification for an individual session."""
    svc = TrafficClassificationService(db)
    row = svc.get_by_session(session_id)
    if not row:
        session = db.get(IPsecSession, session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        row = svc.classify_session(session)
    return _row_to_schema(row)


@router.get("/comprehensive/{session_id}")
def get_comprehensive_session_analysis(session_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve complete AI-powered protocol, mode, crypto, SA, and traffic classification."""
    from app.layers.layer08_ai_ml.protocol_classifier import AIProtocolTrafficClassifier

    session = db.get(IPsecSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    analysis = AIProtocolTrafficClassifier.analyze_session(session, db=db)
    return analysis.to_dict()


@router.get("/comprehensive-capture/{capture_id}")
def get_comprehensive_capture_analysis(capture_id: str, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Retrieve comprehensive AI analysis for all sessions in a capture."""
    from app.layers.layer08_ai_ml.protocol_classifier import AIProtocolTrafficClassifier

    sessions = db.scalars(
        select(IPsecSession).where(IPsecSession.capture_id == capture_id)
    ).all()
    if not sessions:
        from app.services.packet_service import packet_service
        if packet_service.capture_id == capture_id or not sessions:
            from app.services.session_service import session_service
            session_service.discover_sessions(db, capture_id=capture_id)
            sessions = db.scalars(
                select(IPsecSession).where(IPsecSession.capture_id == capture_id)
            ).all()

    return [AIProtocolTrafficClassifier.analyze_session(s, db=db).to_dict() for s in sessions]


