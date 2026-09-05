"""Feature Extraction & Engineering endpoints (Layer 05)."""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Query
from fastapi.responses import Response

from app.api.routes.packets import ERROR_RESPONSES
from app.schemas.features import (
    FeatureDefinitionSchema,
    FeatureEngineStatusSchema,
    FeatureEntityListSchema,
    FeatureExtractionRequestSchema,
    FeatureExtractionResponseSchema,
    FeatureVectorPageSchema,
    FeatureVectorSchema,
)
from app.services.feature_service import feature_service

router = APIRouter(prefix="/features", tags=["features"])


@router.get("/status", response_model=FeatureEngineStatusSchema, summary="Feature engine state and statistics")
def read_status() -> FeatureEngineStatusSchema:
    return feature_service.status()


@router.get("/definitions", response_model=list[FeatureDefinitionSchema], summary="The feature registry")
def read_definitions() -> list[FeatureDefinitionSchema]:
    return feature_service.definitions()


@router.get("/entities", response_model=FeatureEntityListSchema, responses=ERROR_RESPONSES, summary="Entities available for extraction")
def read_entities(
    entity_type: Literal["PACKET", "SESSION", "SA"] = Query("SESSION"),
) -> FeatureEntityListSchema:
    return feature_service.entities(entity_type)


@router.get("", response_model=FeatureVectorPageSchema, summary="List stored feature vectors")
def list_vectors(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    entity_type: Optional[Literal["PACKET", "SESSION", "SA"]] = Query(None),
) -> FeatureVectorPageSchema:
    return feature_service.query(page=page, page_size=page_size, entity_type=entity_type)


@router.post("/extract", response_model=FeatureExtractionResponseSchema, responses=ERROR_RESPONSES, summary="Extract features for one entity")
def extract(request: FeatureExtractionRequestSchema) -> FeatureExtractionResponseSchema:
    vector = feature_service.extract(request.entity_type, request.entity_id)
    return FeatureExtractionResponseSchema(
        status="EXTRACTED",
        feature_version=vector.feature_version,
        generated_at=vector.generated_at,
        feature_vector=vector,
    )


@router.get("/export", responses=ERROR_RESPONSES, summary="Export stored feature vectors")
def export(fmt: Literal["json", "csv"] = Query("json", alias="format")) -> Response:
    payload, media_type = feature_service.export(fmt)
    extension = "csv" if fmt == "csv" else "json"
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="feature-vectors.{extension}"'},
    )


@router.delete("", response_model=FeatureEngineStatusSchema, responses=ERROR_RESPONSES, summary="Clear stored feature vectors")
def clear() -> FeatureEngineStatusSchema:
    from app.services.packet_service import packet_service

    return feature_service.clear(packet_service.capture_id)


@router.get("/entity/{entity_type}/{entity_id}", response_model=FeatureVectorSchema, responses=ERROR_RESPONSES, summary="Stored vector for one entity")
def read_for_entity(
    entity_type: Literal["PACKET", "SESSION", "SA"],
    entity_id: str,
) -> FeatureVectorSchema:
    return feature_service.for_entity(entity_type, entity_id)


@router.get("/{vector_id}", response_model=FeatureVectorSchema, responses=ERROR_RESPONSES, summary="Feature vector detail")
def read_vector(vector_id: str) -> FeatureVectorSchema:
    return feature_service.get(vector_id)
