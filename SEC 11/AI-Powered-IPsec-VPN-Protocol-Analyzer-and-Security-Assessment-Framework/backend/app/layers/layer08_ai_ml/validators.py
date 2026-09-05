"""Validation utilities for Layer 08 AI / ML Anomaly Detection Engine.

Enforces minimum training samples, feature version compatibility, dataset integrity,
and non-fabrication constraints.
"""

from __future__ import annotations

from typing import List, Sequence
from fastapi import HTTPException, status

CURRENT_FEATURE_VERSION = "1.0"
CURRENT_PREPROCESSING_VERSION = "1.0"


class InsufficientTrainingDataError(HTTPException):
    def __init__(self, available_samples: int, required_samples: int):
        detail = (
            f"INSUFFICIENT TRAINING DATA: The selected baseline contains only {available_samples} "
            f"valid session observation(s), but at least {required_samples} are required. "
            f"Additional real session observations must be collected and baselined before a "
            f"behavioral ML model can be trained reliably."
        )
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class IncompatibleFeatureVersionError(HTTPException):
    def __init__(self, model_version: str, input_version: str):
        detail = (
            f"INCOMPATIBLE FEATURE VERSION: The model expects feature version '{model_version}', "
            f"but received input vector with version '{input_version}'. "
            f"Model cannot process incompatible feature schemas."
        )
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class ModelNotReadyError(HTTPException):
    def __init__(self, model_id: str, current_status: str):
        detail = (
            f"MODEL NOT READY: Model '{model_id}' is in status '{current_status}'. "
            f"Only models in 'READY' or 'TRAINED' status can execute inference."
        )
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class MissingFeatureVectorError(HTTPException):
    def __init__(self, session_id: str):
        detail = (
            f"INVALID FEATURE VECTOR: No session-level feature vector (Level: SESSION) found "
            f"for session '{session_id}'. Run Feature Extraction (Layer 05) before ML analysis."
        )
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def validate_training_sample_count(available_count: int, minimum_required: int) -> None:
    """Verify that training dataset contains sufficient real session observations."""
    if available_count < minimum_required:
        raise InsufficientTrainingDataError(available_count, minimum_required)


def validate_feature_version_compatibility(model_feature_version: str, vector_feature_version: str) -> None:
    """Ensure vector feature version matches the model's trained feature schema."""
    if model_feature_version != vector_feature_version:
        raise IncompatibleFeatureVersionError(model_feature_version, vector_feature_version)


def validate_model_inference_status(model_status: str, model_id: str) -> None:
    """Ensure the model is loaded and ready for inference."""
    if model_status not in ("READY", "TRAINED"):
        raise ModelNotReadyError(model_id, model_status)
