"""Layer 08 — AI / ML Anomaly Detection Engine.

Status: OPERATIONAL.

Identifies behavioral patterns that differ significantly from learned/reference
VPN behavior using unsupervised Isolation Forest models with factual explainable
evidence and 3-signal comparison.
"""

from app.layers.layer08_ai_ml.service import AIAnomalyService
from app.layers.layer08_ai_ml.trainer import ModelTrainingService
from app.layers.layer08_ai_ml.inference import AnomalyInferenceService
from app.layers.layer08_ai_ml.registry import model_registry

LAYER_NUMBER = 8
LAYER_NAME = "AI / ML Anomaly Detection Engine"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "AIAnomalyService",
    "ModelTrainingService",
    "AnomalyInferenceService",
    "model_registry",
]
