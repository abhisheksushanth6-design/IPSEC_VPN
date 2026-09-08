"""Layer 08 — AI / ML Anomaly Detection Engine.

Status: OPERATIONAL.

Identifies behavioral patterns using a locally trained CIC-IDS2017 XGBoost model
(and optional Isolation Forest baselines) with factual explainable evidence.
No cloud LLM is used.
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
