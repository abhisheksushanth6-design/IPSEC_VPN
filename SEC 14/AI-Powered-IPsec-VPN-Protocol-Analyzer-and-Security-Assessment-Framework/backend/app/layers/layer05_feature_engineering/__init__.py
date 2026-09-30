"""Layer 05 — Feature Extraction & Engineering.

Turns the factual observations of Layers 03 and 04 into a structured,
versioned feature vector that later baseline, drift and AI modules can
consume.

The layer calculates and validates; it does not judge. There is no baseline,
no drift, no anomaly score and no risk here, and no normalization statistics
fitted to data — Section 8 builds the normalization architecture only.
"""

from .calculators import SAEvent, SARecord, SessionRecord
from .extraction import (
    FeatureExtractionError,
    build_vector,
    extract_packet,
    extract_sa,
    extract_session,
)
from .models import (
    FEATURE_VERSION,
    EntityType,
    FeatureAvailability,
    FeatureCategory,
    FeatureDefinition,
    FeatureLevel,
    FeatureQuality,
    FeatureType,
    FeatureValue,
    FeatureVector,
    NormalizationMethod,
    SourceAvailability,
)
from .registry import (
    BURST_WINDOW_SECONDS,
    FEATURE_DEFINITIONS,
    definition,
    definitions_for,
    has_definition,
)
from .assessment_models import RiskAssessmentReport, SecurityFinding
from .assessment_rules import run_security_assessment
from .assessment_service import SecurityAssessmentService, get_security_assessment_service

LAYER_NUMBER = 5
LAYER_NAME = "Feature Extraction & Engineering"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "FEATURE_VERSION",
    "FEATURE_DEFINITIONS",
    "BURST_WINDOW_SECONDS",
    "FeatureExtractionError",
    "FeatureVector",
    "FeatureValue",
    "FeatureDefinition",
    "SourceAvailability",
    "EntityType",
    "FeatureLevel",
    "FeatureType",
    "FeatureCategory",
    "FeatureAvailability",
    "FeatureQuality",
    "NormalizationMethod",
    "SessionRecord",
    "SARecord",
    "SAEvent",
    "build_vector",
    "extract_packet",
    "extract_session",
    "extract_sa",
    "definition",
    "definitions_for",
    "has_definition",
    "SecurityFinding",
    "RiskAssessmentReport",
    "run_security_assessment",
    "SecurityAssessmentService",
    "get_security_assessment_service",
]
