"""Layer 06 — Session Fingerprint Engine.

Builds a deterministic behavioral fingerprint from Section 8 session feature
vectors.

Fingerprint Principles:
1. Determinism: Same features -> exact same fingerprint ID and signature.
2. Canonical Serialization: Keys and values are sorted and normalized into a
   canonical JSON representation before hashing.
3. Cryptographic Signature: SHA-256 over canonical feature data guarantees
   integrity and change detection.
4. Equal Treatment: Features are unweighted and factual.
5. Strict Feature Versioning: Feature version is recorded and validated.
6. Representation Only: The fingerprint does NOT make security or risk judgments.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.layers.layer05_feature_engineering.models import (
    FEATURE_VERSION,
    FeatureVector,
)
from app.layers.layer05_feature_engineering.registry import (
    definition,
    definitions_for,
)
from .models import FingerprintFeature, SessionFingerprint

# Documented core feature set selected for session fingerprinting
# All categories from Section 8 SESSION level are covered:
FINGERPRINT_FEATURE_CATEGORIES = (
    "TRAFFIC",
    "TIMING",
    "PROTOCOL",
    "IPSEC",
    "IKE",
    "DIRECTIONAL",
    "STATISTICAL",
)


def canonicalize_feature_value(val: Any) -> Any:
    """Ensure predictable representation for canonical hashing.
    
    Floats are rounded to 6 decimal places to avoid floating point jitter.
    Booleans, ints, and strings are preserved.
    None is represented as None.
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        # Prevent floating precision discrepancies across architectures
        return round(val, 6)
    return str(val)


def generate_fingerprint_signature(canonical_payload: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 signature from canonical key-value dictionary."""
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_session_fingerprint(
    vector: FeatureVector,
    capture_id: str,
    created_at: Optional[str] = None,
) -> SessionFingerprint:
    """Construct a SessionFingerprint from a Section 8 session FeatureVector.
    
    Raises ValueError if vector entity_type is not 'SESSION' or if feature_version
    is incompatible.
    """
    if vector.entity_type != "SESSION":
        raise ValueError(
            f"Cannot build session fingerprint from entity type '{vector.entity_type}'. Expected 'SESSION'."
        )

    if vector.feature_version != FEATURE_VERSION:
        raise ValueError(
            f"Feature version mismatch: vector has '{vector.feature_version}', expected '{FEATURE_VERSION}'."
        )

    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    features: List[FingerprintFeature] = []
    canonical_items: Dict[str, Any] = {}

    for fv in vector.features:
        try:
            defn = definition("SESSION", fv.name)
        except KeyError:
            continue

        if defn.category not in FINGERPRINT_FEATURE_CATEGORIES:
            continue

        # Timestamps like first_seen / last_seen are excluded from the behavioral
        # signature so that identical behavior at different times yields identical signature,
        # but they are kept in the fingerprint features list for timeline inspection.
        feature_item = FingerprintFeature(
            name=defn.name,
            display_name=defn.display_name,
            category=defn.category,
            data_type=defn.data_type,
            unit=defn.unit,
            value=fv.value,
            availability=fv.availability,
            quality=fv.quality,
            source=fv.source,
        )
        features.append(feature_item)

        if defn.data_type != "TIMESTAMP":
            canonical_items[defn.name] = canonicalize_feature_value(fv.value)

    # Compute deterministic SHA-256 signature
    signature = generate_fingerprint_signature(canonical_items)
    fingerprint_id = f"FP-{vector.entity_id}-{signature[:12]}"

    return SessionFingerprint(
        fingerprint_id=fingerprint_id,
        session_id=vector.entity_id,
        capture_id=capture_id,
        feature_version=vector.feature_version,
        fingerprint_signature=signature,
        created_at=timestamp,
        features=features,
        feature_count=len(features),
    )
