"""Layer 04 — Security State & SA Lifecycle Engine.

Derives IKE SAs and child SAs from Layer 03 output, tracks their lifecycle,
and correlates IPsec packets into logical sessions with stable fingerprints.
"""

from __future__ import annotations

LAYER_NUMBER = 4
LAYER_NAME = "Security State & SA Lifecycle Engine"

from app.layers.layer04_sa_lifecycle.engine import (  # noqa: E402
    ChildSA,
    LifecycleEvent,
    SecurityAssociation,
    discover,
)
from app.layers.layer04_sa_lifecycle.models import (  # noqa: E402
    SessionFingerprintComponents,
    VPNSessionFingerprint,
)
from app.layers.layer04_sa_lifecycle.service import (  # noqa: E402
    Layer04Service,
    get_layer04_service,
)
from app.layers.layer04_sa_lifecycle.session_correlator import (  # noqa: E402
    correlate_sessions_and_fingerprint,
)

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "SecurityAssociation",
    "ChildSA",
    "LifecycleEvent",
    "discover",
    "SessionFingerprintComponents",
    "VPNSessionFingerprint",
    "Layer04Service",
    "get_layer04_service",
    "correlate_sessions_and_fingerprint",
]
