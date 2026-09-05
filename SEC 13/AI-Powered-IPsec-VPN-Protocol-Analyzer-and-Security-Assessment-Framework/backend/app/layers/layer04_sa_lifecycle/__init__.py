"""Layer 04 — Security State & SA Lifecycle Engine.

Status: IN DEVELOPMENT.

Derives IKE SAs and child SAs from Layer 03 output and tracks their lifecycle
with evidence-cited transitions. See `engine.py` for the rules and for what
the engine deliberately refuses to infer.
"""

LAYER_NUMBER = 4
LAYER_NAME = "Security State & SA Lifecycle Engine"

from app.layers.layer04_sa_lifecycle.engine import SecurityAssociation, LifecycleEvent, discover  # noqa: E402

__all__ = ["LAYER_NUMBER", "LAYER_NAME", "SecurityAssociation", "LifecycleEvent", "discover"]
