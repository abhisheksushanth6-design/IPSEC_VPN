"""Model persistence, registry, and integrity verification for Layer 08.

Saves and loads serialized scikit-learn models using joblib, verifies SHA-256
checksums to ensure artifact integrity, and maintains an in-memory cache of
the active model.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import joblib

logger = logging.getLogger(__name__)

# Base directory for persisted models: backend/data/models
MODELS_DIR = Path(__file__).resolve().parents[3] / "data" / "models"


class ModelIntegrityError(Exception):
    """Raised when an artifact checksum does not match its database record."""
    pass


class ModelRegistry:
    """Manages disk serialization, checksum verification, and in-memory cache."""

    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or MODELS_DIR
        self._ensure_storage()
        self._cached_model_id: Optional[str] = None
        self._cached_model_object: Optional[Any] = None

    def _ensure_storage(self) -> None:
        """Create storage directory if it does not exist."""
        try:
            self.models_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.error("Failed to create models directory %s: %s", self.models_dir, exc)

    def is_writable(self) -> bool:
        """Check if models storage is accessible and writable."""
        try:
            test_file = self.models_dir / ".write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()
            return True
        except Exception:
            return False

    def compute_file_checksum(self, file_path: Path) -> str:
        """Compute SHA-256 checksum of a file on disk."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def save_model(
        self,
        model_id: str,
        model_object: Any,
        metadata: Dict[str, Any],
    ) -> Tuple[str, str]:
        """Serialize a model and its associated metadata to disk.
        
        Returns:
            (artifact_relative_path, sha256_checksum)
        """
        self._ensure_storage()
        file_name = f"{model_id}.joblib"
        artifact_path = self.models_dir / file_name

        payload = {
            "model_id": model_id,
            "model_object": model_object,
            "metadata": metadata,
        }

        joblib.dump(payload, artifact_path, compress=3)
        checksum = self.compute_file_checksum(artifact_path)

        # Update cache
        self._cached_model_id = model_id
        self._cached_model_object = model_object

        logger.info("Persisted model %s to %s (sha256=%s)", model_id, artifact_path, checksum[:12])
        return str(artifact_path), checksum

    def load_model(
        self,
        model_id: str,
        artifact_path_str: str,
        expected_checksum: Optional[str] = None,
    ) -> Tuple[Any, Dict[str, Any]]:
        """Load and verify a model from disk.
        
        Returns:
            (model_object, metadata)
        """
        if not artifact_path_str or not Path(artifact_path_str).is_file():
            artifact_path = self.models_dir / f"{model_id}.joblib"
        else:
            artifact_path = Path(artifact_path_str)

        if not artifact_path.exists() or not artifact_path.is_file():
            raise FileNotFoundError(f"Model artifact file not found: {artifact_path}")

        # Check integrity
        if expected_checksum:
            actual_checksum = self.compute_file_checksum(artifact_path)
            if actual_checksum != expected_checksum:
                raise ModelIntegrityError(
                    f"Model artifact integrity check failed for '{model_id}'. "
                    f"Expected checksum {expected_checksum}, got {actual_checksum}."
                )

        payload = joblib.load(artifact_path)
        model_object = payload["model_object"]
        metadata = payload.get("metadata", {})

        self._cached_model_id = model_id
        self._cached_model_object = model_object

        return model_object, metadata

    def get_cached_model(self, model_id: str) -> Optional[Any]:
        """Return in-memory model object if cached."""
        if self._cached_model_id == model_id:
            return self._cached_model_object
        return None

    def clear_cache(self) -> None:
        """Invalidate the model cache."""
        self._cached_model_id = None
        self._cached_model_object = None


model_registry = ModelRegistry()
