"""Application configuration.

All runtime configuration is read from environment variables so that no
credentials, hosts or paths are hard-coded in the source tree. See
`.env.example` at the repository root for the supported keys.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_NAME = (
    "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework"
)

# backend/app/core/config.py -> backend/
BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = BACKEND_ROOT.parent
DEFAULT_DATA_DIR = BACKEND_ROOT / "data"


class Settings(BaseSettings):
    """Typed application settings loaded from the environment."""

    model_config = SettingsConfigDict(
        env_file=(REPOSITORY_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    project_name: str = PROJECT_NAME
    api_prefix: str = "/api"

    database_url: str = Field(default="")
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000)
    cors_origins: str = Field(default="http://localhost:5173")
    application_mode: str = Field(default="DEMO")
    log_level: str = Field(default="INFO")

    @field_validator("application_mode")
    @classmethod
    def _normalise_mode(cls, value: str) -> str:
        mode = (value or "DEMO").strip().upper()
        allowed = {"DEMO", "DEVELOPMENT", "PRODUCTION"}
        if mode not in allowed:
            raise ValueError(
                f"APPLICATION_MODE must be one of {sorted(allowed)}, got {value!r}"
            )
        return mode

    @property
    def resolved_database_url(self) -> str:
        """Return the configured database URL, or a local SQLite default."""
        if self.database_url.strip():
            return self.database_url.strip()
        DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DEFAULT_DATA_DIR / 'application.db'}"

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse the comma-separated CORS origins into a list.

        A wildcard is only honoured outside of PRODUCTION so that a stray
        environment value cannot open up a deployed instance.
        """
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        if not origins:
            return ["http://localhost:5173"]
        if "*" in origins and self.application_mode == "PRODUCTION":
            raise ValueError("Wildcard CORS origins are not allowed in PRODUCTION mode")
        return origins

    @property
    def is_production(self) -> bool:
        return self.application_mode == "PRODUCTION"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the settings cache. Used by tests that patch the environment."""
    get_settings.cache_clear()


def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean-ish environment variable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
