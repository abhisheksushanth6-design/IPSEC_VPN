"""Configuration loading."""

from __future__ import annotations

import pytest

from app.core.config import PROJECT_NAME, Settings, get_settings


def test_project_name_is_exact() -> None:
    assert get_settings().project_name == (
        "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework"
    )
    assert PROJECT_NAME == get_settings().project_name


def test_database_url_falls_back_to_sqlite() -> None:
    settings = Settings(database_url="", application_mode="STANDALONE")
    assert settings.resolved_database_url.startswith("sqlite:///")


def test_default_application_mode_is_standalone() -> None:
    settings = Settings(application_mode="")
    assert settings.application_mode == "STANDALONE"


def test_explicit_demo_opt_in_allowed() -> None:
    settings = Settings(application_mode="DEMO")
    assert settings.application_mode == "DEMO"


def test_cors_origins_are_parsed() -> None:
    settings = Settings(cors_origins="http://a.test, http://b.test")
    assert settings.cors_origin_list == ["http://a.test", "http://b.test"]


def test_wildcard_cors_rejected_in_production() -> None:
    settings = Settings(cors_origins="*", application_mode="PRODUCTION")
    with pytest.raises(ValueError):
        _ = settings.cors_origin_list


def test_invalid_application_mode_rejected() -> None:
    with pytest.raises(ValueError):
        Settings(application_mode="NOT_A_MODE")
