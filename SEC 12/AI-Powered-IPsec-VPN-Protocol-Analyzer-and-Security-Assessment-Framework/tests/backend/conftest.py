"""Shared pytest fixtures for the backend test suite.

Every test runs against a throwaway SQLite file so the developer database is
never touched.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _isolated_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    db_path = tmp_path_factory.mktemp("db") / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["APPLICATION_MODE"] = "DEMO"
    os.environ["CORS_ORIGINS"] = "http://localhost:5173"
    yield


@pytest.fixture(scope="session")
def client(_isolated_environment: None):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
