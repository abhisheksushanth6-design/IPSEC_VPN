"""Comprehensive test suite for Authentication & Authorization API endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.core.security import hash_password, login_rate_limiter
from app.db.base import SessionLocal
from app.main import app
from app.models.user import User


@pytest.fixture(autouse=True)
def _clean_test_state():
    """Reset rate limiter and clean up any test accounts before and after tests."""
    with login_rate_limiter._lock:
        login_rate_limiter._attempts.clear()
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@testcorp.org")))
        db.commit()
    yield
    with login_rate_limiter._lock:
        login_rate_limiter._attempts.clear()
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@testcorp.org")))
        db.commit()


@pytest.fixture
def auth_client():
    """Fresh TestClient instance for authentication testing."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def seed_test_user():
    """Ensure a clean test user exists in the database."""
    with SessionLocal() as db:
        u = User(
            name="Test Analyst",
            email="analyst@testcorp.org",
            username="analyst_test",
            password_hash=hash_password("StrongPassword@2026!"),
            role="analyst",
            is_active=True,
            is_verified=True,
        )
        db.add(u)
        db.commit()

    return {
        "name": "Test Analyst",
        "email": "analyst@testcorp.org",
        "username": "analyst_test",
        "password": "StrongPassword@2026!",
    }


class TestRegistration:
    """Test user registration flow and constraints."""

    def test_successful_registration(self, auth_client: TestClient) -> None:
        payload = {
            "name": "Jane Doe",
            "email": "jane.doe@testcorp.org",
            "username": "janedoe",
            "password": "StrongPassword@2026!",
        }
        res = auth_client.post("/api/auth/register", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["user"]["email"] == "jane.doe@testcorp.org"
        assert data["user"]["username"] == "janedoe"
        assert "password" not in data["user"]
        assert "password_hash" not in data["user"]
        assert "access_token" in res.cookies

    def test_duplicate_email_rejected(self, auth_client: TestClient, seed_test_user: dict) -> None:
        payload = {
            "name": "Duplicate Email",
            "email": seed_test_user["email"],
            "username": "unique_username",
            "password": "StrongPassword@2026!",
        }
        res = auth_client.post("/api/auth/register", json=payload)
        assert res.status_code == 409
        assert "email" in res.json()["error"].lower()

    def test_duplicate_username_rejected(self, auth_client: TestClient, seed_test_user: dict) -> None:
        payload = {
            "name": "Duplicate Username",
            "email": "unique.email@testcorp.org",
            "username": seed_test_user["username"],
            "password": "StrongPassword@2026!",
        }
        res = auth_client.post("/api/auth/register", json=payload)
        assert res.status_code == 409
        assert "username" in res.json()["error"].lower()

    def test_weak_password_rejected(self, auth_client: TestClient) -> None:
        payload = {
            "name": "Weak Pwd",
            "email": "weak@testcorp.org",
            "username": "weakuser",
            "password": "simplepassword",
        }
        res = auth_client.post("/api/auth/register", json=payload)
        assert res.status_code == 422


class TestLoginAndSession:
    """Test user authentication and session issuance."""

    def test_login_with_correct_credentials_email(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        res = auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["email"],
                "password": seed_test_user["password"],
            },
        )
        assert res.status_code == 200
        assert "access_token" in res.cookies
        assert res.json()["user"]["email"] == seed_test_user["email"]

    def test_login_with_correct_credentials_username(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        res = auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["username"],
                "password": seed_test_user["password"],
            },
        )
        assert res.status_code == 200
        assert res.json()["user"]["username"] == seed_test_user["username"]

    def test_login_with_incorrect_password(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        res = auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["username"],
                "password": "WrongPassword@999!",
            },
        )
        assert res.status_code == 401
        assert "Invalid" in res.json()["error"]

    def test_login_with_nonexistent_user(self, auth_client: TestClient) -> None:
        res = auth_client.post(
            "/api/auth/login",
            json={
                "identifier": "nonexistent@testcorp.org",
                "password": "AnyPassword@123!",
            },
        )
        assert res.status_code == 401
        assert "Invalid" in res.json()["error"]

    def test_me_endpoint_requires_auth(self, auth_client: TestClient) -> None:
        auth_client.cookies.clear()
        res = auth_client.get("/api/auth/me")
        assert res.status_code == 401

    def test_me_endpoint_with_valid_session(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["username"],
                "password": seed_test_user["password"],
            },
        )
        res = auth_client.get("/api/auth/me")
        assert res.status_code == 200
        assert res.json()["username"] == seed_test_user["username"]

    def test_logout_terminates_session(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        # Log in
        auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["username"],
                "password": seed_test_user["password"],
            },
        )
        assert auth_client.get("/api/auth/me").status_code == 200

        # Logout
        logout_res = auth_client.post("/api/auth/logout")
        assert logout_res.status_code == 200

        # Accessing /me after logout fails
        me_res = auth_client.get("/api/auth/me")
        assert me_res.status_code == 401


class TestRateLimiting:
    """Test brute-force attack rate limiting."""

    def test_rate_limit_lockout(self, auth_client: TestClient) -> None:
        for _ in range(5):
            auth_client.post(
                "/api/auth/login",
                json={"identifier": "victim@testcorp.org", "password": "wrong"},
            )

        # 6th attempt should return 429
        blocked = auth_client.post(
            "/api/auth/login",
            json={"identifier": "victim@testcorp.org", "password": "wrong"},
        )
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers


class TestPasswordResetFlow:
    """Test forgot-password and reset-password single-use token lifecycle."""

    def test_forgot_password_generic_message(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        # Existing email
        r1 = auth_client.post(
            "/api/auth/forgot-password",
            json={"email": seed_test_user["email"]},
        )
        assert r1.status_code == 200
        assert "link has been sent" in r1.json()["message"]

        # Non-existing email
        r2 = auth_client.post(
            "/api/auth/forgot-password",
            json={"email": "nobody@testcorp.org"},
        )
        assert r2.status_code == 200
        assert "link has been sent" in r2.json()["message"]

    def test_complete_reset_flow(
        self, auth_client: TestClient, seed_test_user: dict
    ) -> None:
        req = auth_client.post(
            "/api/auth/forgot-password",
            json={"email": seed_test_user["email"]},
        )
        demo_token = req.json().get("demo_reset_token")
        assert demo_token is not None

        # Reset password with token
        reset_res = auth_client.post(
            "/api/auth/reset-password",
            json={
                "token": demo_token,
                "new_password": "NewStrongPassword@2026!",
            },
        )
        assert reset_res.status_code == 200
        assert "reset successfully" in reset_res.json()["message"]

        # Re-using the same token should fail
        reuse_res = auth_client.post(
            "/api/auth/reset-password",
            json={
                "token": demo_token,
                "new_password": "AnotherPassword@2026!",
            },
        )
        assert reuse_res.status_code == 400

        # Login with old password fails
        old_login = auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["username"],
                "password": seed_test_user["password"],
            },
        )
        assert old_login.status_code == 401

        # Login with new password succeeds
        new_login = auth_client.post(
            "/api/auth/login",
            json={
                "identifier": seed_test_user["username"],
                "password": "NewStrongPassword@2026!",
            },
        )
        assert new_login.status_code == 200
