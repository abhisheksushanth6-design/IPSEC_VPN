"""Authentication security primitives: Argon2id password hashing, JWT, tokens, and rate limiting."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Argon2id password hasher with secure defaults
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
)

# Password policy pattern requirements
_REQ_MIN_LENGTH = 8
_REQ_UPPERCASE = re.compile(r"[A-Z]")
_REQ_LOWERCASE = re.compile(r"[a-z]")
_REQ_DIGIT = re.compile(r"[0-9]")
_REQ_SPECIAL = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]")


def hash_password(plain_password: str) -> str:
    """Hash a password using Argon2id."""
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against an Argon2id hash with timing protection."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as exc:
        logger.error("Unexpected error during password verification: %s", exc)
        return False


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """Validate that password satisfies enterprise security policy."""
    if len(password) < _REQ_MIN_LENGTH:
        return False, f"Password must be at least {_REQ_MIN_LENGTH} characters long."
    if not _REQ_UPPERCASE.search(password):
        return False, "Password must contain at least one uppercase letter."
    if not _REQ_LOWERCASE.search(password):
        return False, "Password must contain at least one lowercase letter."
    if not _REQ_DIGIT.search(password):
        return False, "Password must contain at least one number."
    if not _REQ_SPECIAL.search(password):
        return False, "Password must contain at least one special character."
    return True, None


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT access token."""
    settings = get_settings()
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"iat": int(now.timestamp()), "exp": int(expire.timestamp())})
    encoded_jwt = jwt.encode(
        to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat"]},
        )
        return payload
    except jwt.PyJWTError as exc:
        logger.debug("JWT decode failure: %s", exc)
        return None


def generate_reset_token() -> Tuple[str, str]:
    """Generate a single-use URL-safe reset token and its SHA-256 database hash."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_reset_token(raw_token)
    return raw_token, token_hash


def hash_reset_token(raw_token: str) -> str:
    """Compute SHA-256 hex digest of a raw token for secure database storage."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class LoginRateLimiter:
    """Thread-safe sliding-window rate limiter to mitigate brute-force authentication attacks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempts: Dict[str, list[float]] = {}

    def _clean_window(self, key: str, window_seconds: int, now: float) -> list[float]:
        cutoff = now - window_seconds
        valid = [t for t in self._attempts.get(key, []) if t > cutoff]
        if valid:
            self._attempts[key] = valid
        else:
            self._attempts.pop(key, None)
        return valid

    def is_rate_limited(self, identifier: str, ip: str) -> Tuple[bool, int]:
        """Check if an identifier or IP has exceeded the allowed failure attempts."""
        settings = get_settings()
        now = time.time()
        window = settings.auth_rate_limit_window_seconds
        max_attempts = settings.auth_rate_limit_max_attempts

        with self._lock:
            for key in (f"id:{identifier.lower()}", f"ip:{ip}"):
                attempts = self._clean_window(key, window, now)
                if len(attempts) >= max_attempts:
                    oldest_attempt = min(attempts)
                    retry_after = max(1, int(oldest_attempt + window - now))
                    return True, retry_after
            return False, 0

    def record_failure(self, identifier: str, ip: str) -> None:
        """Record an authentication failure for both the identifier and the IP."""
        now = time.time()
        with self._lock:
            for key in (f"id:{identifier.lower()}", f"ip:{ip}"):
                if key not in self._attempts:
                    self._attempts[key] = []
                self._attempts[key].append(now)

    def record_success(self, identifier: str, ip: str) -> None:
        """Clear recorded failure attempts on successful authentication."""
        with self._lock:
            self._attempts.pop(f"id:{identifier.lower()}", None)
            self._attempts.pop(f"ip:{ip}", None)


login_rate_limiter = LoginRateLimiter()
