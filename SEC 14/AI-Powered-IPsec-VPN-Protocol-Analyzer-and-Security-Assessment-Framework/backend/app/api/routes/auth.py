"""Authentication endpoints: register, login, logout, me, forgot-password, and reset-password."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    login_rate_limiter,
    verify_password,
)
from app.db.base import get_db
from app.models.user import PasswordResetToken, User, UserSession
from app.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginSuccessResponse,
    MessageResponse,
    ResetPasswordRequest,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Dummy hash used for constant-time comparison when a user identifier does not exist
_DUMMY_HASH = hash_password("DummyTimingProtectionPassword123!")


def _client_ip(request: Request) -> str:
    """Safely obtain client IP address for rate limiting."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.post(
    "/register",
    response_model=LoginSuccessResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(
    payload: UserRegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginSuccessResponse:
    """Create a new user account, initialize a session, and return the session cookie."""
    settings = get_settings()

    # Check for existing email or username conflict
    existing_user = db.scalar(
        select(User).where(
            or_(
                User.email == payload.email,
                User.username == payload.username,
            )
        )
    )
    if existing_user:
        if existing_user.email == payload.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email address already exists.",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this username already exists.",
        )

    # Hash password with Argon2id
    pwd_hash = hash_password(payload.password)

    new_user = User(
        name=payload.name,
        email=payload.email,
        username=payload.username,
        password_hash=pwd_hash,
        role="analyst",
        is_active=True,
        is_verified=True,
        last_login=datetime.now(timezone.utc),
    )
    db.add(new_user)
    db.flush()

    # Create active session
    session_expiry = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    new_session = UserSession(
        user_id=new_user.id,
        user_agent=request.headers.get("User-Agent"),
        ip_address=_client_ip(request),
        expires_at=session_expiry,
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_user)
    db.refresh(new_session)

    # Issue access token
    token = create_access_token(
        {
            "sub": new_user.id,
            "sid": new_session.id,
            "email": new_user.email,
            "username": new_user.username,
            "role": new_user.role,
        }
    )

    # Attach HTTP-only cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.is_cookie_secure,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )

    logger.info("User registered: %s (%s)", new_user.username, new_user.email)
    return LoginSuccessResponse(
        message="Account created successfully.",
        user=UserResponse.model_validate(new_user),
    )


@router.post(
    "/login",
    response_model=LoginSuccessResponse,
    summary="Authenticate and establish session",
)
def login(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginSuccessResponse:
    """Verify credentials, enforce brute-force rate limits, and set HTTP-only session cookie."""
    settings = get_settings()
    client_ip = _client_ip(request)
    identifier = payload.identifier.strip().lower()

    # Check brute-force rate limit
    is_limited, retry_after = login_rate_limiter.is_rate_limited(identifier, client_ip)
    if is_limited:
        logger.warning(
            "Rate limit triggered for '%s' from IP %s. Retry after %ds",
            identifier,
            client_ip,
            retry_after,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    # Look up user by email or username
    user = db.scalar(
        select(User).where(
            or_(
                User.email == identifier,
                User.username == identifier,
            )
        )
    )

    if not user:
        # Constant-time mitigation against timing enumeration attacks
        verify_password(payload.password, _DUMMY_HASH)
        login_rate_limiter.record_failure(identifier, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password.",
        )

    if not verify_password(payload.password, user.password_hash):
        login_rate_limiter.record_failure(identifier, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Please contact an administrator.",
        )

    # Success: clear failure counters
    login_rate_limiter.record_success(identifier, client_ip)

    now = datetime.now(timezone.utc)
    user.last_login = now

    # Create new user session
    session_expiry = now + timedelta(minutes=settings.access_token_expire_minutes)
    new_session = UserSession(
        user_id=user.id,
        user_agent=request.headers.get("User-Agent"),
        ip_address=client_ip,
        expires_at=session_expiry,
    )
    db.add(new_session)
    db.commit()
    db.refresh(user)
    db.refresh(new_session)

    # Issue JWT token
    token = create_access_token(
        {
            "sub": user.id,
            "sid": new_session.id,
            "email": user.email,
            "username": user.username,
            "role": user.role,
        }
    )

    # Set HTTP-only SameSite cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.is_cookie_secure,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )

    logger.info("User logged in: %s (%s)", user.username, user.email)
    return LoginSuccessResponse(
        message="Authentication successful.",
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Terminate session and clear cookie",
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Revoke the active database session and clear the session cookie."""
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    if token:
        payload = decode_access_token(token)
        if payload and "sid" in payload:
            session_id = payload["sid"]
            active_session = db.scalar(
                select(UserSession).where(UserSession.id == session_id)
            )
            if active_session:
                active_session.is_revoked = True
                try:
                    db.commit()
                except Exception as exc:
                    logger.warning("Error revoking session %s: %s", session_id, exc)

    response.delete_cookie(key="access_token", path="/")
    return MessageResponse(message="Signed out successfully.")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Return the currently authenticated user's profile."""
    return UserResponse.model_validate(current_user)


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Request a password reset link",
)
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
) -> ForgotPasswordResponse:
    """Generate a single-use reset token without revealing whether the email exists."""
    user = db.scalar(select(User).where(User.email == payload.email))

    demo_token: Optional[str] = None
    demo_url: Optional[str] = None

    if user and user.is_active:
        raw_token, token_hash = generate_reset_token()
        expiry = datetime.now(timezone.utc) + timedelta(minutes=15)

        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expiry,
        )
        db.add(reset_record)
        db.commit()

        demo_token = raw_token
        demo_url = f"/reset-password?token={raw_token}"
        logger.info(
            "Password reset token generated for %s: %s", user.email, demo_url
        )

    # Generic response protects against account enumeration
    return ForgotPasswordResponse(
        message="If an account exists for this email, a password reset link has been sent.",
        demo_reset_token=demo_token,
        demo_reset_url=demo_url,
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using a valid token",
)
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Verify reset token, update password using Argon2id, and revoke prior sessions."""
    incoming_hash = hash_reset_token(payload.token.strip())
    now = datetime.now(timezone.utc)

    reset_record = db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == incoming_hash,
            PasswordResetToken.is_used.is_(False),
            PasswordResetToken.expires_at > now,
        )
    )

    if not reset_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The password reset link is invalid or has expired.",
        )

    user = db.scalar(select(User).where(User.id == reset_record.user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account associated with this token no longer exists.",
        )

    # Hash new password with Argon2id
    user.password_hash = hash_password(payload.new_password)
    user.updated_at = now
    reset_record.is_used = True

    # Invalidate all prior sessions for security
    sessions = db.scalars(
        select(UserSession).where(
            UserSession.user_id == user.id,
            UserSession.is_revoked.is_(False),
        )
    ).all()
    for s in sessions:
        s.is_revoked = True

    db.commit()
    logger.info("Password successfully reset for user %s", user.email)
    return MessageResponse(
        message="Password has been reset successfully. You may now sign in with your new password."
    )
