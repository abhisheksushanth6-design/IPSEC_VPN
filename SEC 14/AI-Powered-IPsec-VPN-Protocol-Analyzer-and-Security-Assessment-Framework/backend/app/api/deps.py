"""FastAPI dependencies for authentication, database sessions, and authorization."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.base import get_db
from app.models.user import User, UserSession

logger = logging.getLogger(__name__)


def _extract_token_from_request(request: Request) -> Optional[str]:
    """Extract the JWT access token from HTTP-only cookie or Authorization header."""
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Dependency that resolves the authenticated User from the session or JWT."""
    token = _extract_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: Optional[str] = payload.get("sub")
    session_id: Optional[str] = payload.get("sid")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        )

    now = datetime.now(timezone.utc)

    # Check session revocation in database if session id is attached
    if session_id:
        active_session = db.scalar(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
                UserSession.is_revoked.is_(False),
                UserSession.expires_at > now,
            )
        )
        if not active_session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been terminated or expired. Please sign in again.",
            )
        # Touch last activity
        active_session.last_activity = now
        try:
            db.commit()
        except Exception:
            db.rollback()

    user = db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Please contact an administrator.",
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the resolved user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated.",
        )
    return current_user


async def get_optional_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Optional dependency that returns User if authenticated, else None."""
    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None
