"""Pydantic schemas for authentication and authorization requests/responses."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.security import validate_password_strength

_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{3,64}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserRegisterRequest(BaseModel):
    """Payload to register a new user account."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., min_length=2, max_length=128, description="User's full name")
    email: str = Field(..., max_length=255, description="Unique email address")
    username: str = Field(..., min_length=3, max_length=64, description="Unique username")
    password: str = Field(..., min_length=8, max_length=128, description="Account password")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        norm = value.strip().lower()
        if not _EMAIL_PATTERN.match(norm):
            raise ValueError("Please enter a valid email address.")
        return norm

    @field_validator("username")
    @classmethod
    def validate_username_format(cls, value: str) -> str:
        norm = value.strip().lower()
        if not _USERNAME_PATTERN.match(norm):
            raise ValueError(
                "Username must be 3-64 characters and contain only letters, numbers, hyphens, dots, or underscores."
            )
        return norm

    @field_validator("password")
    @classmethod
    def validate_password_policy(cls, value: str) -> str:
        valid, error_msg = validate_password_strength(value)
        if not valid:
            raise ValueError(error_msg or "Password does not meet complexity requirements.")
        return value


class UserLoginRequest(BaseModel):
    """Payload to authenticate an existing user."""

    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(..., min_length=1, max_length=255, description="Email or Username")
    password: str = Field(..., min_length=1, max_length=128, description="Password")


class UserResponse(BaseModel):
    """Public user information safe for client consumption."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class LoginSuccessResponse(BaseModel):
    """Response returned upon successful authentication."""

    message: str = "Authentication successful"
    user: UserResponse


class ForgotPasswordRequest(BaseModel):
    """Request payload to initiate a password reset."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: str = Field(..., max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        norm = value.strip().lower()
        if not _EMAIL_PATTERN.match(norm):
            raise ValueError("Please enter a valid email address.")
        return norm


class ForgotPasswordResponse(BaseModel):
    """Generic response confirming password reset link dispatch."""

    message: str = "If an account exists for this email, a password reset link has been sent."
    demo_reset_token: Optional[str] = None
    demo_reset_url: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    """Request payload to set a new password using a reset token."""

    model_config = ConfigDict(str_strip_whitespace=True)

    token: str = Field(..., min_length=10, max_length=256, description="Reset token from URL")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        valid, error_msg = validate_password_strength(value)
        if not valid:
            raise ValueError(error_msg or "Password does not meet complexity requirements.")
        return value


class MessageResponse(BaseModel):
    """Simple standard operation status response."""

    message: str
