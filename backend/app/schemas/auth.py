"""Authentication schemas - Phase 5.

Pydantic models for authentication requests and responses.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr, field_validator
import re


class LoginRequest(BaseModel):
    """User login request."""
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Username or email"
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password"
    )


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str = Field(..., description="Valid refresh token")


class UserCreate(BaseModel):
    """User creation request (admin only)."""
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Username (alphanumeric and underscore only)"
    )
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password"
    )
    full_name: Optional[str] = Field(
        None,
        max_length=255,
        description="User full name"
    )
    role: str = Field(
        default="VIEWER",
        description="User role (ADMIN, ANALYST, VIEWER)"
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid_roles = ["ADMIN", "ANALYST", "VIEWER"]
        if v.upper() not in valid_roles:
            raise ValueError(f"Role must be one of: {', '.join(valid_roles)}")
        return v.upper()


class UserUpdate(BaseModel):
    """User update request."""
    email: Optional[EmailStr] = Field(None, description="User email address")
    full_name: Optional[str] = Field(
        None,
        max_length=255,
        description="User full name"
    )
    role: Optional[str] = Field(None, description="User role")
    status: Optional[str] = Field(None, description="User status")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        valid_roles = ["ADMIN", "ANALYST", "VIEWER"]
        if v.upper() not in valid_roles:
            raise ValueError(f"Role must be one of: {', '.join(valid_roles)}")
        return v.upper()

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        valid_statuses = ["ACTIVE", "INACTIVE", "LOCKED"]
        if v.upper() not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return v.upper()


class PasswordChange(BaseModel):
    """Password change request."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password"
    )


class UserResponse(BaseModel):
    """User information response."""
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    status: str
    last_login: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    """List of users response."""
    users: List[UserResponse]
    total: int


class AuthError(BaseModel):
    """Authentication error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")


class MeResponse(BaseModel):
    """Current user info response."""
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    permissions: List[str]

    model_config = {"from_attributes": True}
