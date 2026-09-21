"""Health check schemas."""
from typing import Literal
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Basic health check response."""

    status: Literal["healthy"] = Field(
        default="healthy",
        description="Service health status"
    )
    service: str = Field(
        default="SecureMailScope API",
        description="Service name"
    )
    version: str = Field(
        default="0.5.0",
        description="Application version"
    )


class DependencyStatus(BaseModel):
    """Individual dependency status."""

    name: str = Field(description="Dependency name")
    status: Literal["healthy", "unhealthy", "unknown"] = Field(
        description="Dependency health status"
    )
    message: str | None = Field(
        default=None,
        description="Additional status information"
    )


class DependenciesHealthResponse(BaseModel):
    """Detailed health check with dependencies."""

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        description="Overall system health status"
    )
    service: str = Field(
        default="SecureMailScope API",
        description="Service name"
    )
    version: str = Field(
        default="0.5.0",
        description="Application version"
    )
    dependencies: list[DependencyStatus] = Field(
        description="Status of system dependencies"
    )
