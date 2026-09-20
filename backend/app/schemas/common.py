"""Common schemas for API responses."""
from typing import Generic, TypeVar, Any
from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Error detail structure."""
    code: str = Field(description="Error code")
    message: str = Field(description="Human-readable error message")
    details: dict[str, Any] | None = Field(
        default=None,
        description="Additional error details"
    )


class ApiResponse(BaseModel, Generic[T]):
    """Generic API response wrapper."""
    success: bool = Field(description="Whether the request was successful")
    data: T | None = Field(default=None, description="Response data")
    error: ErrorDetail | None = Field(default=None, description="Error information")

    @classmethod
    def ok(cls, data: T) -> "ApiResponse[T]":
        """Create a successful response."""
        return cls(success=True, data=data, error=None)

    @classmethod
    def fail(cls, code: str, message: str, details: dict[str, Any] | None = None) -> "ApiResponse[T]":
        """Create a failed response."""
        return cls(
            success=False,
            data=None,
            error=ErrorDetail(code=code, message=message, details=details)
        )


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""
    items: list[T] = Field(description="List of items")
    total: int = Field(description="Total number of items")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Number of items per page")
    pages: int = Field(description="Total number of pages")
