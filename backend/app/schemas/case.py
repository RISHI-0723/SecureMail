"""Case schemas for API requests and responses."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

from app.models.case import CaseStatus


class CaseCreate(BaseModel):
    """Request schema for creating a case."""
    case_name: str = Field(
        min_length=1,
        max_length=255,
        description="Name of the forensic case"
    )
    description: str | None = Field(
        default=None,
        max_length=5000,
        description="Detailed description of the case"
    )


class CaseUpdate(BaseModel):
    """Request schema for updating a case."""
    case_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Updated case name"
    )
    description: str | None = Field(
        default=None,
        max_length=5000,
        description="Updated description"
    )
    status: CaseStatus | None = Field(
        default=None,
        description="Updated case status"
    )


class CaseResponse(BaseModel):
    """Response schema for a single case."""
    model_config = ConfigDict(from_attributes=True)

    case_id: str = Field(description="Unique case identifier")
    case_name: str = Field(description="Name of the case")
    description: str | None = Field(description="Case description")
    status: CaseStatus = Field(description="Current case status")
    created_at: datetime = Field(description="Case creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")


class CaseWithEvidenceCount(CaseResponse):
    """Case response including evidence count."""
    evidence_count: int = Field(
        default=0,
        description="Number of evidence files in this case"
    )


class CaseListResponse(BaseModel):
    """Response schema for case listing."""
    cases: list[CaseWithEvidenceCount] = Field(description="List of cases")
    total: int = Field(description="Total number of cases")
