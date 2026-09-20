"""Evidence schemas for API requests and responses."""
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

from app.models.evidence import EvidenceStatus, FileFormat


class EvidenceResponse(BaseModel):
    """Response schema for evidence metadata."""
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str = Field(description="Unique evidence identifier")
    case_id: str = Field(description="Associated case identifier")
    original_filename: str = Field(description="Original uploaded filename")
    file_format: FileFormat = Field(description="Detected file format")
    file_size_bytes: int = Field(description="File size in bytes")
    sha256: str = Field(description="SHA-256 hash of the file")
    upload_timestamp: datetime = Field(description="Upload timestamp")
    status: EvidenceStatus = Field(description="Evidence processing status")
    error_code: str | None = Field(default=None, description="Error code if failed")
    error_message: str | None = Field(default=None, description="Error message if failed")
    created_at: datetime = Field(description="Record creation timestamp")
    updated_at: datetime = Field(description="Last update timestamp")


class EvidenceUploadResponse(BaseModel):
    """Response schema for evidence upload."""
    evidence_id: str = Field(description="Unique evidence identifier")
    case_id: str = Field(description="Associated case identifier")
    original_filename: str = Field(description="Original uploaded filename")
    file_size_bytes: int = Field(description="File size in bytes")
    file_format: FileFormat = Field(description="Detected file format")
    sha256: str = Field(description="SHA-256 hash of the file")
    evidence_status: EvidenceStatus = Field(description="Evidence processing status")
    analysis_job_id: str = Field(description="Created analysis job identifier")
    analysis_status: str = Field(description="Analysis job status")


class EvidenceListResponse(BaseModel):
    """Response schema for evidence listing."""
    evidence: list[EvidenceResponse] = Field(description="List of evidence")
    total: int = Field(description="Total number of evidence files")


class DuplicateEvidenceResponse(BaseModel):
    """Response for duplicate evidence detection."""
    is_duplicate: bool = Field(description="Whether this is duplicate evidence")
    existing_evidence_id: str = Field(description="ID of existing evidence with same hash")
    existing_case_id: str = Field(description="ID of case containing existing evidence")
    sha256: str = Field(description="SHA-256 hash of the duplicate")
