"""Analysis job schemas for API requests and responses."""
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

from app.models.analysis_job import JobStatus, JobType


class AnalysisJobResponse(BaseModel):
    """Response schema for analysis job."""
    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(description="Unique job identifier")
    evidence_id: str = Field(description="Associated evidence identifier")
    job_type: JobType = Field(description="Type of analysis job")
    status: JobStatus = Field(description="Current job status")
    created_at: datetime = Field(description="Job creation timestamp")
    started_at: datetime | None = Field(description="Job start timestamp")
    completed_at: datetime | None = Field(description="Job completion timestamp")
    error_code: str | None = Field(default=None, description="Error code if failed")
    error_message: str | None = Field(default=None, description="Error message if failed")
    progress_percent: str | None = Field(default=None, description="Progress percentage")
    stage: str | None = Field(default=None, description="Current processing stage")


class AnalysisJobListResponse(BaseModel):
    """Response schema for job listing."""
    jobs: list[AnalysisJobResponse] = Field(description="List of analysis jobs")
    total: int = Field(description="Total number of jobs")
