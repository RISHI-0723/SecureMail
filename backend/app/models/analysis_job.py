"""Analysis job model for forensic processing tasks."""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Text, DateTime, Enum,
    ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class JobStatus(str, PyEnum):
    """Enumeration of analysis job statuses."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class JobType(str, PyEnum):
    """Types of analysis jobs."""
    FULL_ANALYSIS = "FULL_ANALYSIS"
    PROTOCOL_DETECTION = "PROTOCOL_DETECTION"
    TLS_ANALYSIS = "TLS_ANALYSIS"
    CERTIFICATE_ANALYSIS = "CERTIFICATE_ANALYSIS"
    SECURITY_ANALYSIS = "SECURITY_ANALYSIS"  # Phase 3
    INTELLIGENCE = "INTELLIGENCE"  # Phase 4


def generate_job_id() -> str:
    """Generate a unique job ID with prefix."""
    return f"job_{uuid.uuid4().hex[:12]}"


class AnalysisJob(Base):
    """
    Analysis job entity representing a forensic processing task.

    Jobs are created when evidence is uploaded and track the
    progress of forensic analysis through the pipeline.
    """
    __tablename__ = "analysis_jobs"

    job_id = Column(
        String(50),
        primary_key=True,
        default=generate_job_id,
        index=True
    )
    evidence_id = Column(
        String(50),
        ForeignKey("pcap_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    job_type = Column(
        Enum(JobType),
        nullable=False,
        default=JobType.FULL_ANALYSIS
    )
    status = Column(
        Enum(JobStatus),
        nullable=False,
        default=JobStatus.QUEUED,
        index=True
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    progress_percent = Column(String(10), nullable=True, default="0")
    stage = Column(String(100), nullable=True)

    # Relationships
    evidence = relationship("PcapEvidence", back_populates="analysis_jobs")

    # Indexes for common queries
    __table_args__ = (
        Index("ix_jobs_evidence_status", "evidence_id", "status"),
        Index("ix_jobs_status_created", "status", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AnalysisJob(job_id={self.job_id}, evidence_id={self.evidence_id}, status={self.status})>"
