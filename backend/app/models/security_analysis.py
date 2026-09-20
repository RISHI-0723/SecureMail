"""Security analysis model for Phase 3 results.

Phase 3: Security Intelligence Engine Results

This model stores the complete Phase 3 analysis:
- TCP stream data
- Email security sessions
- TLS observations
- Certificate observations
- Security findings
- Risk assessment

Data is stored as JSON for flexibility while maintaining
traceability through job_id and evidence_id.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Text, DateTime, Integer, Float,
    ForeignKey, Index, JSON, Enum
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class SecurityAnalysisStatus(str, PyEnum):
    """Status of security analysis."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


def generate_security_analysis_id() -> str:
    """Generate a unique security analysis ID with prefix."""
    return f"sa_{uuid.uuid4().hex[:12]}"


class SecurityAnalysis(Base):
    """
    Phase 3 security analysis results.

    Stores all Phase 3 analysis data including:
    - TCP stream reconstruction
    - Email security sessions
    - TLS observations
    - Certificate observations
    - Security findings
    - Risk assessment

    All complex data is stored as JSON for flexibility.
    This allows the schema to evolve without migrations.
    """
    __tablename__ = "security_analyses"

    analysis_id = Column(
        String(50),
        primary_key=True,
        default=generate_security_analysis_id,
        index=True
    )
    job_id = Column(
        String(50),
        ForeignKey("analysis_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One security analysis per job
        index=True
    )
    evidence_id = Column(
        String(50),
        ForeignKey("pcap_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    packet_analysis_id = Column(
        String(50),
        ForeignKey("packet_analyses.analysis_id", ondelete="CASCADE"),
        nullable=True,  # May not have Phase 2 analysis
        index=True
    )

    # Analysis status
    status = Column(
        Enum(SecurityAnalysisStatus),
        nullable=False,
        default=SecurityAnalysisStatus.QUEUED,
        index=True
    )

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Analysis counts (for quick queries without parsing JSON)
    total_streams = Column(Integer, nullable=False, default=0)
    total_sessions = Column(Integer, nullable=False, default=0)
    total_tls_observations = Column(Integer, nullable=False, default=0)
    total_certificates = Column(Integer, nullable=False, default=0)
    total_findings = Column(Integer, nullable=False, default=0)

    # Finding severity counts
    critical_findings = Column(Integer, nullable=False, default=0)
    high_findings = Column(Integer, nullable=False, default=0)
    medium_findings = Column(Integer, nullable=False, default=0)
    low_findings = Column(Integer, nullable=False, default=0)
    info_findings = Column(Integer, nullable=False, default=0)

    # Risk assessment summary
    overall_risk_level = Column(String(20), nullable=True)
    overall_risk_score = Column(Float, nullable=True)

    # Analysis confidence and coverage
    confidence = Column(String(20), nullable=True, default="UNKNOWN")
    coverage = Column(String(20), nullable=True, default="UNKNOWN")

    # JSON fields for detailed results
    # TCP stream reconstruction result
    tcp_streams = Column(JSON, nullable=False, default=list)

    # Email security sessions result
    email_sessions = Column(JSON, nullable=False, default=list)

    # TLS observations
    tls_observations = Column(JSON, nullable=False, default=list)

    # Certificate observations
    certificates = Column(JSON, nullable=False, default=list)

    # Security findings with evidence
    findings = Column(JSON, nullable=False, default=list)

    # Complete risk assessment
    risk_assessment = Column(JSON, nullable=True)

    # Error information
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)

    # Policy version used
    policy_version = Column(String(20), nullable=True, default="1.0.0")

    # Relationships
    job = relationship("AnalysisJob", backref="security_analysis", uselist=False)
    evidence = relationship("PcapEvidence", backref="security_analyses")
    packet_analysis = relationship(
        "PacketAnalysis",
        backref="security_analysis",
        uselist=False
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_security_analysis_evidence_status", "evidence_id", "status"),
        Index("ix_security_analysis_risk", "overall_risk_level", "overall_risk_score"),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityAnalysis(analysis_id={self.analysis_id}, "
            f"job_id={self.job_id}, status={self.status}, "
            f"findings={self.total_findings})>"
        )
