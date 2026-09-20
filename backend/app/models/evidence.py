"""Evidence model for PCAP/PCAPNG files."""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Text, DateTime, Enum, BigInteger,
    ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class EvidenceStatus(str, PyEnum):
    """Enumeration of evidence statuses."""
    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    INVALID = "INVALID"
    STORED = "STORED"
    FAILED = "FAILED"


class FileFormat(str, PyEnum):
    """Supported capture file formats."""
    PCAP = "pcap"
    PCAPNG = "pcapng"
    UNKNOWN = "unknown"


def generate_evidence_id() -> str:
    """Generate a unique evidence ID with prefix."""
    return f"ev_{uuid.uuid4().hex[:12]}"


def generate_storage_key() -> str:
    """Generate a unique storage key for the file."""
    return uuid.uuid4().hex


class PcapEvidence(Base):
    """
    Evidence entity representing a PCAP/PCAPNG file.

    Stores metadata about uploaded evidence files including
    hash, validation status, and storage location.
    """
    __tablename__ = "pcap_evidence"

    evidence_id = Column(
        String(50),
        primary_key=True,
        default=generate_evidence_id,
        index=True
    )
    case_id = Column(
        String(50),
        ForeignKey("cases.case_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    original_filename = Column(String(512), nullable=False)
    stored_filename = Column(String(128), nullable=False, unique=True)
    file_format = Column(
        Enum(FileFormat, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=FileFormat.UNKNOWN
    )
    file_size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    mime_type = Column(String(128), nullable=True)
    upload_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    status = Column(
        Enum(EvidenceStatus),
        nullable=False,
        default=EvidenceStatus.PENDING,
        index=True
    )
    storage_location = Column(String(1024), nullable=True)
    validation_status = Column(String(50), nullable=True)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    case = relationship("Case", back_populates="evidence")
    analysis_jobs = relationship(
        "AnalysisJob",
        back_populates="evidence",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_evidence_case_status", "case_id", "status"),
        Index("ix_evidence_sha256_case", "sha256", "case_id"),
    )

    def __repr__(self) -> str:
        return f"<PcapEvidence(evidence_id={self.evidence_id}, filename={self.original_filename}, sha256={self.sha256[:16]}...)>"
