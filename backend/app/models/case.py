"""Case model for forensic investigations."""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import Column, String, Text, DateTime, Enum, Index
from sqlalchemy.orm import relationship
from app.core.database import Base


class CaseStatus(str, PyEnum):
    """Enumeration of case statuses."""
    OPEN = "OPEN"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    ARCHIVED = "ARCHIVED"


def generate_case_id() -> str:
    """Generate a unique case ID with prefix."""
    return f"case_{uuid.uuid4().hex[:12]}"


class Case(Base):
    """
    Case entity representing a forensic investigation.

    A case is the parent entity for evidence files and provides
    organizational structure for forensic analysis.
    """
    __tablename__ = "cases"

    case_id = Column(
        String(50),
        primary_key=True,
        default=generate_case_id,
        index=True
    )
    case_name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(
        Enum(CaseStatus),
        nullable=False,
        default=CaseStatus.OPEN,
        index=True
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    evidence = relationship(
        "PcapEvidence",
        back_populates="case",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_cases_status_created", "status", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Case(case_id={self.case_id}, name={self.case_name}, status={self.status})>"
