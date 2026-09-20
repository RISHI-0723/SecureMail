"""Packet analysis model for Phase 2 results.

Stores packet analysis summaries and protocol detection results.
This model captures aggregate results - not individual packet records.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, DateTime, Integer, Float,
    ForeignKey, Index, JSON
)
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_analysis_id() -> str:
    """Generate a unique packet analysis ID with prefix."""
    return f"pa_{uuid.uuid4().hex[:12]}"


class PacketAnalysis(Base):
    """
    Packet analysis results for Phase 2.

    Stores aggregate packet counts, protocol detection results,
    and session candidates for an evidence file.

    This table stores summary-level data, not individual packets.
    For large captures, storing every packet would be prohibitive.
    """
    __tablename__ = "packet_analyses"

    analysis_id = Column(
        String(50),
        primary_key=True,
        default=generate_analysis_id,
        index=True
    )
    job_id = Column(
        String(50),
        ForeignKey("analysis_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One analysis per job
        index=True
    )
    evidence_id = Column(
        String(50),
        ForeignKey("pcap_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # TShark metadata
    tshark_version = Column(String(50), nullable=True)
    analysis_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    duration_seconds = Column(Float, nullable=True)

    # Packet counts
    total_packets = Column(Integer, nullable=False, default=0)
    email_packets = Column(Integer, nullable=False, default=0)
    smtp_packets = Column(Integer, nullable=False, default=0)
    imap_packets = Column(Integer, nullable=False, default=0)
    pop3_packets = Column(Integer, nullable=False, default=0)
    tls_packets = Column(Integer, nullable=False, default=0)
    other_packets = Column(Integer, nullable=False, default=0)

    # JSON fields for flexible storage
    # List of protocol names detected: ["SMTP", "IMAP", "POP3"]
    protocols_detected = Column(JSON, nullable=False, default=list)

    # List of ProtocolDetection objects as dicts
    protocol_detections = Column(JSON, nullable=False, default=list)

    # List of ProtocolSessionCandidate objects as dicts
    session_candidates = Column(JSON, nullable=False, default=list)

    # Status message
    message = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    job = relationship("AnalysisJob", backref="packet_analysis", uselist=False)
    evidence = relationship("PcapEvidence", backref="packet_analyses")

    # Note: Indexes are created via index=True on columns above
    # No __table_args__ needed as individual column indexes suffice

    def __repr__(self) -> str:
        return (
            f"<PacketAnalysis(analysis_id={self.analysis_id}, "
            f"job_id={self.job_id}, total_packets={self.total_packets})>"
        )
