"""Security finding models.

Phase 3: Evidence-backed security findings.

Each finding is traceable to specific evidence:
- TCP stream
- Email session
- TLS observation
- Certificate
- Packet numbers

Findings are deterministic - same evidence + same policy = same findings.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field

from app.services.crypto.rules import Severity, RuleCategory


class FindingStatus(str, Enum):
    """Finding lifecycle status."""
    ACTIVE = "ACTIVE"           # Current finding
    ACKNOWLEDGED = "ACKNOWLEDGED"  # User acknowledged
    RESOLVED = "RESOLVED"       # Issue fixed
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Marked as FP


class EvidenceType(str, Enum):
    """Types of evidence that support findings."""
    TCP_STREAM = "TCP_STREAM"
    EMAIL_SESSION = "EMAIL_SESSION"
    TLS_OBSERVATION = "TLS_OBSERVATION"
    CERTIFICATE = "CERTIFICATE"
    PACKET = "PACKET"
    PROTOCOL_DETECTION = "PROTOCOL_DETECTION"


class FindingEvidence(BaseModel):
    """
    Evidence supporting a security finding.

    Provides full traceability from finding to source evidence.
    """
    evidence_type: EvidenceType = Field(description="Type of evidence")
    reference_id: str = Field(description="ID of the evidence object")
    stream_id: Optional[int] = Field(default=None, description="TCP stream ID")
    packet_numbers: list[int] = Field(
        default_factory=list,
        description="Supporting packet numbers"
    )
    observed_value: Optional[Any] = Field(
        default=None,
        description="Value that triggered the finding"
    )
    expected_value: Optional[Any] = Field(
        default=None,
        description="Expected/policy value"
    )
    context: dict = Field(
        default_factory=dict,
        description="Additional context"
    )


class SecurityFinding(BaseModel):
    """
    Security finding with full evidence traceability.

    Every finding must be:
    1. Traceable to evidence
    2. Deterministic
    3. Explainable
    """
    finding_id: str = Field(description="Unique finding identifier")
    rule_id: str = Field(description="Rule that generated this finding")

    # Classification
    title: str = Field(description="Human-readable title")
    description: str = Field(description="Detailed description")
    category: RuleCategory = Field(description="Finding category")
    severity: Severity = Field(description="Finding severity")

    # Evidence
    evidence: list[FindingEvidence] = Field(
        default_factory=list,
        description="Supporting evidence"
    )

    # Context
    evidence_id: str = Field(description="PCAP evidence ID")
    job_id: str = Field(description="Analysis job ID")
    session_id: Optional[str] = Field(
        default=None,
        description="Related email session ID"
    )
    stream_id: Optional[int] = Field(
        default=None,
        description="Related TCP stream ID"
    )
    certificate_id: Optional[str] = Field(
        default=None,
        description="Related certificate ID"
    )

    # Metadata
    status: FindingStatus = Field(
        default=FindingStatus.ACTIVE,
        description="Finding status"
    )
    confidence: str = Field(
        default="HIGH",
        description="Finding confidence"
    )
    first_observed: Optional[datetime] = Field(
        default=None,
        description="When the issue was first observed"
    )

    # Remediation
    remediation: str = Field(
        default="",
        description="Remediation guidance"
    )

    # Aggregation
    occurrence_count: int = Field(
        default=1,
        description="Number of occurrences (for deduplication)"
    )
    affected_streams: list[int] = Field(
        default_factory=list,
        description="All affected stream IDs"
    )


class FindingSummary(BaseModel):
    """Summary statistics for findings."""
    total_findings: int = Field(default=0, description="Total findings")
    critical_count: int = Field(default=0, description="Critical findings")
    high_count: int = Field(default=0, description="High findings")
    medium_count: int = Field(default=0, description="Medium findings")
    low_count: int = Field(default=0, description="Low findings")
    info_count: int = Field(default=0, description="Informational findings")

    # By category
    by_category: dict[str, int] = Field(
        default_factory=dict,
        description="Findings by category"
    )

    # Unique rules triggered
    unique_rules: list[str] = Field(
        default_factory=list,
        description="Unique rule IDs triggered"
    )


class FindingsResult(BaseModel):
    """Complete findings result for an analysis job."""
    evidence_id: str = Field(description="Evidence identifier")
    job_id: str = Field(description="Analysis job identifier")

    # Findings
    findings: list[SecurityFinding] = Field(
        default_factory=list,
        description="All security findings"
    )

    # Summary
    summary: FindingSummary = Field(
        default_factory=FindingSummary,
        description="Findings summary"
    )

    # Analysis metadata
    rules_evaluated: int = Field(
        default=0,
        description="Number of rules evaluated"
    )
    streams_analyzed: int = Field(
        default=0,
        description="Number of streams analyzed"
    )
    sessions_analyzed: int = Field(
        default=0,
        description="Number of sessions analyzed"
    )
    certificates_analyzed: int = Field(
        default=0,
        description="Number of certificates analyzed"
    )

    # Deduplication
    raw_matches: int = Field(
        default=0,
        description="Raw rule matches before deduplication"
    )
    deduplicated_findings: int = Field(
        default=0,
        description="Findings after deduplication"
    )
