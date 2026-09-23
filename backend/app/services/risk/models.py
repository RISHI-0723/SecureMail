"""Risk assessment models.

Phase 3: Deterministic risk calculation models.

Risk assessment is based on:
1. Finding severity distribution
2. Security dimensions (TLS, cert, protocol, config)
3. Coverage and confidence metadata

The scoring formula is documented and deterministic.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from app.services.crypto.rules import Severity


class RiskLevel(str, Enum):
    """Overall risk level classification."""
    CRITICAL = "CRITICAL"   # Immediate action required
    HIGH = "HIGH"           # Significant risk
    MEDIUM = "MEDIUM"       # Moderate risk
    LOW = "LOW"             # Minor risk
    MINIMAL = "MINIMAL"     # Very low risk
    UNKNOWN = "UNKNOWN"     # Insufficient data


class SecurityDimension(str, Enum):
    """Security assessment dimensions."""
    TLS_SECURITY = "TLS_SECURITY"
    CERTIFICATE_SECURITY = "CERTIFICATE_SECURITY"
    PROTOCOL_SECURITY = "PROTOCOL_SECURITY"
    CONFIGURATION_SECURITY = "CONFIGURATION_SECURITY"


class DimensionScore(BaseModel):
    """Score for a single security dimension."""
    dimension: SecurityDimension = Field(description="Security dimension")
    score: float = Field(
        ge=0.0, le=100.0,
        description="Score 0-100 (higher is better)"
    )
    risk_level: RiskLevel = Field(description="Risk level for dimension")
    findings_count: int = Field(
        default=0,
        description="Number of findings affecting this dimension"
    )
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    description: str = Field(
        default="",
        description="Human-readable assessment"
    )


class SecurityPosture(BaseModel):
    """
    Overall security posture assessment.

    The overall score is calculated as:
    score = 100 - (critical_penalty + high_penalty + medium_penalty + low_penalty)

    Where:
    - critical_penalty = critical_count * 25 (capped at 100)
    - high_penalty = high_count * 15
    - medium_penalty = medium_count * 5
    - low_penalty = low_count * 1

    This formula is deterministic and explainable.

    Note: overall_score can be None when there's insufficient evidence to assess
    (e.g., no email traffic detected in a non-email PCAP).
    """
    overall_score: Optional[float] = Field(
        None,
        ge=0.0, le=100.0,
        description="Overall security score 0-100, or null if cannot assess"
    )
    overall_risk: RiskLevel = Field(description="Overall risk level")

    # Dimension scores
    dimensions: list[DimensionScore] = Field(
        default_factory=list,
        description="Per-dimension scores"
    )

    # Score breakdown
    score_breakdown: dict = Field(
        default_factory=dict,
        description="Detailed score calculation"
    )

    # Assessment metadata
    confidence: str = Field(
        default="HIGH",
        description="Assessment confidence"
    )
    coverage: str = Field(
        default="COMPLETE",
        description="Analysis coverage"
    )

    # Human-readable summary
    summary: str = Field(
        default="",
        description="Human-readable posture summary"
    )
    key_findings: list[str] = Field(
        default_factory=list,
        description="Key findings summary"
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Priority recommendations"
    )


class RiskAssessment(BaseModel):
    """Complete risk assessment result."""
    evidence_id: str = Field(description="Evidence identifier")
    job_id: str = Field(description="Analysis job identifier")

    # Security posture
    posture: SecurityPosture = Field(description="Security posture assessment")

    # Input statistics
    total_findings: int = Field(default=0)
    total_streams: int = Field(default=0)
    total_sessions: int = Field(default=0)
    total_certificates: int = Field(default=0)

    # Analysis metadata
    assessment_version: str = Field(
        default="1.0.0",
        description="Risk assessment algorithm version"
    )
    policy_version: str = Field(
        default="1.0.0",
        description="Security policy version used"
    )
