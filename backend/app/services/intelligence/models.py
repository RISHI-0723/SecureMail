"""Phase 4 Intelligence Models.

Pydantic models for intelligence aggregation, correlations,
and recommendations.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


class CorrelationType(str, Enum):
    """Types of security correlations."""
    SAME_CERTIFICATE = "SAME_CERTIFICATE"
    SAME_CIPHER_WEAKNESS = "SAME_CIPHER_WEAKNESS"
    SAME_TLS_VERSION = "SAME_TLS_VERSION"
    SAME_KEY_EXCHANGE = "SAME_KEY_EXCHANGE"
    SAME_SERVER = "SAME_SERVER"
    TEMPORAL_PATTERN = "TEMPORAL_PATTERN"
    RISK_ESCALATION = "RISK_ESCALATION"


class RecommendationPriority(str, Enum):
    """Priority levels for recommendations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RecommendationCategory(str, Enum):
    """Categories for recommendations."""
    TLS_UPGRADE = "TLS_UPGRADE"
    CIPHER_UPGRADE = "CIPHER_UPGRADE"
    CERTIFICATE_RENEWAL = "CERTIFICATE_RENEWAL"
    KEY_ROTATION = "KEY_ROTATION"
    CONFIGURATION = "CONFIGURATION"
    MONITORING = "MONITORING"
    COMPLIANCE = "COMPLIANCE"


class SecurityPostureGrade(str, Enum):
    """Security posture grades."""
    A = "A"  # Excellent (90-100)
    B = "B"  # Good (80-89)
    C = "C"  # Fair (70-79)
    D = "D"  # Poor (60-69)
    F = "F"  # Critical (<60)


def generate_correlation_id() -> str:
    """Generate unique correlation ID."""
    return f"corr_{uuid.uuid4().hex[:12]}"


def generate_recommendation_id() -> str:
    """Generate unique recommendation ID."""
    return f"rec_{uuid.uuid4().hex[:12]}"


class CorrelationData(BaseModel):
    """Data model for a security correlation."""
    correlation_id: str = Field(default_factory=generate_correlation_id)
    correlation_type: CorrelationType
    strength: float = Field(ge=0.0, le=1.0, default=1.0)
    confidence: str = "MEDIUM"

    title: str
    description: Optional[str] = None

    linked_findings: list[str] = Field(default_factory=list)
    linked_sessions: list[str] = Field(default_factory=list)
    linked_certificates: list[str] = Field(default_factory=list)
    linked_streams: list[int] = Field(default_factory=list)

    common_attribute: Optional[str] = None
    common_value: Optional[str] = None

    combined_severity: Optional[str] = None
    combined_risk_score: Optional[float] = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RecommendationData(BaseModel):
    """Data model for a security recommendation."""
    recommendation_id: str = Field(default_factory=generate_recommendation_id)
    priority: RecommendationPriority
    category: RecommendationCategory

    title: str
    description: str

    remediation_steps: list[str] = Field(default_factory=list)
    estimated_effort: Optional[str] = None  # Low/Medium/High
    technical_impact: Optional[str] = None
    business_impact: Optional[str] = None

    affected_findings: list[str] = Field(default_factory=list)
    affected_sessions: list[str] = Field(default_factory=list)
    affected_certificates: list[str] = Field(default_factory=list)

    compliance_references: Optional[dict[str, list[str]]] = None

    status: str = "OPEN"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DimensionScore(BaseModel):
    """Score for a security dimension."""
    dimension: str
    score: float = Field(ge=0.0, le=100.0)
    weight: float = Field(ge=0.0, le=1.0, default=0.25)
    findings_count: int = 0
    critical_issues: int = 0
    details: Optional[str] = None


class SecurityPosture(BaseModel):
    """Overall security posture assessment."""
    overall_score: float = Field(ge=0.0, le=100.0)
    grade: SecurityPostureGrade

    tls_security: DimensionScore
    certificate_security: DimensionScore
    protocol_security: DimensionScore
    configuration_security: DimensionScore

    risk_factors: list[str] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)

    confidence: str = "HIGH"


class AggregatedFinding(BaseModel):
    """Aggregated finding with occurrence tracking."""
    finding_id: str
    rule_id: str
    title: str
    description: str
    category: str
    severity: str

    occurrence_count: int = 1
    affected_streams: list[int] = Field(default_factory=list)
    affected_sessions: list[str] = Field(default_factory=list)
    affected_certificates: list[str] = Field(default_factory=list)

    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    remediation: Optional[str] = None
    confidence: str = "HIGH"


class IntelligenceSummary(BaseModel):
    """Intelligence report summary."""
    evidence_id: str
    job_id: str

    # Posture
    security_posture: SecurityPosture

    # Aggregated data
    total_findings: int = 0
    total_correlations: int = 0
    total_recommendations: int = 0

    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Categories
    findings_by_category: dict[str, int] = Field(default_factory=dict)

    # Executive summary
    executive_summary: str = ""

    # ML insights (if enabled)
    ml_enabled: bool = False
    anomalies_detected: int = 0
    ml_confidence: Optional[float] = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntelligenceResult(BaseModel):
    """Complete intelligence analysis result."""
    evidence_id: str
    job_id: str
    security_analysis_id: Optional[str] = None

    summary: IntelligenceSummary
    aggregated_findings: list[AggregatedFinding] = Field(default_factory=list)
    correlations: list[CorrelationData] = Field(default_factory=list)
    recommendations: list[RecommendationData] = Field(default_factory=list)

    # Raw Phase 3 data references
    streams_analyzed: int = 0
    sessions_analyzed: int = 0
    certificates_analyzed: int = 0

    # Processing metadata
    processing_time_seconds: Optional[float] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
