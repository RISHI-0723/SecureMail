"""Report Models - Phase 4.

Pydantic models for report generation and structure.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
import uuid


class ReportFormat(str, Enum):
    """Report output formats."""
    JSON = "JSON"
    HTML = "HTML"
    PDF = "PDF"


class ReportStatus(str, Enum):
    """Report generation status."""
    QUEUED = "QUEUED"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


def generate_report_id() -> str:
    """Generate unique report ID."""
    return f"rep_{uuid.uuid4().hex[:12]}"


class ReportMetadata(BaseModel):
    """Report metadata."""
    report_id: str = Field(default_factory=generate_report_id)
    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    evidence_id: str
    job_id: str
    case_name: Optional[str] = None

    format: ReportFormat
    version: str = "1.0"

    # Generator info
    generator: str = "SecureMailScope"
    generator_version: str = "0.4.0-phase4"


class EvidenceSection(BaseModel):
    """Evidence information section."""
    evidence_id: str
    original_filename: str
    sha256: str
    file_size_bytes: int
    upload_timestamp: Optional[datetime] = None

    # Analysis metadata
    packets_analyzed: int = 0
    streams_analyzed: int = 0
    sessions_analyzed: int = 0
    certificates_analyzed: int = 0


class SecurityPostureSection(BaseModel):
    """Security posture summary section."""
    overall_score: float
    grade: str

    # Dimension scores
    tls_security_score: float
    certificate_security_score: float
    protocol_security_score: float
    configuration_security_score: float

    risk_factors: list[str] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)


class FindingSection(BaseModel):
    """Finding detail for report."""
    finding_id: str
    rule_id: str
    title: str
    description: str

    category: str
    severity: str
    confidence: str

    occurrence_count: int = 1
    affected_sessions: int = 0
    affected_certificates: int = 0

    remediation: Optional[str] = None


class RecommendationSection(BaseModel):
    """Recommendation detail for report."""
    recommendation_id: str
    priority: str
    category: str

    title: str
    description: str

    remediation_steps: list[str] = Field(default_factory=list)
    estimated_effort: Optional[str] = None

    compliance_references: Optional[dict[str, list[str]]] = None


class CorrelationSection(BaseModel):
    """Correlation detail for report."""
    correlation_id: str
    correlation_type: str
    strength: float

    title: str
    description: Optional[str] = None

    linked_findings: int = 0
    linked_sessions: int = 0


class MLSection(BaseModel):
    """ML insights section."""
    ml_enabled: bool = False
    model_version: Optional[str] = None

    anomalies_detected: int = 0
    top_anomalies: list[str] = Field(default_factory=list)
    confidence: float = 0.0

    summary: str = ""


class IntegritySection(BaseModel):
    """Evidence integrity section."""
    evidence_sha256: str
    evidence_sha512: Optional[str] = None
    analysis_hash: Optional[str] = None
    report_hash: Optional[str] = None

    # Blockchain anchoring (optional)
    blockchain_anchored: bool = False
    transaction_hash: Optional[str] = None
    anchor_timestamp: Optional[datetime] = None


class FullReport(BaseModel):
    """Complete forensic report structure."""
    metadata: ReportMetadata

    # Summary
    executive_summary: str

    # Evidence info
    evidence: EvidenceSection

    # Security posture
    security_posture: SecurityPostureSection

    # Findings (by severity)
    critical_findings: list[FindingSection] = Field(default_factory=list)
    high_findings: list[FindingSection] = Field(default_factory=list)
    medium_findings: list[FindingSection] = Field(default_factory=list)
    low_findings: list[FindingSection] = Field(default_factory=list)
    info_findings: list[FindingSection] = Field(default_factory=list)

    # Recommendations
    recommendations: list[RecommendationSection] = Field(default_factory=list)

    # Correlations
    correlations: list[CorrelationSection] = Field(default_factory=list)

    # ML insights (optional)
    ml_insights: Optional[MLSection] = None

    # Integrity
    integrity: IntegritySection

    # Limitations and notes
    limitations: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class GeneratedReportInfo(BaseModel):
    """Information about a generated report."""
    report_id: str
    format: ReportFormat
    status: ReportStatus

    filename: Optional[str] = None
    file_size_bytes: Optional[int] = None
    content_hash: Optional[str] = None

    generated_at: Optional[datetime] = None
    error_message: Optional[str] = None
