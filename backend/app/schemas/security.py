"""Phase 3 Security Analysis API schemas.

Schemas for security analysis endpoints including:
- Security analysis status
- TCP streams
- Email sessions
- TLS observations
- Certificates
- Security findings
- Risk assessment
"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


# ============================================================
# Security Analysis Overview
# ============================================================

class SecurityAnalysisSummaryResponse(BaseModel):
    """Security analysis summary response."""
    analysis_id: str = Field(description="Security analysis identifier")
    job_id: str = Field(description="Analysis job identifier")
    evidence_id: str = Field(description="Evidence identifier")
    status: str = Field(description="Analysis status")

    # Timestamps
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Counts
    total_streams: int = Field(default=0)
    total_sessions: int = Field(default=0)
    total_tls_observations: int = Field(default=0)
    total_certificates: int = Field(default=0)
    total_findings: int = Field(default=0)

    # Finding severities
    critical_findings: int = Field(default=0)
    high_findings: int = Field(default=0)
    medium_findings: int = Field(default=0)
    low_findings: int = Field(default=0)
    info_findings: int = Field(default=0)

    # Risk
    overall_risk_level: Optional[str] = None
    overall_risk_score: Optional[float] = None

    # Metadata
    confidence: Optional[str] = None
    coverage: Optional[str] = None
    policy_version: Optional[str] = None


# ============================================================
# TCP Streams
# ============================================================

class TcpStreamResponse(BaseModel):
    """TCP stream response."""
    stream_id: int = Field(description="TCP stream identifier")
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None

    integrity: str = Field(description="Stream integrity status")
    packet_count: int = Field(default=0)
    byte_count: int = Field(default=0)

    has_fin: bool = Field(default=False)
    has_rst: bool = Field(default=False)
    termination_type: Optional[str] = None

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class TcpStreamsResponse(BaseModel):
    """TCP streams list response."""
    streams: list[TcpStreamResponse] = Field(default_factory=list)
    total: int = Field(default=0)
    complete_count: int = Field(default=0)
    partial_count: int = Field(default=0)


# ============================================================
# Email Sessions
# ============================================================

class EmailSessionResponse(BaseModel):
    """Email security session response."""
    session_id: str = Field(description="Session identifier")
    stream_id: int = Field(description="TCP stream ID")
    protocol: str = Field(description="Email protocol")

    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None

    transport_security: str = Field(description="Transport security mode")
    starttls_advertised: bool = Field(default=False)
    starttls_state: str = Field(default="NONE")
    tls_detected: bool = Field(default=False)
    implicit_tls: bool = Field(default=False)

    confidence: str = Field(default="UNKNOWN")
    coverage: str = Field(default="UNKNOWN")


class EmailSessionsResponse(BaseModel):
    """Email sessions list response."""
    sessions: list[EmailSessionResponse] = Field(default_factory=list)
    total: int = Field(default=0)
    by_protocol: dict[str, int] = Field(default_factory=dict)
    by_transport_security: dict[str, int] = Field(default_factory=dict)


# ============================================================
# TLS Observations
# ============================================================

class TlsObservationResponse(BaseModel):
    """TLS observation response."""
    observation_id: str = Field(description="Observation identifier")
    session_id: Optional[str] = None
    stream_id: int = Field(description="TCP stream ID")

    tls_version: Optional[str] = None
    tls_version_security: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    has_forward_secrecy: bool = Field(default=False)

    handshake_status: str = Field(default="UNKNOWN")
    handshake_timestamp: Optional[datetime] = None

    sni: Optional[str] = None
    alpn: Optional[str] = None

    confidence: str = Field(default="UNKNOWN")
    coverage: str = Field(default="UNKNOWN")


class TlsObservationsResponse(BaseModel):
    """TLS observations list response."""
    observations: list[TlsObservationResponse] = Field(default_factory=list)
    total: int = Field(default=0)
    by_version: dict[str, int] = Field(default_factory=dict)
    modern_tls_count: int = Field(default=0)
    deprecated_tls_count: int = Field(default=0)


# ============================================================
# Certificates
# ============================================================

class CertificateResponse(BaseModel):
    """Certificate observation response."""
    certificate_id: str = Field(description="Certificate identifier")
    stream_id: int = Field(description="TCP stream ID")

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None

    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    validity: str = Field(default="UNKNOWN")

    key_type: Optional[str] = None
    key_size_bits: Optional[int] = None
    key_strength: str = Field(default="UNKNOWN")

    signature_algorithm: Optional[str] = None
    signature_algorithm_security: str = Field(default="UNKNOWN")

    is_self_signed: Optional[bool] = None
    subject_alt_names: list[str] = Field(default_factory=list)

    confidence: str = Field(default="UNKNOWN")
    parse_status: Optional[str] = None


class CertificatesResponse(BaseModel):
    """Certificates list response."""
    certificates: list[CertificateResponse] = Field(default_factory=list)
    total: int = Field(default=0)
    valid_count: int = Field(default=0)
    expired_count: int = Field(default=0)
    weak_key_count: int = Field(default=0)
    self_signed_count: int = Field(default=0)


# ============================================================
# Security Findings
# ============================================================

class FindingEvidenceResponse(BaseModel):
    """Finding evidence response."""
    evidence_type: str = Field(description="Type of evidence")
    reference_id: str = Field(description="Reference identifier")
    stream_id: Optional[int] = None
    observed_value: Optional[Any] = None
    expected_value: Optional[Any] = None


class FindingResponse(BaseModel):
    """Security finding response."""
    finding_id: str = Field(description="Finding identifier")
    rule_id: str = Field(description="Rule identifier")

    title: str = Field(description="Finding title")
    description: str = Field(description="Finding description")
    category: str = Field(description="Finding category")
    severity: str = Field(description="Finding severity")

    evidence: list[FindingEvidenceResponse] = Field(default_factory=list)

    session_id: Optional[str] = None
    stream_id: Optional[int] = None
    certificate_id: Optional[str] = None

    confidence: str = Field(default="HIGH")
    remediation: str = Field(default="")

    occurrence_count: int = Field(default=1)
    affected_streams: list[int] = Field(default_factory=list)


class FindingsResponse(BaseModel):
    """Findings list response."""
    findings: list[FindingResponse] = Field(default_factory=list)
    total: int = Field(default=0)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    unique_rules: list[str] = Field(default_factory=list)


# ============================================================
# Risk Assessment
# ============================================================

class DimensionScoreResponse(BaseModel):
    """Security dimension score response."""
    dimension: str = Field(description="Security dimension")
    score: float = Field(description="Score 0-100")
    risk_level: str = Field(description="Risk level")
    findings_count: int = Field(default=0)
    description: str = Field(default="")


class RiskAssessmentResponse(BaseModel):
    """Risk assessment response."""
    overall_score: float = Field(description="Overall security score 0-100")
    overall_risk: str = Field(description="Overall risk level")

    dimensions: list[DimensionScoreResponse] = Field(default_factory=list)

    confidence: str = Field(default="UNKNOWN")
    coverage: str = Field(default="UNKNOWN")

    summary: str = Field(default="")
    key_findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    assessment_version: str = Field(default="1.0.0")
    policy_version: str = Field(default="1.0.0")


# ============================================================
# Trigger Security Analysis
# ============================================================

class TriggerSecurityAnalysisRequest(BaseModel):
    """Request to trigger security analysis."""
    packet_analysis_id: Optional[str] = Field(
        default=None,
        description="Optional Phase 2 analysis ID to use"
    )


class TriggerSecurityAnalysisResponse(BaseModel):
    """Response for triggering security analysis."""
    job_id: str = Field(description="Analysis job identifier")
    status: str = Field(description="Trigger status")
    message: str = Field(description="Status message")
