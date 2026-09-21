"""Phase 4 Intelligence API Schemas.

Pydantic schemas for intelligence analysis API endpoints.
"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


class IntelligenceSummaryResponse(BaseModel):
    """Intelligence analysis summary response."""
    report_id: str
    evidence_id: str
    security_analysis_id: Optional[str] = None
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Counts
    total_correlations: int = 0
    total_recommendations: int = 0
    ml_enabled: bool = False
    ml_predictions_count: int = 0
    anomalies_detected: int = 0

    # Posture
    security_posture_score: Optional[float] = None
    security_posture_grade: Optional[str] = None
    tls_security_score: Optional[float] = None
    certificate_security_score: Optional[float] = None
    protocol_security_score: Optional[float] = None
    configuration_security_score: Optional[float] = None

    executive_summary: Optional[str] = None


class SecurityPostureResponse(BaseModel):
    """Security posture response."""
    overall_score: float
    grade: str
    tls_security_score: float
    certificate_security_score: float
    protocol_security_score: float
    configuration_security_score: float
    aggregated_findings: list[dict] = Field(default_factory=list)
    correlation_summary: dict = Field(default_factory=dict)
    recommendation_summary: dict = Field(default_factory=dict)


class CorrelationResponse(BaseModel):
    """Single correlation response."""
    correlation_id: str
    correlation_type: str
    strength: float
    confidence: str
    title: str
    description: Optional[str] = None
    linked_findings: list[str] = Field(default_factory=list)
    linked_sessions: list[str] = Field(default_factory=list)
    linked_certificates: list[str] = Field(default_factory=list)
    common_attribute: Optional[str] = None
    common_value: Optional[str] = None
    combined_severity: Optional[str] = None
    combined_risk_score: Optional[float] = None
    created_at: datetime


class CorrelationsResponse(BaseModel):
    """Correlations list response."""
    total: int
    correlations: list[CorrelationResponse] = Field(default_factory=list)


class RecommendationResponse(BaseModel):
    """Single recommendation response."""
    recommendation_id: str
    priority: str
    category: str
    title: str
    description: str
    remediation_steps: list[str] = Field(default_factory=list)
    estimated_effort: Optional[str] = None
    technical_impact: Optional[str] = None
    business_impact: Optional[str] = None
    affected_findings: list[str] = Field(default_factory=list)
    affected_sessions: list[str] = Field(default_factory=list)
    affected_certificates: list[str] = Field(default_factory=list)
    compliance_references: Optional[dict[str, list[str]]] = None
    status: str = "OPEN"
    created_at: datetime


class RecommendationsResponse(BaseModel):
    """Recommendations list response."""
    total: int
    recommendations: list[RecommendationResponse] = Field(default_factory=list)


class AnomalyResponse(BaseModel):
    """Single anomaly response."""
    prediction_id: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    anomaly_score: Optional[float] = None
    confidence: Optional[float] = None
    feature_importance: Optional[dict[str, float]] = None
    explanation: str = ""


class MLInsightsResponse(BaseModel):
    """ML insights response."""
    ml_enabled: bool
    model_version: Optional[str] = None
    total_predictions: int = 0
    anomalies_detected: int = 0
    anomalies: list[AnomalyResponse] = Field(default_factory=list)
    top_risk_factors: list = Field(default_factory=list)
    confidence: float = 0.0
    message: str = ""


class ReportInfoResponse(BaseModel):
    """Report information response."""
    report_id: str
    format: str
    status: str
    filename: Optional[str] = None
    file_size_bytes: Optional[int] = None
    content_hash: Optional[str] = None
    generated_at: Optional[datetime] = None
    error_message: Optional[str] = None


class ReportListResponse(BaseModel):
    """Report list response."""
    total: int
    reports: list[ReportInfoResponse] = Field(default_factory=list)


class IntegrityResponse(BaseModel):
    """Evidence integrity response."""
    integrity_id: str
    evidence_id: str
    status: str
    evidence_sha256: str
    evidence_sha512: Optional[str] = None
    analysis_hash: Optional[str] = None
    report_hash: Optional[str] = None
    merkle_root: Optional[str] = None
    blockchain_enabled: bool = False
    blockchain_network: Optional[str] = None
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    anchor_timestamp: Optional[datetime] = None
    created_at: datetime
    verified_at: Optional[datetime] = None
    verification_message: Optional[str] = None


class TriggerIntelligenceRequest(BaseModel):
    """Request to trigger intelligence analysis."""
    enable_ml: bool = True
    generate_reports: bool = True


class TriggerIntelligenceResponse(BaseModel):
    """Response after triggering intelligence analysis."""
    job_id: str
    evidence_id: str
    status: str
    message: str
    security_analysis_id: Optional[str] = None
