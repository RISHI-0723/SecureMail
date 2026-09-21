"""Intelligence and reporting models for Phase 4.

Phase 4: Intelligence Aggregation, ML, Reports, Evidence Integrity

This module contains models for:
- Intelligence aggregation from Phase 3 findings
- Cross-session and cross-evidence correlations
- Actionable recommendations
- ML models and predictions
- Anomaly detection results
- Generated reports (JSON/HTML/PDF)
- Evidence integrity and optional blockchain anchoring
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Text, DateTime, Integer, Float, Boolean,
    ForeignKey, Index, JSON, Enum, LargeBinary
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class IntelligenceStatus(str, PyEnum):
    """Status of intelligence aggregation."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class ReportFormat(str, PyEnum):
    """Report output formats."""
    JSON = "JSON"
    HTML = "HTML"
    PDF = "PDF"


class ReportStatus(str, PyEnum):
    """Status of report generation."""
    QUEUED = "QUEUED"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class IntegrityStatus(str, PyEnum):
    """Status of integrity verification."""
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ANCHORED = "ANCHORED"  # Blockchain anchored


class CorrelationType(str, PyEnum):
    """Types of security correlations."""
    SAME_CERTIFICATE = "SAME_CERTIFICATE"
    SAME_CIPHER_WEAKNESS = "SAME_CIPHER_WEAKNESS"
    SAME_TLS_VERSION = "SAME_TLS_VERSION"
    SAME_KEY_EXCHANGE = "SAME_KEY_EXCHANGE"
    SAME_SERVER = "SAME_SERVER"
    TEMPORAL_PATTERN = "TEMPORAL_PATTERN"
    RISK_ESCALATION = "RISK_ESCALATION"


class RecommendationPriority(str, PyEnum):
    """Priority levels for recommendations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RecommendationCategory(str, PyEnum):
    """Categories for recommendations."""
    TLS_UPGRADE = "TLS_UPGRADE"
    CIPHER_UPGRADE = "CIPHER_UPGRADE"
    CERTIFICATE_RENEWAL = "CERTIFICATE_RENEWAL"
    KEY_ROTATION = "KEY_ROTATION"
    CONFIGURATION = "CONFIGURATION"
    MONITORING = "MONITORING"
    COMPLIANCE = "COMPLIANCE"


def generate_intelligence_id() -> str:
    """Generate a unique intelligence report ID."""
    return f"intel_{uuid.uuid4().hex[:12]}"


def generate_correlation_id() -> str:
    """Generate a unique correlation ID."""
    return f"corr_{uuid.uuid4().hex[:12]}"


def generate_recommendation_id() -> str:
    """Generate a unique recommendation ID."""
    return f"rec_{uuid.uuid4().hex[:12]}"


def generate_report_id() -> str:
    """Generate a unique report ID."""
    return f"rep_{uuid.uuid4().hex[:12]}"


def generate_integrity_id() -> str:
    """Generate a unique integrity record ID."""
    return f"integ_{uuid.uuid4().hex[:12]}"


def generate_ml_prediction_id() -> str:
    """Generate a unique ML prediction ID."""
    return f"mlp_{uuid.uuid4().hex[:12]}"


class IntelligenceReport(Base):
    """
    Phase 4 intelligence aggregation results.

    Aggregates all Phase 3 findings into a comprehensive
    intelligence report with correlations, recommendations,
    and ML-enhanced insights.
    """
    __tablename__ = "intelligence_reports"

    report_id = Column(
        String(50),
        primary_key=True,
        default=generate_intelligence_id,
        index=True
    )
    evidence_id = Column(
        String(50),
        ForeignKey("pcap_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    security_analysis_id = Column(
        String(50),
        ForeignKey("security_analyses.analysis_id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    job_id = Column(
        String(50),
        ForeignKey("analysis_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Status
    status = Column(
        Enum(IntelligenceStatus),
        nullable=False,
        default=IntelligenceStatus.QUEUED,
        index=True
    )

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Aggregated metrics
    total_correlations = Column(Integer, nullable=False, default=0)
    total_recommendations = Column(Integer, nullable=False, default=0)
    ml_predictions_count = Column(Integer, nullable=False, default=0)
    anomalies_detected = Column(Integer, nullable=False, default=0)

    # Overall security posture (aggregated from Phase 3 + Phase 4 insights)
    security_posture_score = Column(Float, nullable=True)
    security_posture_grade = Column(String(10), nullable=True)  # A, B, C, D, F

    # Dimension scores (0-100)
    tls_security_score = Column(Float, nullable=True)
    certificate_security_score = Column(Float, nullable=True)
    protocol_security_score = Column(Float, nullable=True)
    configuration_security_score = Column(Float, nullable=True)

    # ML confidence
    ml_enabled = Column(Boolean, nullable=False, default=False)
    ml_model_version = Column(String(50), nullable=True)
    ml_confidence_score = Column(Float, nullable=True)

    # Executive summary (generated)
    executive_summary = Column(Text, nullable=True)

    # JSON fields for detailed data
    aggregated_findings = Column(JSON, nullable=False, default=list)
    correlation_summary = Column(JSON, nullable=False, default=dict)
    recommendation_summary = Column(JSON, nullable=False, default=dict)
    ml_insights = Column(JSON, nullable=True)
    anomaly_summary = Column(JSON, nullable=True)

    # Error handling
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    evidence = relationship("PcapEvidence", backref="intelligence_reports")
    security_analysis = relationship(
        "SecurityAnalysis",
        backref="intelligence_report",
        uselist=False
    )
    job = relationship("AnalysisJob", backref="intelligence_report", uselist=False)

    __table_args__ = (
        Index("ix_intelligence_evidence_status", "evidence_id", "status"),
        Index("ix_intelligence_posture", "security_posture_grade", "security_posture_score"),
    )

    def __repr__(self) -> str:
        return (
            f"<IntelligenceReport(report_id={self.report_id}, "
            f"status={self.status}, posture={self.security_posture_grade})>"
        )


class Correlation(Base):
    """
    Security correlations across sessions and evidence.

    Links related findings, sessions, or patterns that
    share common security characteristics.
    """
    __tablename__ = "correlations"

    correlation_id = Column(
        String(50),
        primary_key=True,
        default=generate_correlation_id,
        index=True
    )
    intelligence_report_id = Column(
        String(50),
        ForeignKey("intelligence_reports.report_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Correlation type and strength
    correlation_type = Column(
        Enum(CorrelationType),
        nullable=False,
        index=True
    )
    strength = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0
    confidence = Column(String(20), nullable=False, default="MEDIUM")

    # Title and description
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Linked entities (as JSON arrays of IDs)
    linked_findings = Column(JSON, nullable=False, default=list)
    linked_sessions = Column(JSON, nullable=False, default=list)
    linked_certificates = Column(JSON, nullable=False, default=list)
    linked_streams = Column(JSON, nullable=False, default=list)

    # Common attribute that creates the correlation
    common_attribute = Column(String(100), nullable=True)
    common_value = Column(Text, nullable=True)

    # Impact assessment
    combined_severity = Column(String(20), nullable=True)
    combined_risk_score = Column(Float, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    intelligence_report = relationship(
        "IntelligenceReport",
        backref="correlations"
    )

    __table_args__ = (
        Index("ix_correlation_type_strength", "correlation_type", "strength"),
    )

    def __repr__(self) -> str:
        return (
            f"<Correlation(correlation_id={self.correlation_id}, "
            f"type={self.correlation_type}, strength={self.strength})>"
        )


class Recommendation(Base):
    """
    Actionable security recommendations.

    Generated from findings and correlations with
    specific remediation steps.
    """
    __tablename__ = "recommendations"

    recommendation_id = Column(
        String(50),
        primary_key=True,
        default=generate_recommendation_id,
        index=True
    )
    intelligence_report_id = Column(
        String(50),
        ForeignKey("intelligence_reports.report_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Priority and category
    priority = Column(
        Enum(RecommendationPriority),
        nullable=False,
        default=RecommendationPriority.MEDIUM,
        index=True
    )
    category = Column(
        Enum(RecommendationCategory),
        nullable=False,
        index=True
    )

    # Title and description
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    # Remediation details
    remediation_steps = Column(JSON, nullable=False, default=list)
    estimated_effort = Column(String(50), nullable=True)  # Low/Medium/High
    technical_impact = Column(Text, nullable=True)
    business_impact = Column(Text, nullable=True)

    # Affected entities
    affected_findings = Column(JSON, nullable=False, default=list)
    affected_sessions = Column(JSON, nullable=False, default=list)
    affected_certificates = Column(JSON, nullable=False, default=list)

    # Status tracking (for dashboard)
    status = Column(String(20), nullable=False, default="OPEN")
    assigned_to = Column(String(100), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Compliance references
    compliance_references = Column(JSON, nullable=True)  # NIST, PCI-DSS, etc.

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    intelligence_report = relationship(
        "IntelligenceReport",
        backref="recommendations"
    )

    __table_args__ = (
        Index("ix_recommendation_priority_status", "priority", "status"),
        Index("ix_recommendation_category", "category"),
    )

    def __repr__(self) -> str:
        return (
            f"<Recommendation(recommendation_id={self.recommendation_id}, "
            f"priority={self.priority}, category={self.category})>"
        )


class MLPrediction(Base):
    """
    ML model predictions and anomaly detection results.

    Stores predictions from ML models along with
    feature data for explainability.
    """
    __tablename__ = "ml_predictions"

    prediction_id = Column(
        String(50),
        primary_key=True,
        default=generate_ml_prediction_id,
        index=True
    )
    intelligence_report_id = Column(
        String(50),
        ForeignKey("intelligence_reports.report_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Model information
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(50), nullable=False)
    model_type = Column(String(50), nullable=False)  # classifier, anomaly_detector

    # Prediction details
    prediction_type = Column(String(50), nullable=False)  # risk_level, anomaly_score
    predicted_value = Column(String(50), nullable=True)
    predicted_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)

    # Anomaly detection specific
    is_anomaly = Column(Boolean, nullable=True)
    anomaly_score = Column(Float, nullable=True)  # Isolation Forest score

    # Features used (for explainability)
    feature_vector = Column(JSON, nullable=True)
    feature_importance = Column(JSON, nullable=True)

    # Target entity
    target_type = Column(String(50), nullable=True)  # session, certificate, finding
    target_id = Column(String(50), nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    intelligence_report = relationship(
        "IntelligenceReport",
        backref="ml_predictions"
    )

    __table_args__ = (
        Index("ix_ml_prediction_model", "model_name", "model_version"),
        Index("ix_ml_prediction_anomaly", "is_anomaly", "anomaly_score"),
    )

    def __repr__(self) -> str:
        return (
            f"<MLPrediction(prediction_id={self.prediction_id}, "
            f"model={self.model_name}, anomaly={self.is_anomaly})>"
        )


class GeneratedReport(Base):
    """
    Generated reports in various formats.

    Stores metadata and file references for
    JSON, HTML, and PDF reports.
    """
    __tablename__ = "generated_reports"

    report_id = Column(
        String(50),
        primary_key=True,
        default=generate_report_id,
        index=True
    )
    intelligence_report_id = Column(
        String(50),
        ForeignKey("intelligence_reports.report_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    evidence_id = Column(
        String(50),
        ForeignKey("pcap_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Format and status
    format = Column(
        Enum(ReportFormat),
        nullable=False,
        index=True
    )
    status = Column(
        Enum(ReportStatus),
        nullable=False,
        default=ReportStatus.QUEUED,
        index=True
    )

    # File information
    filename = Column(String(255), nullable=True)
    stored_path = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    content_hash = Column(String(64), nullable=True)  # SHA-256

    # For JSON reports, store content directly
    report_content = Column(JSON, nullable=True)

    # For HTML, store the rendered content
    html_content = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    generated_at = Column(DateTime(timezone=True), nullable=True)

    # Error handling
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    intelligence_report = relationship(
        "IntelligenceReport",
        backref="generated_reports"
    )
    evidence = relationship("PcapEvidence", backref="reports")

    __table_args__ = (
        Index("ix_generated_report_format_status", "format", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<GeneratedReport(report_id={self.report_id}, "
            f"format={self.format}, status={self.status})>"
        )


class EvidenceIntegrity(Base):
    """
    Evidence integrity tracking and optional blockchain anchoring.

    Maintains cryptographic hashes and integrity proofs
    for forensic evidence chain of custody.
    """
    __tablename__ = "evidence_integrity"

    integrity_id = Column(
        String(50),
        primary_key=True,
        default=generate_integrity_id,
        index=True
    )
    evidence_id = Column(
        String(50),
        ForeignKey("pcap_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    intelligence_report_id = Column(
        String(50),
        ForeignKey("intelligence_reports.report_id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )

    # Status
    status = Column(
        Enum(IntegrityStatus),
        nullable=False,
        default=IntegrityStatus.PENDING,
        index=True
    )

    # Evidence hashes
    evidence_sha256 = Column(String(64), nullable=False)
    evidence_sha512 = Column(String(128), nullable=True)
    evidence_md5 = Column(String(32), nullable=True)  # For legacy compatibility

    # Analysis result hash
    analysis_hash = Column(String(64), nullable=True)
    report_hash = Column(String(64), nullable=True)

    # Merkle tree root (for batched verification)
    merkle_root = Column(String(64), nullable=True)

    # Blockchain anchoring (optional)
    blockchain_enabled = Column(Boolean, nullable=False, default=False)
    blockchain_network = Column(String(50), nullable=True)  # ethereum, polygon
    transaction_hash = Column(String(100), nullable=True)
    block_number = Column(Integer, nullable=True)
    anchor_timestamp = Column(DateTime(timezone=True), nullable=True)

    # Integrity metadata
    integrity_metadata = Column(JSON, nullable=True)  # Additional proof data

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    verified_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    evidence = relationship("PcapEvidence", backref="integrity_records")
    intelligence_report = relationship(
        "IntelligenceReport",
        backref="integrity_record",
        uselist=False
    )

    __table_args__ = (
        Index("ix_evidence_integrity_hash", "evidence_sha256"),
        Index("ix_evidence_integrity_blockchain", "blockchain_enabled", "transaction_hash"),
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceIntegrity(integrity_id={self.integrity_id}, "
            f"status={self.status}, anchored={self.blockchain_enabled})>"
        )
