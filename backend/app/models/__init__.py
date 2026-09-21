"""SQLAlchemy database models."""
from app.core.database import Base

# Import all models here for Alembic auto-generation
from app.models.case import Case, CaseStatus
from app.models.evidence import PcapEvidence, EvidenceStatus, FileFormat
from app.models.analysis_job import AnalysisJob, JobStatus, JobType
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.models.intelligence import (
    IntelligenceReport,
    IntelligenceStatus,
    Correlation,
    CorrelationType,
    Recommendation,
    RecommendationPriority,
    RecommendationCategory,
    MLPrediction,
    GeneratedReport,
    ReportFormat,
    ReportStatus,
    EvidenceIntegrity,
    IntegrityStatus,
)

__all__ = [
    "Base",
    "Case",
    "CaseStatus",
    "PcapEvidence",
    "EvidenceStatus",
    "FileFormat",
    "AnalysisJob",
    "JobStatus",
    "JobType",
    "PacketAnalysis",
    "SecurityAnalysis",
    "SecurityAnalysisStatus",
    # Phase 4
    "IntelligenceReport",
    "IntelligenceStatus",
    "Correlation",
    "CorrelationType",
    "Recommendation",
    "RecommendationPriority",
    "RecommendationCategory",
    "MLPrediction",
    "GeneratedReport",
    "ReportFormat",
    "ReportStatus",
    "EvidenceIntegrity",
    "IntegrityStatus",
]
