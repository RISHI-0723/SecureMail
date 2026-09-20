"""Pydantic schemas for request/response validation."""
from app.schemas.common import ApiResponse, ErrorDetail, PaginatedResponse
from app.schemas.case import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseWithEvidenceCount,
    CaseListResponse,
)
from app.schemas.evidence import (
    EvidenceResponse,
    EvidenceUploadResponse,
    EvidenceListResponse,
    DuplicateEvidenceResponse,
)
from app.schemas.analysis import (
    AnalysisJobResponse,
    AnalysisJobListResponse,
    # Phase 2
    PacketAnalysisSummaryResponse,
    ProtocolSummaryResponse,
    ProtocolDetectionResponse,
    SessionCandidateResponse,
    TriggerAnalysisResponse,
)
from app.schemas.health import (
    HealthResponse,
    DependencyStatus,
    DependenciesHealthResponse,
)
from app.schemas.security import (
    # Phase 3 Security Analysis
    SecurityAnalysisSummaryResponse,
    TcpStreamResponse,
    TcpStreamsResponse,
    EmailSessionResponse,
    EmailSessionsResponse,
    TlsObservationResponse,
    TlsObservationsResponse,
    CertificateResponse,
    CertificatesResponse,
    FindingResponse,
    FindingEvidenceResponse,
    FindingsResponse,
    DimensionScoreResponse,
    RiskAssessmentResponse,
    TriggerSecurityAnalysisRequest,
    TriggerSecurityAnalysisResponse,
)

__all__ = [
    # Common
    "ApiResponse",
    "ErrorDetail",
    "PaginatedResponse",
    # Case
    "CaseCreate",
    "CaseUpdate",
    "CaseResponse",
    "CaseWithEvidenceCount",
    "CaseListResponse",
    # Evidence
    "EvidenceResponse",
    "EvidenceUploadResponse",
    "EvidenceListResponse",
    "DuplicateEvidenceResponse",
    # Analysis
    "AnalysisJobResponse",
    "AnalysisJobListResponse",
    # Phase 2 Packet Analysis
    "PacketAnalysisSummaryResponse",
    "ProtocolSummaryResponse",
    "ProtocolDetectionResponse",
    "SessionCandidateResponse",
    "TriggerAnalysisResponse",
    # Health
    "HealthResponse",
    "DependencyStatus",
    "DependenciesHealthResponse",
    # Phase 3 Security Analysis
    "SecurityAnalysisSummaryResponse",
    "TcpStreamResponse",
    "TcpStreamsResponse",
    "EmailSessionResponse",
    "EmailSessionsResponse",
    "TlsObservationResponse",
    "TlsObservationsResponse",
    "CertificateResponse",
    "CertificatesResponse",
    "FindingResponse",
    "FindingEvidenceResponse",
    "FindingsResponse",
    "DimensionScoreResponse",
    "RiskAssessmentResponse",
    "TriggerSecurityAnalysisRequest",
    "TriggerSecurityAnalysisResponse",
]
