"""Phase 3 Security Analysis API endpoints.

Endpoints for:
- Security analysis summary
- TCP streams
- Email sessions
- TLS observations
- Certificates
- Security findings
- Risk assessment
- Triggering security analysis

IMPORTANT: These endpoints return Phase 3 analysis results.
They do NOT re-run TShark or trigger Phase 2 analysis.
"""
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis_job import AnalysisJob, JobStatus, JobType, generate_job_id
from app.models.evidence import PcapEvidence
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.schemas.common import ApiResponse
from app.schemas.security import (
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
from app.workers.security_tasks import run_security_analysis

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_security_analysis(
    evidence_id: str,
    db: Session
) -> SecurityAnalysis:
    """Get security analysis for evidence, raising appropriate errors."""
    # Get the latest security analysis for this evidence
    analysis = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.evidence_id == evidence_id
    ).order_by(SecurityAnalysis.created_at.desc()).first()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SECURITY_ANALYSIS_NOT_FOUND",
                "message": f"No security analysis found for evidence: {evidence_id}"
            }
        )

    if analysis.status == SecurityAnalysisStatus.QUEUED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_NOT_STARTED",
                "message": "Security analysis has not started yet"
            }
        )

    if analysis.status == SecurityAnalysisStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_IN_PROGRESS",
                "message": "Security analysis is in progress"
            }
        )

    if analysis.status == SecurityAnalysisStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": analysis.error_code or "ANALYSIS_FAILED",
                "message": analysis.error_message or "Security analysis failed"
            }
        )

    return analysis


@router.get(
    "/security/{evidence_id}/summary",
    response_model=ApiResponse[SecurityAnalysisSummaryResponse],
    tags=["Security"],
    summary="Get security analysis summary"
)
async def get_security_summary(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[SecurityAnalysisSummaryResponse]:
    """
    Get security analysis summary for evidence.

    Returns overview of all Phase 3 analysis results including:
    - Analysis status
    - Counts (streams, sessions, TLS, certs, findings)
    - Risk assessment summary
    """
    analysis = _get_security_analysis(evidence_id, db)

    response = SecurityAnalysisSummaryResponse(
        analysis_id=analysis.analysis_id,
        job_id=analysis.job_id,
        evidence_id=analysis.evidence_id,
        status=analysis.status.value,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        duration_seconds=analysis.duration_seconds,
        total_streams=analysis.total_streams,
        total_sessions=analysis.total_sessions,
        total_tls_observations=analysis.total_tls_observations,
        total_certificates=analysis.total_certificates,
        total_findings=analysis.total_findings,
        critical_findings=analysis.critical_findings,
        high_findings=analysis.high_findings,
        medium_findings=analysis.medium_findings,
        low_findings=analysis.low_findings,
        info_findings=analysis.info_findings,
        overall_risk_level=analysis.overall_risk_level,
        overall_risk_score=analysis.overall_risk_score,
        confidence=analysis.confidence,
        coverage=analysis.coverage,
        policy_version=analysis.policy_version
    )

    return ApiResponse.ok(response)


@router.get(
    "/security/{evidence_id}/streams",
    response_model=ApiResponse[TcpStreamsResponse],
    tags=["Security"],
    summary="Get TCP streams"
)
async def get_tcp_streams(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[TcpStreamsResponse]:
    """Get reconstructed TCP streams for evidence."""
    analysis = _get_security_analysis(evidence_id, db)

    streams = []
    complete_count = 0
    partial_count = 0

    for stream_data in (analysis.tcp_streams or []):
        stream = TcpStreamResponse(
            stream_id=stream_data.get("stream_id", 0),
            client_ip=stream_data.get("client_ip"),
            client_port=stream_data.get("client_port"),
            server_ip=stream_data.get("server_ip"),
            server_port=stream_data.get("server_port"),
            integrity=stream_data.get("integrity", "UNKNOWN"),
            packet_count=stream_data.get("packet_count", 0),
            byte_count=stream_data.get("byte_count", 0),
            has_fin=stream_data.get("has_fin", False),
            has_rst=stream_data.get("has_rst", False),
            termination_type=stream_data.get("termination_type"),
            start_time=stream_data.get("start_time"),
            end_time=stream_data.get("end_time")
        )
        streams.append(stream)

        if stream_data.get("integrity") == "COMPLETE":
            complete_count += 1
        elif stream_data.get("integrity") == "PARTIAL":
            partial_count += 1

    return ApiResponse.ok(TcpStreamsResponse(
        streams=streams,
        total=len(streams),
        complete_count=complete_count,
        partial_count=partial_count
    ))


@router.get(
    "/security/{evidence_id}/sessions",
    response_model=ApiResponse[EmailSessionsResponse],
    tags=["Security"],
    summary="Get email sessions"
)
async def get_email_sessions(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[EmailSessionsResponse]:
    """Get email security sessions for evidence."""
    analysis = _get_security_analysis(evidence_id, db)

    sessions = []
    by_protocol: dict[str, int] = {}
    by_transport: dict[str, int] = {}

    for session_data in (analysis.email_sessions or []):
        session = EmailSessionResponse(
            session_id=session_data.get("session_id", ""),
            stream_id=session_data.get("stream_id", 0),
            protocol=session_data.get("protocol", "UNKNOWN"),
            client_ip=session_data.get("client_ip"),
            client_port=session_data.get("client_port"),
            server_ip=session_data.get("server_ip"),
            server_port=session_data.get("server_port"),
            transport_security=session_data.get("transport_security", "UNKNOWN"),
            starttls_advertised=session_data.get("starttls_advertised", False),
            starttls_state=session_data.get("starttls_state", "NONE"),
            tls_detected=session_data.get("tls_detected", False),
            implicit_tls=session_data.get("implicit_tls", False),
            confidence=session_data.get("confidence", "UNKNOWN"),
            coverage=session_data.get("coverage", "UNKNOWN")
        )
        sessions.append(session)

        # Count by protocol
        proto = session_data.get("protocol", "UNKNOWN")
        by_protocol[proto] = by_protocol.get(proto, 0) + 1

        # Count by transport security
        transport = session_data.get("transport_security", "UNKNOWN")
        by_transport[transport] = by_transport.get(transport, 0) + 1

    return ApiResponse.ok(EmailSessionsResponse(
        sessions=sessions,
        total=len(sessions),
        by_protocol=by_protocol,
        by_transport_security=by_transport
    ))


@router.get(
    "/security/{evidence_id}/tls",
    response_model=ApiResponse[TlsObservationsResponse],
    tags=["Security"],
    summary="Get TLS observations"
)
async def get_tls_observations(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[TlsObservationsResponse]:
    """Get TLS observations for evidence."""
    analysis = _get_security_analysis(evidence_id, db)

    observations = []
    by_version: dict[str, int] = {}
    modern_count = 0
    deprecated_count = 0

    for obs_data in (analysis.tls_observations or []):
        obs = TlsObservationResponse(
            observation_id=obs_data.get("observation_id", ""),
            session_id=obs_data.get("session_id"),
            stream_id=obs_data.get("stream_id", 0),
            tls_version=obs_data.get("tls_version"),
            tls_version_security=obs_data.get("tls_version_security"),
            cipher_suite=obs_data.get("cipher_suite"),
            key_exchange=obs_data.get("key_exchange"),
            has_forward_secrecy=obs_data.get("has_forward_secrecy", False),
            handshake_status=obs_data.get("handshake_status", "UNKNOWN"),
            handshake_timestamp=obs_data.get("handshake_timestamp"),
            sni=obs_data.get("sni"),
            alpn=obs_data.get("alpn"),
            confidence=obs_data.get("confidence", "UNKNOWN"),
            coverage=obs_data.get("coverage", "UNKNOWN")
        )
        observations.append(obs)

        # Count by version
        version = obs_data.get("tls_version", "UNKNOWN")
        by_version[version] = by_version.get(version, 0) + 1

        # Count modern vs deprecated
        security = obs_data.get("tls_version_security", "")
        if security in ["MODERN", "ACCEPTABLE"]:
            modern_count += 1
        elif security in ["DEPRECATED", "OBSOLETE"]:
            deprecated_count += 1

    return ApiResponse.ok(TlsObservationsResponse(
        observations=observations,
        total=len(observations),
        by_version=by_version,
        modern_tls_count=modern_count,
        deprecated_tls_count=deprecated_count
    ))


@router.get(
    "/security/{evidence_id}/certificates",
    response_model=ApiResponse[CertificatesResponse],
    tags=["Security"],
    summary="Get certificates"
)
async def get_certificates(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[CertificatesResponse]:
    """Get certificate observations for evidence."""
    analysis = _get_security_analysis(evidence_id, db)

    certificates = []
    valid_count = 0
    expired_count = 0
    weak_key_count = 0
    self_signed_count = 0

    for cert_data in (analysis.certificates or []):
        cert = CertificateResponse(
            certificate_id=cert_data.get("certificate_id", ""),
            stream_id=cert_data.get("stream_id", 0),
            subject=cert_data.get("subject"),
            issuer=cert_data.get("issuer"),
            serial_number=cert_data.get("serial_number"),
            not_before=cert_data.get("not_before"),
            not_after=cert_data.get("not_after"),
            validity=cert_data.get("validity", "UNKNOWN"),
            key_type=cert_data.get("key_type"),
            key_size_bits=cert_data.get("key_size_bits"),
            key_strength=cert_data.get("key_strength", "UNKNOWN"),
            signature_algorithm=cert_data.get("signature_algorithm"),
            signature_algorithm_security=cert_data.get(
                "signature_algorithm_security", "UNKNOWN"
            ),
            is_self_signed=cert_data.get("is_self_signed"),
            subject_alt_names=cert_data.get("subject_alt_names", []),
            confidence=cert_data.get("confidence", "UNKNOWN"),
            parse_status=cert_data.get("parse_status")
        )
        certificates.append(cert)

        # Count statistics
        validity = cert_data.get("validity", "")
        if validity == "VALID":
            valid_count += 1
        elif validity == "EXPIRED":
            expired_count += 1

        key_strength = cert_data.get("key_strength", "")
        if key_strength in ["WEAK", "INSECURE"]:
            weak_key_count += 1

        if cert_data.get("is_self_signed"):
            self_signed_count += 1

    return ApiResponse.ok(CertificatesResponse(
        certificates=certificates,
        total=len(certificates),
        valid_count=valid_count,
        expired_count=expired_count,
        weak_key_count=weak_key_count,
        self_signed_count=self_signed_count
    ))


@router.get(
    "/security/{evidence_id}/findings",
    response_model=ApiResponse[FindingsResponse],
    tags=["Security"],
    summary="Get security findings"
)
async def get_findings(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[FindingsResponse]:
    """Get security findings for evidence."""
    analysis = _get_security_analysis(evidence_id, db)

    findings = []
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    unique_rules: set[str] = set()

    for finding_data in (analysis.findings or []):
        evidence_list = [
            FindingEvidenceResponse(
                evidence_type=e.get("evidence_type", ""),
                reference_id=e.get("reference_id", ""),
                stream_id=e.get("stream_id"),
                observed_value=e.get("observed_value"),
                expected_value=e.get("expected_value")
            )
            for e in finding_data.get("evidence", [])
        ]

        finding = FindingResponse(
            finding_id=finding_data.get("finding_id", ""),
            rule_id=finding_data.get("rule_id", ""),
            title=finding_data.get("title", ""),
            description=finding_data.get("description", ""),
            category=finding_data.get("category", ""),
            severity=finding_data.get("severity", ""),
            evidence=evidence_list,
            session_id=finding_data.get("session_id"),
            stream_id=finding_data.get("stream_id"),
            certificate_id=finding_data.get("certificate_id"),
            confidence=finding_data.get("confidence", "HIGH"),
            remediation=finding_data.get("remediation", ""),
            occurrence_count=finding_data.get("occurrence_count", 1),
            affected_streams=finding_data.get("affected_streams", [])
        )
        findings.append(finding)

        # Counts
        severity = finding_data.get("severity", "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1

        category = finding_data.get("category", "UNKNOWN")
        by_category[category] = by_category.get(category, 0) + 1

        unique_rules.add(finding_data.get("rule_id", ""))

    return ApiResponse.ok(FindingsResponse(
        findings=findings,
        total=len(findings),
        by_severity=by_severity,
        by_category=by_category,
        unique_rules=list(unique_rules)
    ))


@router.get(
    "/security/{evidence_id}/risk",
    response_model=ApiResponse[RiskAssessmentResponse],
    tags=["Security"],
    summary="Get risk assessment"
)
async def get_risk_assessment(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[RiskAssessmentResponse]:
    """Get risk assessment for evidence."""
    analysis = _get_security_analysis(evidence_id, db)

    risk_data = analysis.risk_assessment or {}
    posture = risk_data.get("posture", {})

    dimensions = [
        DimensionScoreResponse(
            dimension=d.get("dimension", ""),
            score=d.get("score", 0),
            risk_level=d.get("risk_level", "UNKNOWN"),
            findings_count=d.get("findings_count", 0),
            description=d.get("description", "")
        )
        for d in posture.get("dimensions", [])
    ]

    return ApiResponse.ok(RiskAssessmentResponse(
        overall_score=posture.get("overall_score", 0),
        overall_risk=posture.get("overall_risk", "UNKNOWN"),
        dimensions=dimensions,
        confidence=posture.get("confidence", "UNKNOWN"),
        coverage=posture.get("coverage", "UNKNOWN"),
        summary=posture.get("summary", ""),
        key_findings=posture.get("key_findings", []),
        recommendations=posture.get("recommendations", []),
        assessment_version=risk_data.get("assessment_version", "1.0.0"),
        policy_version=risk_data.get("policy_version", "1.0.0")
    ))


@router.post(
    "/security/{evidence_id}/analyze",
    response_model=ApiResponse[TriggerSecurityAnalysisResponse],
    tags=["Security"],
    summary="Trigger security analysis"
)
async def trigger_security_analysis(
    evidence_id: str,
    request: TriggerSecurityAnalysisRequest = TriggerSecurityAnalysisRequest(),
    db: Session = Depends(get_db)
) -> ApiResponse[TriggerSecurityAnalysisResponse]:
    """
    Trigger Phase 3 security analysis for evidence.

    This creates a new analysis job and enqueues the security analysis task.
    Requires Phase 2 packet analysis to be completed.

    IMPORTANT: This does NOT re-run TShark. It consumes Phase 2 data.
    """
    # Check evidence exists
    evidence = db.query(PcapEvidence).filter(
        PcapEvidence.evidence_id == evidence_id
    ).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "EVIDENCE_NOT_FOUND",
                "message": f"Evidence not found: {evidence_id}"
            }
        )

    # Check for Phase 2 packet analysis
    packet_analysis = None
    if request.packet_analysis_id:
        packet_analysis = db.query(PacketAnalysis).filter(
            PacketAnalysis.analysis_id == request.packet_analysis_id
        ).first()
    else:
        packet_analysis = db.query(PacketAnalysis).filter(
            PacketAnalysis.evidence_id == evidence_id
        ).first()

    # Check if security analysis already exists
    existing = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.evidence_id == evidence_id
    ).order_by(SecurityAnalysis.created_at.desc()).first()

    if existing:
        if existing.status == SecurityAnalysisStatus.RUNNING:
            return ApiResponse.ok(TriggerSecurityAnalysisResponse(
                job_id=existing.job_id,
                status="RUNNING",
                message="Security analysis is already running"
            ))
        elif existing.status == SecurityAnalysisStatus.COMPLETED:
            return ApiResponse.ok(TriggerSecurityAnalysisResponse(
                job_id=existing.job_id,
                status="COMPLETED",
                message="Security analysis already completed. Create new job to re-analyze."
            ))

    # Create new analysis job for Phase 3
    job_id = generate_job_id()
    job = AnalysisJob(
        job_id=job_id,
        evidence_id=evidence_id,
        job_type=JobType.TLS_ANALYSIS,  # Reuse existing type for now
        status=JobStatus.QUEUED,
        stage="QUEUED_FOR_SECURITY_ANALYSIS"
    )
    db.add(job)
    db.commit()

    logger.info(
        f"Triggering security analysis for evidence {evidence_id}",
        extra={
            "job_id": job_id,
            "evidence_id": evidence_id,
            "packet_analysis_id": packet_analysis.analysis_id if packet_analysis else None
        }
    )

    # Enqueue security analysis task
    run_security_analysis.delay(
        job_id,
        packet_analysis.analysis_id if packet_analysis else None
    )

    return ApiResponse.ok(TriggerSecurityAnalysisResponse(
        job_id=job_id,
        status="TRIGGERED",
        message="Security analysis has been triggered"
    ))
