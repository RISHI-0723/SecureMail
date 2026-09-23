"""Analysis execution service - supports both Celery and demo modes.

This module provides the core analysis execution logic that can be called
either asynchronously via Celery tasks or synchronously for demo deployments.

The implementation maintains the exact same analysis pipeline regardless of
execution mode, ensuring consistent results and proper error handling.
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis_job import AnalysisJob, JobStatus, JobType, generate_job_id
from app.models.evidence import PcapEvidence
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.models.intelligence import IntelligenceStatus
from app.services.packet import (
    TSharkService,
    TSharkStatus,
    PacketParser,
    ProtocolDetector,
)
from app.services.ingestion.storage import evidence_storage, StorageError

# Phase 3 services
from app.services.tcp import TcpStreamReconstructor
from app.services.email import EmailSecurityAnalyzer
from app.services.tls import TlsAnalyzer
from app.services.certificates import CertificateAnalyzer
from app.services.crypto import get_default_policy
from app.services.findings import FindingEngine
from app.services.risk import RiskEngine

logger = logging.getLogger(__name__)


class AnalysisExecutionError(Exception):
    """Base exception for analysis execution errors."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def execute_phase2_analysis(db: Session, job_id: str) -> Dict[str, Any]:
    """
    Execute Phase 2 packet analysis (TShark).

    This is the core Phase 2 logic extracted from the Celery task.
    Can be called synchronously or asynchronously.

    Args:
        db: Database session
        job_id: Analysis job identifier

    Returns:
        Analysis result dictionary

    Raises:
        AnalysisExecutionError: If analysis fails
    """
    job = None
    temp_file_cleanup = False
    evidence_path = None

    try:
        # Get the analysis job
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            raise AnalysisExecutionError(
                "ANALYSIS_JOB_NOT_FOUND",
                f"Job not found: {job_id}"
            )

        # Update job to RUNNING
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        job.stage = "INITIALIZING"
        db.commit()

        # Get evidence
        evidence = db.query(PcapEvidence).filter(
            PcapEvidence.evidence_id == job.evidence_id
        ).first()

        if not evidence:
            _fail_job(db, job, "EVIDENCE_NOT_FOUND", f"Evidence not found: {job.evidence_id}")
            raise AnalysisExecutionError("EVIDENCE_NOT_FOUND", f"Evidence not found: {job.evidence_id}")

        # Get evidence path through storage abstraction
        try:
            storage_key = evidence.stored_filename
            if not storage_key:
                _fail_job(db, job, "EVIDENCE_NOT_FOUND", "Evidence storage key is missing")
                raise AnalysisExecutionError("EVIDENCE_NOT_FOUND", "Evidence storage key is missing")

            evidence_path = str(evidence_storage.get_path(storage_key))
            temp_file_cleanup = settings.storage_backend.lower() == "s3"
        except StorageError as e:
            logger.error(f"Failed to retrieve evidence: {e.message}")
            _fail_job(db, job, e.code, e.message)
            raise AnalysisExecutionError(e.code, e.message)

        logger.info(
            f"Starting packet analysis for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "evidence_path": evidence_path
            }
        )

        # Initialize TShark service
        tshark_service = TSharkService()

        # Step 1: Validate TShark binary
        job.stage = "VALIDATING_TSHARK"
        db.commit()

        is_valid, binary_or_error = tshark_service.validate_binary()
        if not is_valid:
            logger.error(f"TShark binary validation failed: {binary_or_error}")
            _fail_job(db, job, "TSHARK_NOT_FOUND", binary_or_error)
            raise AnalysisExecutionError("TSHARK_NOT_FOUND", binary_or_error)

        # Step 2: Extract packets using TShark
        job.stage = "EXTRACTING_PACKETS"
        job.progress_percent = "10"
        db.commit()

        tshark_result = tshark_service.extract_packets(evidence_path)

        # Handle TShark execution result
        if tshark_result.status == TSharkStatus.NOT_FOUND:
            _fail_job(db, job, "TSHARK_NOT_FOUND", tshark_result.stderr)
            raise AnalysisExecutionError("TSHARK_NOT_FOUND", tshark_result.stderr)

        if tshark_result.status == TSharkStatus.TIMEOUT:
            job.status = JobStatus.TIMEOUT
            job.error_code = "TSHARK_TIMEOUT"
            job.error_message = f"TShark timed out after {tshark_result.duration_seconds:.1f}s"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise AnalysisExecutionError("TSHARK_TIMEOUT", job.error_message)

        if tshark_result.status == TSharkStatus.FAILED:
            error_msg = f"TShark failed with exit code {tshark_result.exit_code}: {tshark_result.stderr[:500]}"
            _fail_job(db, job, "TSHARK_EXECUTION_FAILED", error_msg)
            raise AnalysisExecutionError("TSHARK_EXECUTION_FAILED", error_msg)

        if tshark_result.status == TSharkStatus.INVALID_OUTPUT:
            _fail_job(db, job, "TSHARK_INVALID_OUTPUT", "TShark produced invalid output")
            raise AnalysisExecutionError("TSHARK_INVALID_OUTPUT", "TShark produced invalid output")

        # Step 3: Parse packets
        job.stage = "PARSING_PACKETS"
        job.progress_percent = "40"
        db.commit()

        parser = PacketParser()
        packets = list(parser.parse(tshark_result))
        total_packets = len(packets)

        logger.info(
            f"Parsed {total_packets} packets",
            extra={"job_id": job_id, "total_packets": total_packets}
        )

        # Step 4: Detect protocols
        job.stage = "DETECTING_PROTOCOLS"
        job.progress_percent = "60"
        db.commit()

        detector = ProtocolDetector()
        detector.process_packets(iter(packets))

        protocol_counts = detector.get_protocol_counts()
        email_packets = detector.get_email_packet_count()
        protocols_detected = detector.get_detected_protocols()
        detections = detector.get_detections()
        session_candidates = detector.get_session_candidates()

        # Calculate other packets
        other_packets = total_packets - email_packets - protocol_counts.get("TLS", 0)
        if other_packets < 0:
            other_packets = 0

        logger.info(
            f"Protocol detection complete",
            extra={
                "job_id": job_id,
                "total_packets": total_packets,
                "email_packets": email_packets,
                "protocols_detected": protocols_detected,
            }
        )

        # Step 5: Persist results
        job.stage = "PERSISTING_RESULTS"
        job.progress_percent = "80"
        db.commit()

        # Create message
        if total_packets == 0:
            message = "No packets were detected in this capture."
        elif email_packets == 0:
            message = "No supported email protocols detected in this capture."
        else:
            message = f"Detected {email_packets} email protocol packets across {len(protocols_detected)} protocols."

        # Create PacketAnalysis record
        packet_analysis = PacketAnalysis(
            job_id=job_id,
            evidence_id=job.evidence_id,
            tshark_version=tshark_result.tshark_version,
            analysis_timestamp=datetime.now(timezone.utc),
            duration_seconds=tshark_result.duration_seconds,
            total_packets=total_packets,
            email_packets=email_packets,
            smtp_packets=protocol_counts.get("SMTP", 0),
            imap_packets=protocol_counts.get("IMAP", 0),
            pop3_packets=protocol_counts.get("POP3", 0),
            tls_packets=protocol_counts.get("TLS", 0),
            other_packets=other_packets,
            protocols_detected=protocols_detected,
            protocol_detections=[d.model_dump() for d in detections],
            session_candidates=[c.model_dump() for c in session_candidates],
            message=message,
        )
        db.add(packet_analysis)

        # Step 6: Complete job
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.stage = "COMPLETED"
        job.progress_percent = "100"
        job.error_code = None
        job.error_message = None
        db.commit()

        logger.info(
            f"Phase 2 analysis completed successfully for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "total_packets": total_packets,
                "email_packets": email_packets,
            }
        )

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "packet_analysis_id": packet_analysis.analysis_id,
            "total_packets": total_packets,
            "email_packets": email_packets,
            "protocols_detected": protocols_detected,
        }

    finally:
        # Clean up temporary file if using S3 storage
        if temp_file_cleanup and evidence_path:
            try:
                import os
                temp_path = Path(evidence_path)
                if temp_path.exists():
                    os.unlink(temp_path)
                    logger.debug(f"Cleaned up temporary evidence file: {temp_path}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up temporary file: {cleanup_error}")


def execute_phase3_analysis(db: Session, job_id: str, packet_analysis_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute Phase 3 security analysis.

    This is the core Phase 3 logic extracted from the Celery task.
    Can be called synchronously or asynchronously.

    Args:
        db: Database session
        job_id: Analysis job identifier
        packet_analysis_id: Optional Phase 2 PacketAnalysis ID

    Returns:
        Analysis result dictionary

    Raises:
        AnalysisExecutionError: If analysis fails
    """
    job = None
    security_analysis = None
    start_time = datetime.now(timezone.utc)

    try:
        # Get the analysis job
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            raise AnalysisExecutionError(
                "ANALYSIS_JOB_NOT_FOUND",
                f"Job not found: {job_id}"
            )

        # Update job to RUNNING
        job.status = JobStatus.RUNNING
        job.started_at = start_time
        job.stage = "INITIALIZING_SECURITY_ANALYSIS"
        db.commit()

        logger.info(
            "PHASE3_STARTED",
            extra={
                "event": "PHASE3_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "packet_analysis_id": packet_analysis_id
            }
        )

        # Get Phase 2 packet analysis results
        packet_analysis = None
        if packet_analysis_id:
            packet_analysis = db.query(PacketAnalysis).filter(
                PacketAnalysis.analysis_id == packet_analysis_id
            ).first()
        else:
            packet_analysis = db.query(PacketAnalysis).filter(
                PacketAnalysis.evidence_id == job.evidence_id
            ).first()

        if not packet_analysis:
            logger.warning(
                f"No Phase 2 packet analysis found for job {job_id}. "
                "Will create limited security analysis."
            )

        # Create SecurityAnalysis record
        security_analysis = SecurityAnalysis(
            job_id=job_id,
            evidence_id=job.evidence_id,
            packet_analysis_id=packet_analysis.analysis_id if packet_analysis else None,
            status=SecurityAnalysisStatus.RUNNING,
            started_at=start_time,
            policy_version=get_default_policy().version
        )
        db.add(security_analysis)
        db.commit()

        logger.info(
            f"Starting security analysis for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
            }
        )

        # Initialize services
        stream_reconstructor = TcpStreamReconstructor()
        email_analyzer = EmailSecurityAnalyzer()
        tls_analyzer = TlsAnalyzer()
        certificate_analyzer = CertificateAnalyzer()
        finding_engine = FindingEngine()
        risk_engine = RiskEngine()

        # Step 1: Reconstruct TCP streams
        job.stage = "RECONSTRUCTING_TCP_STREAMS"
        job.progress_percent = "10"
        db.commit()

        if packet_analysis and packet_analysis.session_candidates:
            from app.services.packet.models import PacketRecord, ProtocolSessionCandidate
            packets = _session_candidates_to_packets(packet_analysis.session_candidates)
            stream_reconstructor.process_packets(packets)

        stream_result = stream_reconstructor.get_result(job.evidence_id, job_id)
        streams = stream_reconstructor.get_streams()

        # Step 2: Analyze email security
        job.stage = "ANALYZING_EMAIL_SECURITY"
        job.progress_percent = "25"
        db.commit()

        email_analyzer.analyze_streams(streams)
        email_result = email_analyzer.get_result(job.evidence_id, job_id)
        sessions = email_analyzer.get_sessions()

        # Step 3: Analyze TLS
        job.stage = "ANALYZING_TLS"
        job.progress_percent = "40"
        db.commit()

        tls_analyzer.analyze_sessions(sessions, streams)
        tls_result = tls_analyzer.get_result(job.evidence_id, job_id)
        tls_observations = tls_analyzer.get_observations()

        # Step 4: Analyze certificates
        job.stage = "ANALYZING_CERTIFICATES"
        job.progress_percent = "55"
        db.commit()

        certificate_analyzer.analyze_tls_observations(tls_observations)
        cert_result = certificate_analyzer.get_result(job.evidence_id, job_id)
        certificates = certificate_analyzer.get_certificates()

        # Step 5: Generate findings
        job.stage = "GENERATING_FINDINGS"
        job.progress_percent = "70"
        db.commit()

        logger.info(
            "FINDINGS_ENGINE_STARTED",
            extra={
                "event": "FINDINGS_ENGINE_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "total_streams": len(streams),
                "total_sessions": len(sessions),
                "total_tls_observations": len(tls_observations),
                "total_certificates": len(certificates)
            }
        )

        finding_engine.analyze_streams(
            streams=streams,
            evidence_id=job.evidence_id,
            job_id=job_id
        )

        finding_engine.analyze_email_sessions(
            sessions=sessions,
            evidence_id=job.evidence_id,
            job_id=job_id
        )

        finding_engine.analyze_tls_observations(
            observations=tls_observations,
            evidence_id=job.evidence_id,
            job_id=job_id
        )

        finding_engine.analyze_certificates(
            certificates=certificates,
            evidence_id=job.evidence_id,
            job_id=job_id
        )

        findings_result = finding_engine.get_result(
            evidence_id=job.evidence_id,
            job_id=job_id
        )

        findings = findings_result.findings

        logger.info(
            "FINDINGS_ENGINE_COMPLETED",
            extra={
                "event": "FINDINGS_ENGINE_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "total_findings": findings_result.summary.total_findings,
                "critical_findings": findings_result.summary.critical_count,
                "high_findings": findings_result.summary.high_count,
                "medium_findings": findings_result.summary.medium_count,
                "low_findings": findings_result.summary.low_count,
                "info_findings": findings_result.summary.info_count
            }
        )

        # Step 6: Calculate risk
        job.stage = "CALCULATING_RISK"
        job.progress_percent = "85"
        db.commit()

        # Check if we have email traffic to analyze
        has_email_traffic = email_result.total_sessions > 0

        logger.info(
            "RISK_ENGINE_STARTED",
            extra={
                "event": "RISK_ENGINE_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "has_email_traffic": has_email_traffic,
                "total_findings": findings_result.summary.total_findings,
                "total_streams": stream_result.total_streams,
                "total_sessions": email_result.total_sessions,
                "total_certificates": cert_result.total_certificates
            }
        )

        if has_email_traffic:
            # Standard risk assessment when email traffic exists
            risk_assessment = risk_engine.assess_risk(
                findings_result=findings_result,
                total_streams=stream_result.total_streams,
                total_sessions=email_result.total_sessions,
                total_certificates=cert_result.total_certificates,
                confidence="HIGH" if stream_result.total_streams > 0 else "MEDIUM",
                coverage="COMPLETE" if stream_result.total_streams > 0 else "PARTIAL"
            )
            logger.info(
                "RISK_ENGINE_COMPLETED",
                extra={
                    "event": "RISK_ENGINE_COMPLETED",
                    "job_id": job_id,
                    "evidence_id": job.evidence_id,
                    "phase": "PHASE3",
                    "risk_level": risk_assessment.overall_risk_level,
                    "risk_score": risk_assessment.overall_risk_score,
                    "total_findings": findings_result.summary.total_findings,
                    "has_email_traffic": True
                }
            )
        else:
            # No email traffic detected - use empty assessment
            risk_assessment = risk_engine.assess_empty(
                evidence_id=job.evidence_id,
                job_id=job_id,
                reason="No SMTP, IMAP, or POP3 traffic was detected in the supplied evidence."
            )
            logger.info(
                "RISK_ENGINE_COMPLETED",
                extra={
                    "event": "RISK_ENGINE_COMPLETED",
                    "job_id": job_id,
                    "evidence_id": job.evidence_id,
                    "phase": "PHASE3",
                    "risk_level": "MINIMAL",
                    "risk_score": 100.0,
                    "total_findings": 0,
                    "has_email_traffic": False,
                    "total_streams": stream_result.total_streams,
                    "total_packets": packet_analysis.total_packets if packet_analysis else 0
                }
            )

        # Step 7: Update security analysis with results
        security_analysis.total_streams = stream_result.total_streams
        security_analysis.total_sessions = email_result.total_sessions
        security_analysis.total_tls_observations = tls_result.total_observations
        security_analysis.total_certificates = cert_result.total_certificates

        security_analysis.total_findings = (
            findings_result.summary.total_findings
        )

        security_analysis.critical_findings = (
            findings_result.summary.critical_count
        )
        security_analysis.high_findings = (
            findings_result.summary.high_count
        )
        security_analysis.medium_findings = (
            findings_result.summary.medium_count
        )
        security_analysis.low_findings = (
            findings_result.summary.low_count
        )
        security_analysis.info_findings = (
            findings_result.summary.info_count
        )

        security_analysis.overall_risk_level = (
            risk_assessment.posture.overall_risk.value
        )

        security_analysis.overall_risk_score = (
            risk_assessment.posture.overall_score
        )

        security_analysis.confidence = (
            risk_assessment.posture.confidence
        )

        security_analysis.coverage = (
            risk_assessment.posture.coverage
        )

        logger.info(
            "SECURITY_ANALYSIS_PERSIST_STARTED",
            extra={
                "event": "SECURITY_ANALYSIS_PERSIST_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "streams_to_serialize": len(streams),
                "sessions_to_serialize": len(sessions),
                "tls_observations_to_serialize": len(tls_observations),
                "certificates_to_serialize": len(certificates),
                "findings_to_serialize": len(findings)
            }
        )

        persist_start_time = datetime.now(timezone.utc)

        security_analysis.tcp_streams = [
            stream.model_dump()
            for stream in streams
        ]

        security_analysis.email_sessions = [
            session.model_dump()
            for session in sessions
        ]

        security_analysis.tls_observations = [
            observation.model_dump()
            for observation in tls_observations
        ]

        security_analysis.certificates = [
            certificate.model_dump()
            for certificate in certificates
        ]

        security_analysis.findings = [
            finding.model_dump()
            for finding in findings
        ]

        security_analysis.risk_assessment = (
            risk_assessment.model_dump()
        )

        security_analysis.duration_seconds = (
            datetime.now(timezone.utc) - start_time
        ).total_seconds()

        security_analysis.status = SecurityAnalysisStatus.COMPLETED
        security_analysis.completed_at = datetime.now(timezone.utc)

        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.stage = "COMPLETED"
        job.progress_percent = "100"
        job.error_code = None
        job.error_message = None

        persist_duration = (datetime.now(timezone.utc) - persist_start_time).total_seconds()

        logger.info(
            "SECURITY_ANALYSIS_PERSIST_COMPLETED",
            extra={
                "event": "SECURITY_ANALYSIS_PERSIST_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "persist_duration_seconds": persist_duration
            }
        )

        logger.info(
            "DATABASE_COMMIT_STARTED",
            extra={
                "event": "DATABASE_COMMIT_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3"
            }
        )

        commit_start_time = datetime.now(timezone.utc)
        db.commit()
        commit_duration = (datetime.now(timezone.utc) - commit_start_time).total_seconds()

        logger.info(
            "DATABASE_COMMIT_COMPLETED",
            extra={
                "event": "DATABASE_COMMIT_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "commit_duration_seconds": commit_duration
            }
        )

        total_phase3_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        logger.info(
            "PHASE3_COMPLETED",
            extra={
                "event": "PHASE3_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE3",
                "total_duration_seconds": total_phase3_duration,
                "finding_count": len(findings),
                "risk_level": security_analysis.overall_risk_level,
                "risk_score": security_analysis.overall_risk_score
            }
        )

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "security_analysis_id": security_analysis.analysis_id,
            "finding_count": len(findings),
            "risk_score": risk_assessment.posture.overall_score
        }

    except Exception as e:
        logger.error(f"Phase 3 analysis failed: {e}", exc_info=True)

        # Mark job as failed
        if job:
            job.status = JobStatus.FAILED
            job.error_code = "SECURITY_ANALYSIS_FAILED"
            job.error_message = str(e)[:500]
            job.completed_at = datetime.now(timezone.utc)

        if security_analysis:
            security_analysis.status = SecurityAnalysisStatus.FAILED
            security_analysis.completed_at = datetime.now(timezone.utc)

        db.commit()

        if isinstance(e, AnalysisExecutionError):
            raise
        raise AnalysisExecutionError("SECURITY_ANALYSIS_FAILED", str(e))


def _fail_job(db: Session, job: AnalysisJob, error_code: str, error_message: str):
    """Mark a job as failed with error details."""
    job.status = JobStatus.FAILED
    job.error_code = error_code
    job.error_message = error_message[:500] if error_message else None
    job.completed_at = datetime.now(timezone.utc)
    db.commit()
    logger.error(
        f"Job failed: {job.job_id}",
        extra={"job_id": job.job_id, "error_code": error_code}
    )


def execute_phase4_analysis(
    db: Session,
    job_id: str,
    security_analysis_id: Optional[str] = None,
    enable_ml: bool = False
) -> Dict[str, Any]:
    """
    Execute Phase 4 intelligence analysis.

    This is the core Phase 4 logic for demo mode.
    Can be called synchronously or asynchronously.

    Args:
        db: Database session
        job_id: Analysis job identifier
        security_analysis_id: Optional Phase 3 SecurityAnalysis ID
        enable_ml: Whether to run ML (disabled for demo by default)

    Returns:
        Analysis result dictionary

    Raises:
        AnalysisExecutionError: If analysis fails
    """
    from app.models.intelligence import IntelligenceReport
    from app.services.intelligence import IntelligenceAggregator
    from app.services.intelligence.correlation_engine import CorrelationEngine
    from app.services.intelligence.recommendation_engine import RecommendationEngine
    from app.services.findings.models import SecurityFinding, FindingsResult, FindingSummary
    from app.services.tls.models import TlsObservation
    from app.services.certificates.models import CertificateObservation
    from app.services.email.models import EmailSecuritySession
    from app.services.risk.models import RiskAssessment

    job = None
    intelligence_report = None
    start_time = datetime.now(timezone.utc)

    try:
        # Get the analysis job
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            raise AnalysisExecutionError(
                "ANALYSIS_JOB_NOT_FOUND",
                f"Job not found: {job_id}"
            )

        # Update job to RUNNING
        job.status = JobStatus.RUNNING
        job.started_at = start_time
        job.stage = "INITIALIZING_INTELLIGENCE_ANALYSIS"
        db.commit()

        logger.info(
            "PHASE4_STARTED",
            extra={
                "event": "PHASE4_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE4",
                "security_analysis_id": security_analysis_id,
                "ml_enabled": enable_ml
            }
        )

        # Get Phase 3 security analysis results
        security_analysis = None
        if security_analysis_id:
            security_analysis = db.query(SecurityAnalysis).filter(
                SecurityAnalysis.analysis_id == security_analysis_id
            ).first()
        else:
            security_analysis = db.query(SecurityAnalysis).filter(
                SecurityAnalysis.evidence_id == job.evidence_id,
                SecurityAnalysis.status == SecurityAnalysisStatus.COMPLETED
            ).order_by(SecurityAnalysis.completed_at.desc()).first()

        if not security_analysis:
            raise AnalysisExecutionError(
                "PHASE3_NOT_FOUND",
                "No completed Phase 3 security analysis found"
            )

        # Create IntelligenceReport record
        intelligence_report = IntelligenceReport(
            job_id=job_id,
            evidence_id=job.evidence_id,
            security_analysis_id=security_analysis.analysis_id,
            ml_enabled=enable_ml,
            created_at=start_time,
        )
        db.add(intelligence_report)
        db.commit()

        logger.info(
            f"Starting intelligence analysis for job {job_id}",
            extra={"job_id": job_id, "evidence_id": job.evidence_id}
        )

        # Deserialize Phase 3 data
        findings = [SecurityFinding(**f) for f in (security_analysis.findings or [])]
        tls_observations = [TlsObservation(**o) for o in (security_analysis.tls_observations or [])]
        certificates = [CertificateObservation(**c) for c in (security_analysis.certificates or [])]
        sessions = [EmailSecuritySession(**s) for s in (security_analysis.email_sessions or [])]
        risk_assessment = None
        if security_analysis.risk_assessment:
            risk_assessment = RiskAssessment(**security_analysis.risk_assessment)

        # Build findings result
        findings_result = FindingsResult(
            evidence_id=job.evidence_id,
            job_id=job_id,
            findings=findings,
            summary=FindingSummary(
                total_findings=len(findings),
                critical_count=security_analysis.critical_findings or 0,
                high_count=security_analysis.high_findings or 0,
                medium_count=security_analysis.medium_findings or 0,
                low_count=security_analysis.low_findings or 0,
                info_count=security_analysis.info_findings or 0,
            ),
            streams_analyzed=security_analysis.total_streams or 0,
            sessions_analyzed=security_analysis.total_sessions or 0,
            certificates_analyzed=security_analysis.total_certificates or 0,
        )

        # Step 1: Intelligence Aggregation
        job.stage = "AGGREGATING_INTELLIGENCE"
        job.progress_percent = "10"
        db.commit()

        aggregator = IntelligenceAggregator()
        aggregated_findings, posture, summary = aggregator.aggregate_findings(
            findings_result, risk_assessment
        )

        # Step 2: Correlation Engine
        job.stage = "FINDING_CORRELATIONS"
        job.progress_percent = "30"
        db.commit()

        correlation_engine = CorrelationEngine()
        correlations = correlation_engine.find_correlations(
            findings, tls_observations, certificates, sessions
        )

        # Step 3: Recommendation Engine
        job.stage = "GENERATING_RECOMMENDATIONS"
        job.progress_percent = "50"
        db.commit()

        recommendation_engine = RecommendationEngine()
        recommendations = recommendation_engine.generate_recommendations(
            aggregated_findings, correlations, posture, findings
        )

        # Step 4: ML Analysis (if enabled and sufficient data)
        from app.services.ml.models import MLInsights

        ml_insights = None
        ml_status = "NOT_RUN"

        if enable_ml:
            job.stage = "ML_FEATURE_ENGINEERING"
            job.progress_percent = "50"
            db.commit()

            logger.info(
                "ML_ANALYSIS_STARTED",
                extra={
                    "event": "ML_ANALYSIS_STARTED",
                    "job_id": job_id,
                    "evidence_id": job.evidence_id,
                    "phase": "PHASE4",
                    "total_sessions": len(sessions),
                    "total_tls_observations": len(tls_observations),
                    "total_certificates": len(certificates),
                    "total_findings": len(findings)
                }
            )

            ml_start_time = datetime.now(timezone.utc)

            try:
                from app.services.ml.feature_engineering import FeatureEngineer
                from app.services.ml.anomaly_detector import AnomalyDetector

                logger.info(f"Starting ML analysis for job {job_id}")

                feature_engineer = FeatureEngineer()
                feature_vectors = feature_engineer.extract_all_features(
                    sessions, tls_observations, certificates, findings
                )

                if feature_vectors:
                    job.stage = "ML_ANOMALY_DETECTION"
                    job.progress_percent = "55"
                    db.commit()

                    anomaly_detector = AnomalyDetector()

                    # Fit on current data (trains Isolation Forest)
                    if anomaly_detector.fit(feature_vectors):
                        anomaly_results = anomaly_detector.predict_batch(feature_vectors)
                        ml_insights = anomaly_detector.get_ml_insights(anomaly_results)
                        ml_status = "COMPLETED"

                        ml_duration = (datetime.now(timezone.utc) - ml_start_time).total_seconds()

                        logger.info(
                            "ML_ANALYSIS_COMPLETED",
                            extra={
                                "event": "ML_ANALYSIS_COMPLETED",
                                "job_id": job_id,
                                "evidence_id": job.evidence_id,
                                "phase": "PHASE4",
                                "ml_status": ml_status,
                                "features_extracted": len(feature_vectors),
                                "anomalies_detected": ml_insights.anomalies_detected,
                                "ml_duration_seconds": ml_duration
                            }
                        )
                    else:
                        ml_status = "INSUFFICIENT_DATA"
                        ml_insights = MLInsights(
                            ml_enabled=True,
                            message="Insufficient data for ML analysis (need 5+ sessions)",
                            model_version=None,
                            total_predictions=0,
                            anomalies_detected=0,
                            anomalies=[],
                            top_risk_factors=[],
                            confidence=0.0
                        )
                        ml_duration = (datetime.now(timezone.utc) - ml_start_time).total_seconds()

                        logger.info(
                            "ML_ANALYSIS_COMPLETED",
                            extra={
                                "event": "ML_ANALYSIS_COMPLETED",
                                "job_id": job_id,
                                "evidence_id": job.evidence_id,
                                "phase": "PHASE4",
                                "ml_status": ml_status,
                                "features_extracted": len(feature_vectors),
                                "ml_duration_seconds": ml_duration,
                                "message": "Insufficient data (need 5+ sessions)"
                            }
                        )
                else:
                    ml_status = "NO_FEATURES"
                    ml_insights = MLInsights(
                        ml_enabled=True,
                        message="No features extracted for ML analysis",
                        model_version=None,
                        total_predictions=0,
                        anomalies_detected=0,
                        anomalies=[],
                        top_risk_factors=[],
                        confidence=0.0
                    )
                    ml_duration = (datetime.now(timezone.utc) - ml_start_time).total_seconds()

                    logger.info(
                        "ML_ANALYSIS_COMPLETED",
                        extra={
                            "event": "ML_ANALYSIS_COMPLETED",
                            "job_id": job_id,
                            "evidence_id": job.evidence_id,
                            "phase": "PHASE4",
                            "ml_status": ml_status,
                            "ml_duration_seconds": ml_duration,
                            "message": "No features extracted"
                        }
                    )

            except Exception as ml_error:
                ml_status = "FAILED"
                ml_duration = (datetime.now(timezone.utc) - ml_start_time).total_seconds()

                logger.warning(
                    "ML_ANALYSIS_COMPLETED",
                    extra={
                        "event": "ML_ANALYSIS_COMPLETED",
                        "job_id": job_id,
                        "evidence_id": job.evidence_id,
                        "phase": "PHASE4",
                        "ml_status": ml_status,
                        "ml_duration_seconds": ml_duration,
                        "error": str(ml_error)[:200]
                    },
                    exc_info=True
                )
                ml_insights = MLInsights(
                    ml_enabled=True,
                    message=f"ML analysis failed: {str(ml_error)}",
                    model_version=None,
                    total_predictions=0,
                    anomalies_detected=0,
                    anomalies=[],
                    top_risk_factors=[],
                    confidence=0.0
                )
        else:
            ml_insights = MLInsights(
                ml_enabled=False,
                message="ML disabled in configuration",
                model_version=None,
                total_predictions=0,
                anomalies_detected=0,
                anomalies=[],
                top_risk_factors=[],
                confidence=0.0
            )
            logger.info(
                "ML_ANALYSIS_SKIPPED",
                extra={
                    "event": "ML_ANALYSIS_SKIPPED",
                    "job_id": job_id,
                    "evidence_id": job.evidence_id,
                    "phase": "PHASE4",
                    "reason": "ML disabled in configuration"
                }
            )

        # Step 5: Finalize Intelligence Report
        job.stage = "FINALIZING_INTELLIGENCE"
        job.progress_percent = "65"
        db.commit()

        logger.info(
            "INTELLIGENCE_PERSIST_STARTED",
            extra={
                "event": "INTELLIGENCE_PERSIST_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE4",
                "aggregated_findings_count": len(aggregated_findings),
                "correlations_count": len(correlations),
                "recommendations_count": len(recommendations)
            }
        )

        persist_start_time = datetime.now(timezone.utc)

        # Calculate duration
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Populate intelligence report JSON fields
        intelligence_report.aggregated_findings = [f.model_dump() for f in aggregated_findings]
        intelligence_report.correlation_summary = {
            "total": len(correlations),
            "by_type": {}  # Could be expanded if needed
        }
        intelligence_report.recommendation_summary = {
            "total": len(recommendations),
            "by_priority": {}  # Could be expanded if needed
        }

        # Include ML insights
        if ml_insights:
            intelligence_report.ml_insights = ml_insights.model_dump()
            # Update summary with ML info
            summary.ml_enabled = ml_insights.ml_enabled
            summary.anomalies_detected = ml_insights.anomalies_detected
        else:
            intelligence_report.ml_insights = {"ml_enabled": False, "summary": "ML not executed"}

        # Set counts
        intelligence_report.total_correlations = len(correlations)
        intelligence_report.total_recommendations = len(recommendations)

        # Set security posture scores from posture object
        intelligence_report.security_posture_score = posture.overall_score
        intelligence_report.security_posture_grade = posture.grade.value
        intelligence_report.tls_security_score = posture.tls_security.score
        intelligence_report.certificate_security_score = posture.certificate_security.score
        intelligence_report.protocol_security_score = posture.protocol_security.score
        intelligence_report.configuration_security_score = posture.configuration_security.score

        # Set executive summary from summary object
        intelligence_report.executive_summary = summary.executive_summary if summary.executive_summary else ""

        # Set timestamps and duration
        intelligence_report.completed_at = datetime.now(timezone.utc)
        intelligence_report.duration_seconds = duration

        # CRITICAL: Set status to COMPLETED so frontend can retrieve the report
        intelligence_report.status = IntelligenceStatus.COMPLETED

        # Step 6: Generate Reports (JSON, HTML, PDF)
        job.stage = "GENERATING_REPORTS"
        job.progress_percent = "75"
        db.commit()

        logger.info(f"Generating reports for job {job_id}")

        from app.services.reports import ReportGenerator, ReportFormat
        from app.models.intelligence import GeneratedReport, ReportFormat as DbReportFormat, ReportStatus as DbReportStatus
        from pathlib import Path
        from app.core.config import settings

        # Get reports directory
        reports_dir = Path(getattr(settings, 'REPORTS_DIR', './reports'))
        reports_dir.mkdir(parents=True, exist_ok=True)

        report_generator = ReportGenerator(output_dir=reports_dir)

        # Prepare intelligence result for report generation
        from app.services.intelligence.models import IntelligenceResult
        from app.services.ml.models import MLInsights

        intelligence_result = IntelligenceResult(
            evidence_id=job.evidence_id,
            job_id=job_id,
            aggregated_findings=aggregated_findings,
            correlations=correlations,
            recommendations=recommendations,
            summary=summary
        )

        # Get evidence info
        evidence = db.query(PcapEvidence).filter(
            PcapEvidence.evidence_id == job.evidence_id
        ).first()

        evidence_info = {
            "evidence_id": evidence.evidence_id if evidence else job.evidence_id,
            "original_filename": evidence.original_filename if evidence else "unknown",
            "sha256": evidence.sha256 if evidence else "",
            "file_size_bytes": evidence.file_size_bytes if evidence else 0,
            "upload_timestamp": evidence.upload_timestamp if evidence else None,
            "case_id": evidence.case_id if evidence else None,
            "packets_analyzed": security_analysis.total_streams if security_analysis else 0,
        }

        # ML insights already computed above (lines 760-834) - use those results for reporting
        # Do NOT overwrite ml_insights here

        # Generate JSON report
        try:
            json_report_info = report_generator.generate_report(
                intelligence_result, evidence_info, ml_insights, ReportFormat.JSON
            )

            db_json_report = GeneratedReport(
                intelligence_report_id=intelligence_report.report_id,
                evidence_id=job.evidence_id,
                format=DbReportFormat.JSON,
                status=DbReportStatus.COMPLETED if json_report_info.status.value == "COMPLETED" else DbReportStatus.FAILED,
                filename=json_report_info.filename,
                file_size_bytes=json_report_info.file_size_bytes,
                content_hash=json_report_info.content_hash,
                generated_at=json_report_info.generated_at,
                error_message=json_report_info.error_message,
            )
            db.add(db_json_report)
            logger.info(f"JSON report generated: {json_report_info.filename}")
        except Exception as e:
            logger.warning(f"JSON report generation failed: {e}", exc_info=True)

        # Generate HTML report
        try:
            html_report_info = report_generator.generate_report(
                intelligence_result, evidence_info, ml_insights, ReportFormat.HTML
            )

            db_html_report = GeneratedReport(
                intelligence_report_id=intelligence_report.report_id,
                evidence_id=job.evidence_id,
                format=DbReportFormat.HTML,
                status=DbReportStatus.COMPLETED if html_report_info.status.value == "COMPLETED" else DbReportStatus.FAILED,
                filename=html_report_info.filename,
                file_size_bytes=html_report_info.file_size_bytes,
                content_hash=html_report_info.content_hash,
                generated_at=html_report_info.generated_at,
                error_message=html_report_info.error_message,
            )
            db.add(db_html_report)
            logger.info(f"HTML report generated: {html_report_info.filename}")
        except Exception as e:
            logger.warning(f"HTML report generation failed: {e}", exc_info=True)

        # Generate PDF report (optional, may fail if weasyprint not available)
        try:
            pdf_report_info = report_generator.generate_report(
                intelligence_result, evidence_info, ml_insights, ReportFormat.PDF
            )

            db_pdf_report = GeneratedReport(
                intelligence_report_id=intelligence_report.report_id,
                evidence_id=job.evidence_id,
                format=DbReportFormat.PDF,
                status=DbReportStatus.COMPLETED if pdf_report_info.status.value == "COMPLETED" else DbReportStatus.FAILED,
                filename=pdf_report_info.filename,
                file_size_bytes=pdf_report_info.file_size_bytes,
                content_hash=pdf_report_info.content_hash,
                generated_at=pdf_report_info.generated_at,
                error_message=pdf_report_info.error_message,
            )
            db.add(db_pdf_report)
            logger.info(f"PDF report generated: {pdf_report_info.filename}")
        except Exception as e:
            logger.warning(f"PDF report generation failed (continuing): {e}", exc_info=True)

        # Complete job
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.stage = "COMPLETED"
        job.progress_percent = "100"

        persist_duration = (datetime.now(timezone.utc) - persist_start_time).total_seconds()

        logger.info(
            "INTELLIGENCE_PERSIST_COMPLETED",
            extra={
                "event": "INTELLIGENCE_PERSIST_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE4",
                "persist_duration_seconds": persist_duration
            }
        )

        logger.info(
            "DATABASE_COMMIT_STARTED",
            extra={
                "event": "DATABASE_COMMIT_STARTED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE4"
            }
        )

        commit_start_time = datetime.now(timezone.utc)
        db.commit()
        commit_duration = (datetime.now(timezone.utc) - commit_start_time).total_seconds()

        logger.info(
            "DATABASE_COMMIT_COMPLETED",
            extra={
                "event": "DATABASE_COMMIT_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE4",
                "commit_duration_seconds": commit_duration
            }
        )

        total_phase4_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        logger.info(
            "PHASE4_COMPLETED",
            extra={
                "event": "PHASE4_COMPLETED",
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "phase": "PHASE4",
                "total_duration_seconds": total_phase4_duration,
                "posture_grade": posture.grade.value,
                "posture_score": posture.overall_score,
                "correlations_count": len(correlations),
                "recommendations_count": len(recommendations),
                "ml_status": ml_status
            }
        )

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "intelligence_report_id": intelligence_report.report_id,
            "posture_grade": posture.grade.value,
            "recommendation_count": len(recommendations)
        }

    except Exception as e:
        logger.error(f"Phase 4 analysis failed: {e}", exc_info=True)

        # Mark job as failed
        if job:
            job.status = JobStatus.FAILED
            job.error_code = "INTELLIGENCE_ANALYSIS_FAILED"
            job.error_message = str(e)[:500]
            job.completed_at = datetime.now(timezone.utc)

        if intelligence_report:
            intelligence_report.completed_at = datetime.now(timezone.utc)

        db.commit()

        if isinstance(e, AnalysisExecutionError):
            raise
        raise AnalysisExecutionError("INTELLIGENCE_ANALYSIS_FAILED", str(e))


def _session_candidates_to_packets(session_candidates: list) -> list:
    """Convert session candidates back to packet records for stream reconstruction."""
    from app.services.packet.models import PacketRecord, ProtocolSessionCandidate

    packets = []
    for candidate_dict in session_candidates:
        candidate = ProtocolSessionCandidate(**candidate_dict)
        # Create a minimal packet record for stream reconstruction
        packet = PacketRecord(
            frame_number=0,  # Not needed for stream reconstruction
            timestamp=0.0,
            src_ip=candidate.client_ip,
            dst_ip=candidate.server_ip,
            src_port=candidate.client_port,
            dst_port=candidate.server_port,
            protocol=candidate.protocol,
            length=0,
            info="",
            tcp_stream=None,
            tcp_flags=None,
            tls_record_type=None,
            email_command=None
        )
        packets.append(packet)
    return packets
