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

        findings = finding_engine.generate_findings(
            streams=streams,
            sessions=sessions,
            tls_observations=tls_observations,
            certificates=certificates,
            evidence_id=job.evidence_id,
            job_id=job_id
        )

        # Step 6: Calculate risk
        job.stage = "CALCULATING_RISK"
        job.progress_percent = "85"
        db.commit()

        risk_assessment = risk_engine.assess_risk(
            findings=findings,
            sessions=sessions,
            tls_observations=tls_observations,
            certificates=certificates
        )

        # Step 7: Update security analysis with results
        security_analysis.tcp_stream_count = stream_result.total_streams
        security_analysis.tcp_complete_count = stream_result.complete_streams
        security_analysis.tcp_partial_count = stream_result.partial_streams
        security_analysis.email_session_count = email_result.total_sessions
        security_analysis.smtp_session_count = email_result.smtp_sessions
        security_analysis.imap_session_count = email_result.imap_sessions
        security_analysis.pop3_session_count = email_result.pop3_sessions
        security_analysis.tls_observation_count = tls_result.total_observations
        security_analysis.modern_tls_count = tls_result.modern_tls_count
        security_analysis.deprecated_tls_count = tls_result.deprecated_tls_count
        security_analysis.certificate_count = cert_result.total_certificates
        security_analysis.valid_certificate_count = cert_result.valid_count
        security_analysis.expired_certificate_count = cert_result.expired_count
        security_analysis.weak_key_count = cert_result.weak_key_count
        security_analysis.finding_count = len(findings)
        security_analysis.critical_count = risk_assessment.get("critical_count", 0)
        security_analysis.high_count = risk_assessment.get("high_count", 0)
        security_analysis.medium_count = risk_assessment.get("medium_count", 0)
        security_analysis.low_count = risk_assessment.get("low_count", 0)
        security_analysis.risk_score = risk_assessment.get("risk_score", 0.0)
        security_analysis.status = SecurityAnalysisStatus.COMPLETED
        security_analysis.completed_at = datetime.now(timezone.utc)

        # Complete job
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.stage = "COMPLETED"
        job.progress_percent = "100"
        db.commit()

        logger.info(
            f"Phase 3 security analysis completed successfully for job {job_id}",
            extra={"job_id": job_id, "finding_count": len(findings)}
        )

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "security_analysis_id": security_analysis.analysis_id,
            "finding_count": len(findings),
            "risk_score": risk_assessment.get("risk_score", 0.0)
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
