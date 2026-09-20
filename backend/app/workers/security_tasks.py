"""Phase 3 Celery tasks for security analysis.

Phase 3 Security Intelligence Engine task.

IMPORTANT: This task is SEPARATE from Phase 2 analyze_evidence.
It consumes Phase 2 results and DOES NOT re-run TShark.

This task:
1. Reads Phase 2 packet analysis results
2. Reconstructs TCP streams
3. Analyzes email security (STARTTLS/STLS)
4. Analyzes TLS observations
5. Analyzes certificates
6. Generates security findings
7. Calculates risk assessment
8. Persists results to security_analyses table

Boundary Enforcement:
- NO TShark calls
- NO ML inference
- NO PDF generation
- NO blockchain
- Deterministic analysis only
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from celery import Task
from sqlalchemy.exc import OperationalError, InterfaceError

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.analysis_job import AnalysisJob, JobStatus, JobType
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.services.packet.models import PacketRecord, ProtocolSessionCandidate

# Phase 3 services
from app.services.tcp import TcpStreamReconstructor
from app.services.email import EmailSecurityAnalyzer
from app.services.tls import TlsAnalyzer
from app.services.certificates import CertificateAnalyzer
from app.services.crypto import RulesEngine, get_default_policy
from app.services.findings import FindingEngine
from app.services.risk import RiskEngine

logger = logging.getLogger(__name__)

# Database retry configuration
DB_MAX_RETRIES = 2
DB_RETRY_COUNTDOWN = 10


class SecurityAnalysisTask(Task):
    """Base task with database retry handling for security analysis."""

    autoretry_for = (OperationalError, InterfaceError)
    retry_kwargs = {'max_retries': DB_MAX_RETRIES, 'countdown': DB_RETRY_COUNTDOWN}
    retry_backoff = False


@celery_app.task(
    name="app.workers.security_tasks.run_security_analysis",
    bind=True,
    base=SecurityAnalysisTask,
    acks_late=True,
)
def run_security_analysis(
    self,
    job_id: str,
    packet_analysis_id: Optional[str] = None
) -> dict:
    """
    Run Phase 3 security analysis on Phase 2 results.

    IMPORTANT: This task does NOT re-run TShark.
    It consumes Phase 2 PacketAnalysis results.

    Args:
        job_id: Analysis job identifier (Phase 3 job)
        packet_analysis_id: Optional Phase 2 PacketAnalysis ID.
            If not provided, looks up by evidence_id.

    Returns:
        Analysis result dictionary
    """
    db = SessionLocal()
    job = None
    security_analysis = None
    start_time = datetime.now(timezone.utc)

    try:
        # Get the analysis job
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            logger.error(f"Analysis job not found: {job_id}")
            return {
                "status": "FAILED",
                "error_code": "ANALYSIS_JOB_NOT_FOUND",
                "error_message": f"Job not found: {job_id}"
            }

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
            # Look up by evidence_id
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
                "packet_analysis_id": packet_analysis.analysis_id if packet_analysis else None
            }
        )

        # Initialize services
        stream_reconstructor = TcpStreamReconstructor()
        email_analyzer = EmailSecurityAnalyzer()
        tls_analyzer = TlsAnalyzer()
        certificate_analyzer = CertificateAnalyzer()
        finding_engine = FindingEngine()
        risk_engine = RiskEngine()

        # Step 1: Reconstruct TCP streams from Phase 2 session candidates
        job.stage = "RECONSTRUCTING_TCP_STREAMS"
        job.progress_percent = "10"
        db.commit()

        if packet_analysis and packet_analysis.session_candidates:
            # Convert session candidates to packet records for stream reconstruction
            packets = _session_candidates_to_packets(packet_analysis.session_candidates)
            stream_reconstructor.process_packets(packets)

        stream_result = stream_reconstructor.get_result(job.evidence_id, job_id)
        streams = stream_reconstructor.get_streams()

        logger.info(
            f"TCP stream reconstruction complete",
            extra={
                "job_id": job_id,
                "total_streams": stream_result.total_streams
            }
        )

        # Step 2: Analyze email security
        job.stage = "ANALYZING_EMAIL_SECURITY"
        job.progress_percent = "25"
        db.commit()

        email_analyzer.analyze_streams(streams)
        email_result = email_analyzer.get_result(job.evidence_id, job_id)
        sessions = email_analyzer.get_sessions()

        logger.info(
            f"Email security analysis complete",
            extra={
                "job_id": job_id,
                "total_sessions": email_result.total_sessions
            }
        )

        # Step 3: Analyze TLS observations
        job.stage = "ANALYZING_TLS"
        job.progress_percent = "40"
        db.commit()

        tls_analyzer.analyze_sessions(sessions, streams)
        tls_result = tls_analyzer.get_result(job.evidence_id, job_id)
        tls_observations = tls_analyzer.get_observations()

        logger.info(
            f"TLS analysis complete",
            extra={
                "job_id": job_id,
                "total_observations": tls_result.total_observations
            }
        )

        # Step 4: Analyze certificates
        job.stage = "ANALYZING_CERTIFICATES"
        job.progress_percent = "55"
        db.commit()

        certificate_analyzer.analyze_tls_observations(tls_observations)
        cert_result = certificate_analyzer.get_result(job.evidence_id, job_id)
        certificates = certificate_analyzer.get_certificates()

        logger.info(
            f"Certificate analysis complete",
            extra={
                "job_id": job_id,
                "total_certificates": cert_result.total_certificates
            }
        )

        # Step 5: Generate findings
        job.stage = "GENERATING_FINDINGS"
        job.progress_percent = "70"
        db.commit()

        finding_engine.analyze_streams(streams, job.evidence_id, job_id)
        finding_engine.analyze_email_sessions(sessions, job.evidence_id, job_id)
        finding_engine.analyze_tls_observations(tls_observations, job.evidence_id, job_id)
        finding_engine.analyze_certificates(certificates, job.evidence_id, job_id)
        findings_result = finding_engine.get_result(job.evidence_id, job_id)

        logger.info(
            f"Finding generation complete",
            extra={
                "job_id": job_id,
                "total_findings": findings_result.summary.total_findings
            }
        )

        # Step 6: Calculate risk assessment
        job.stage = "CALCULATING_RISK"
        job.progress_percent = "85"
        db.commit()

        risk_assessment = risk_engine.assess_risk(
            findings_result,
            total_streams=len(streams),
            total_sessions=len(sessions),
            total_certificates=len(certificates),
            confidence=_determine_confidence(packet_analysis),
            coverage=_determine_coverage(packet_analysis)
        )

        logger.info(
            f"Risk assessment complete",
            extra={
                "job_id": job_id,
                "overall_risk": risk_assessment.posture.overall_risk.value,
                "overall_score": risk_assessment.posture.overall_score
            }
        )

        # Step 7: Persist results
        job.stage = "PERSISTING_RESULTS"
        job.progress_percent = "95"
        db.commit()

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Update SecurityAnalysis with results
        security_analysis.status = SecurityAnalysisStatus.COMPLETED
        security_analysis.completed_at = end_time
        security_analysis.duration_seconds = duration

        # Counts
        security_analysis.total_streams = len(streams)
        security_analysis.total_sessions = len(sessions)
        security_analysis.total_tls_observations = len(tls_observations)
        security_analysis.total_certificates = len(certificates)
        security_analysis.total_findings = findings_result.summary.total_findings

        # Finding severities
        security_analysis.critical_findings = findings_result.summary.critical_count
        security_analysis.high_findings = findings_result.summary.high_count
        security_analysis.medium_findings = findings_result.summary.medium_count
        security_analysis.low_findings = findings_result.summary.low_count
        security_analysis.info_findings = findings_result.summary.info_count

        # Risk
        security_analysis.overall_risk_level = risk_assessment.posture.overall_risk.value
        security_analysis.overall_risk_score = risk_assessment.posture.overall_score

        # Metadata
        security_analysis.confidence = risk_assessment.posture.confidence
        security_analysis.coverage = risk_assessment.posture.coverage

        # JSON data
        security_analysis.tcp_streams = [s.model_dump() for s in streams]
        security_analysis.email_sessions = [s.model_dump() for s in sessions]
        security_analysis.tls_observations = [o.model_dump() for o in tls_observations]
        security_analysis.certificates = [c.model_dump() for c in certificates]
        security_analysis.findings = [f.model_dump() for f in findings_result.findings]
        security_analysis.risk_assessment = risk_assessment.model_dump()

        # Update job
        job.status = JobStatus.COMPLETED
        job.completed_at = end_time
        job.stage = "COMPLETED"
        job.progress_percent = "100"
        job.error_code = None
        job.error_message = None

        db.commit()

        logger.info(
            f"Security analysis completed successfully for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "duration_seconds": duration,
                "total_findings": findings_result.summary.total_findings,
                "overall_risk": risk_assessment.posture.overall_risk.value
            }
        )

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "analysis_id": security_analysis.analysis_id,
            "total_streams": len(streams),
            "total_sessions": len(sessions),
            "total_findings": findings_result.summary.total_findings,
            "overall_risk": risk_assessment.posture.overall_risk.value,
            "overall_score": risk_assessment.posture.overall_score,
            "duration_seconds": duration
        }

    except (OperationalError, InterfaceError) as e:
        logger.warning(f"Database error in security analysis task: {e}, will retry")
        db.rollback()
        raise  # Let Celery handle retry

    except Exception as e:
        logger.error(f"Unexpected error in security analysis task: {e}", exc_info=True)
        db.rollback()

        # Try to mark as failed
        if security_analysis:
            try:
                security_analysis.status = SecurityAnalysisStatus.FAILED
                security_analysis.error_code = "SECURITY_ANALYSIS_FAILED"
                security_analysis.error_message = str(e)[:500]
                security_analysis.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception:
                db.rollback()

        if job:
            try:
                job.status = JobStatus.FAILED
                job.error_code = "SECURITY_ANALYSIS_FAILED"
                job.error_message = str(e)[:500]
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception:
                pass

        return {
            "status": "FAILED",
            "error_code": "SECURITY_ANALYSIS_FAILED",
            "error_message": str(e)
        }

    finally:
        db.close()


def _session_candidates_to_packets(
    session_candidates: list[dict]
) -> list[PacketRecord]:
    """
    Convert Phase 2 session candidates to packet records.

    Phase 2 stores aggregate session candidate data, not individual packets.
    This function creates synthetic packet records for stream reconstruction.
    """
    packets = []
    for candidate in session_candidates:
        # Create a representative packet for each session candidate
        packet = PacketRecord(
            frame_number=candidate.get("first_packet_number", 0),
            timestamp=candidate.get("start_time"),
            src_ip=candidate.get("client_ip", ""),
            dst_ip=candidate.get("server_ip", ""),
            src_port=candidate.get("client_port", 0),
            dst_port=candidate.get("server_port", 0),
            protocol=candidate.get("protocol", "TCP"),
            stream_id=candidate.get("stream_id"),
            tcp_flags=0,
            tcp_seq=0,
            tcp_ack=0,
            payload_length=candidate.get("packet_count", 0),
            info=f"Session candidate for {candidate.get('protocol', 'unknown')}"
        )
        packets.append(packet)

        # If we have packet count > 1, create additional synthetic packets
        # to represent the session's data volume
        packet_count = candidate.get("packet_count", 1)
        if packet_count > 1:
            # Add a second packet to represent the response direction
            response_packet = PacketRecord(
                frame_number=candidate.get("first_packet_number", 0) + 1,
                timestamp=candidate.get("start_time"),
                src_ip=candidate.get("server_ip", ""),
                dst_ip=candidate.get("client_ip", ""),
                src_port=candidate.get("server_port", 0),
                dst_port=candidate.get("client_port", 0),
                protocol=candidate.get("protocol", "TCP"),
                stream_id=candidate.get("stream_id"),
                tcp_flags=0,
                tcp_seq=0,
                tcp_ack=0,
                payload_length=0,
                info=f"Response for {candidate.get('protocol', 'unknown')}"
            )
            packets.append(response_packet)

    return packets


def _determine_confidence(packet_analysis: Optional[PacketAnalysis]) -> str:
    """Determine analysis confidence based on Phase 2 results."""
    if not packet_analysis:
        return "LOW"

    if packet_analysis.total_packets == 0:
        return "LOW"

    if packet_analysis.email_packets == 0:
        return "MEDIUM"  # No email traffic, but analyzed successfully

    return "HIGH"


def _determine_coverage(packet_analysis: Optional[PacketAnalysis]) -> str:
    """Determine analysis coverage based on Phase 2 results."""
    if not packet_analysis:
        return "UNKNOWN"

    if packet_analysis.total_packets == 0:
        return "UNKNOWN"

    # Check if we have session candidates
    if packet_analysis.session_candidates:
        return "COMPLETE"

    return "PARTIAL"
