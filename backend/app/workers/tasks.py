"""Celery tasks for SecureMailScope analysis.

Phase 2 implements packet analysis using TShark.

Retry Policy:
- TShark failures (TSHARK_NOT_FOUND, TSHARK_EXECUTION_FAILED, TSHARK_TIMEOUT): NO retry
- Evidence failures (EVIDENCE_NOT_FOUND): NO retry
- Transient database failures: Retry max 2 times with 10s backoff

Worker Crash Recovery:
- On startup, RUNNING jobs are marked FAILED with WORKER_CRASH_RECOVERY
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from celery import Task
from celery.exceptions import Reject
from sqlalchemy.exc import OperationalError, InterfaceError

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.config import settings
from app.models.analysis_job import AnalysisJob, JobStatus, JobType, generate_job_id
from app.models.evidence import PcapEvidence
from app.models.packet_analysis import PacketAnalysis
from app.services.packet import (
    TSharkService,
    TSharkStatus,
    PacketParser,
    ProtocolDetector,
)
from app.services.ingestion.storage import evidence_storage, StorageError

logger = logging.getLogger(__name__)


# Database retry configuration
DB_MAX_RETRIES = 2
DB_RETRY_COUNTDOWN = 10


class AnalysisTask(Task):
    """Base task with database retry handling."""

    autoretry_for = (OperationalError, InterfaceError)
    retry_kwargs = {'max_retries': DB_MAX_RETRIES, 'countdown': DB_RETRY_COUNTDOWN}
    retry_backoff = False  # Use fixed countdown instead


def recover_crashed_jobs():
    """
    Recover jobs that were RUNNING when worker crashed.

    Called on worker startup. Marks any RUNNING jobs as FAILED
    with error_code WORKER_CRASH_RECOVERY.
    """
    db = SessionLocal()
    try:
        running_jobs = db.query(AnalysisJob).filter(
            AnalysisJob.status == JobStatus.RUNNING
        ).all()

        for job in running_jobs:
            logger.warning(
                f"Recovering crashed job: {job.job_id}",
                extra={"job_id": job.job_id, "evidence_id": job.evidence_id}
            )
            job.status = JobStatus.FAILED
            job.error_code = "WORKER_CRASH_RECOVERY"
            job.error_message = "Job was interrupted by worker crash or restart"
            job.completed_at = datetime.now(timezone.utc)

        if running_jobs:
            db.commit()
            logger.info(f"Recovered {len(running_jobs)} crashed jobs")
    except Exception as e:
        logger.error(f"Error during crash recovery: {e}")
        db.rollback()
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.health_check_task")
def health_check_task() -> dict[str, str]:
    """Simple health check task to verify Celery is working.

    Returns:
        Task execution status
    """
    logger.info("Health check task executed successfully")
    return {
        "status": "success",
        "message": "Celery worker is operational"
    }


@celery_app.task(
    name="app.workers.tasks.analyze_evidence",
    bind=True,
    base=AnalysisTask,
    acks_late=True,
)
def analyze_evidence(self, job_id: str) -> dict:
    """
    Analyze PCAP evidence using TShark for protocol detection.

    Phase 2 implementation performs:
    1. TShark binary validation (fails fast if missing)
    2. Packet extraction from evidence
    3. Protocol detection (SMTP, IMAP, POP3, TLS)
    4. Persistence of results

    Args:
        job_id: Analysis job identifier

    Returns:
        Analysis result dictionary

    Note:
        - TShark failures are NOT retried
        - Only transient DB errors trigger retry (max 2)
    """
    db = SessionLocal()
    job = None

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
        job.started_at = datetime.now(timezone.utc)
        job.stage = "INITIALIZING"
        db.commit()

        # Get evidence
        evidence = db.query(PcapEvidence).filter(
            PcapEvidence.evidence_id == job.evidence_id
        ).first()

        if not evidence:
            logger.error(f"Evidence not found: {job.evidence_id}")
            _fail_job(db, job, "EVIDENCE_NOT_FOUND", f"Evidence not found: {job.evidence_id}")
            return {"status": "FAILED", "error_code": "EVIDENCE_NOT_FOUND"}

        # Get evidence path through storage abstraction
        # This works for both local and S3 storage
        # For S3, this downloads the file to a temp path
        try:
            storage_key = evidence.stored_filename
            if not storage_key:
                _fail_job(db, job, "EVIDENCE_NOT_FOUND", "Evidence storage key is missing")
                return {"status": "FAILED", "error_code": "EVIDENCE_NOT_FOUND"}

            evidence_path = str(evidence_storage.get_path(storage_key))
            temp_file_cleanup = settings.storage_backend.lower() == "s3"  # Flag for cleanup
        except StorageError as e:
            logger.error(f"Failed to retrieve evidence: {e.message}")
            _fail_job(db, job, e.code, e.message)
            return {"status": "FAILED", "error_code": e.code}

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

        # Step 1: Validate TShark binary BEFORE any analysis
        job.stage = "VALIDATING_TSHARK"
        db.commit()

        is_valid, binary_or_error = tshark_service.validate_binary()
        if not is_valid:
            logger.error(f"TShark binary validation failed: {binary_or_error}")
            _fail_job(db, job, "TSHARK_NOT_FOUND", binary_or_error)
            # No retry for TShark not found
            return {"status": "FAILED", "error_code": "TSHARK_NOT_FOUND"}

        # Step 2: Extract packets using TShark
        job.stage = "EXTRACTING_PACKETS"
        job.progress_percent = "10"
        db.commit()

        tshark_result = tshark_service.extract_packets(evidence_path)

        # Handle TShark execution result
        if tshark_result.status == TSharkStatus.NOT_FOUND:
            _fail_job(db, job, "TSHARK_NOT_FOUND", tshark_result.stderr)
            return {"status": "FAILED", "error_code": "TSHARK_NOT_FOUND"}

        if tshark_result.status == TSharkStatus.TIMEOUT:
            job.status = JobStatus.TIMEOUT
            job.error_code = "TSHARK_TIMEOUT"
            job.error_message = f"TShark timed out after {tshark_result.duration_seconds:.1f}s"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error(f"TShark timeout for job {job_id}")
            # No retry for timeout
            return {"status": "TIMEOUT", "error_code": "TSHARK_TIMEOUT"}

        if tshark_result.status == TSharkStatus.FAILED:
            _fail_job(
                db, job,
                "TSHARK_EXECUTION_FAILED",
                f"TShark failed with exit code {tshark_result.exit_code}: {tshark_result.stderr[:500]}"
            )
            # No retry for execution failure
            return {"status": "FAILED", "error_code": "TSHARK_EXECUTION_FAILED"}

        if tshark_result.status == TSharkStatus.INVALID_OUTPUT:
            _fail_job(db, job, "TSHARK_INVALID_OUTPUT", "TShark produced invalid output")
            return {"status": "FAILED", "error_code": "TSHARK_INVALID_OUTPUT"}

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
                "smtp_packets": protocol_counts.get("SMTP", 0),
                "imap_packets": protocol_counts.get("IMAP", 0),
                "pop3_packets": protocol_counts.get("POP3", 0),
                "tls_packets": protocol_counts.get("TLS", 0),
            }
        )

        # Step 5: Persist results
        job.stage = "PERSISTING_RESULTS"
        job.progress_percent = "80"
        db.commit()

        # Create message based on results
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
            f"Analysis completed successfully for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "total_packets": total_packets,
                "email_packets": email_packets,
                "duration_seconds": tshark_result.duration_seconds
            }
        )

        # Step 7: Chain to Phase 3 Security Analysis
        phase3_job_id = _trigger_phase3_analysis(db, job.evidence_id, packet_analysis.analysis_id)

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "total_packets": total_packets,
            "email_packets": email_packets,
            "protocols_detected": protocols_detected,
            "phase3_job_id": phase3_job_id,
        }

    except (OperationalError, InterfaceError) as e:
        # These are transient DB errors - let Celery retry
        logger.warning(f"Database error in analysis task: {e}, will retry")
        db.rollback()
        raise  # Celery will handle retry based on AnalysisTask config

    except Exception as e:
        logger.error(f"Unexpected error in analysis task: {e}", exc_info=True)
        db.rollback()

        # Try to mark job as failed
        if job:
            try:
                job.status = JobStatus.FAILED
                job.error_code = "PACKET_ANALYSIS_FAILED"
                job.error_message = str(e)[:500]
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception:
                pass

        return {
            "status": "FAILED",
            "error_code": "PACKET_ANALYSIS_FAILED",
            "error_message": str(e)
        }

    finally:
        # Clean up temporary file if using S3 storage
        if 'temp_file_cleanup' in locals() and temp_file_cleanup and 'evidence_path' in locals():
            try:
                import os
                from pathlib import Path
                temp_path = Path(evidence_path)
                if temp_path.exists():
                    os.unlink(temp_path)
                    logger.debug(f"Cleaned up temporary evidence file: {temp_path}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up temporary file: {cleanup_error}")

        db.close()


def _fail_job(db, job: AnalysisJob, error_code: str, error_message: str):
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


def _trigger_phase3_analysis(db, evidence_id: str, packet_analysis_id: str) -> str:
    """
    Trigger Phase 3 security analysis after Phase 2 completes.

    Returns the Phase 3 job ID.
    """
    from app.workers.security_tasks import run_security_analysis

    # Create Phase 3 job
    phase3_job_id = generate_job_id()
    phase3_job = AnalysisJob(
        job_id=phase3_job_id,
        evidence_id=evidence_id,
        job_type=JobType.TLS_ANALYSIS,
        status=JobStatus.QUEUED,
        stage="QUEUED_FOR_SECURITY_ANALYSIS"
    )
    db.add(phase3_job)
    db.commit()

    logger.info(
        f"Triggering Phase 3 security analysis",
        extra={
            "phase3_job_id": phase3_job_id,
            "evidence_id": evidence_id,
            "packet_analysis_id": packet_analysis_id
        }
    )

    # Enqueue Phase 3 task
    run_security_analysis.delay(phase3_job_id, packet_analysis_id)

    return phase3_job_id


# Register worker startup handler for crash recovery
@celery_app.on_after_configure.connect
def setup_crash_recovery(sender, **kwargs):
    """Set up crash recovery on worker startup."""
    recover_crashed_jobs()
