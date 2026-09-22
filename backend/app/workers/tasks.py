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
from app.services.analysis_executor import execute_phase2_analysis, AnalysisExecutionError

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

    try:
        # Use the extracted executor service
        result = execute_phase2_analysis(db, job_id)

        # Chain to Phase 3
        phase3_job_id = _trigger_phase3_analysis(
            db,
            result.get("evidence_id") or db.query(AnalysisJob).filter(
                AnalysisJob.job_id == job_id
            ).first().evidence_id,
            result["packet_analysis_id"]
        )

        result["phase3_job_id"] = phase3_job_id
        return result

    except AnalysisExecutionError as e:
        logger.error(f"Analysis execution failed: {e.code} - {e.message}")
        return {
            "status": "FAILED",
            "error_code": e.code,
            "error_message": e.message
        }

    except (OperationalError, InterfaceError) as e:
        logger.warning(f"Database error in analysis task: {e}, will retry")
        db.rollback()
        raise

    except Exception as e:
        logger.error(f"Unexpected error in analysis task: {e}", exc_info=True)
        db.rollback()
        return {
            "status": "FAILED",
            "error_code": "PACKET_ANALYSIS_FAILED",
            "error_message": str(e)
        }

    finally:
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
