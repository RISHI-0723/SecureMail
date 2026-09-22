"""Demo mode background execution without Celery/Redis.

This module provides background task execution for free demo deployments
where Celery and Redis are not available. Tasks run in background threads
within the same process.

IMPORTANT: This is NOT for production. Production must use Celery.
"""
import logging
import threading
from typing import Optional
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.services.analysis_executor import (
    execute_phase2_analysis,
    execute_phase3_analysis,
    execute_phase4_analysis,
    AnalysisExecutionError
)
from app.models.analysis_job import AnalysisJob, JobStatus, JobType, generate_job_id

logger = logging.getLogger(__name__)


class DemoExecutor:
    """
    Background task executor for demo mode.

    Executes analysis phases in background threads and updates
    job status in the database. Frontend can poll for status.
    """

    @staticmethod
    def execute_full_analysis_background(
        evidence_id: str,
        phase2_job_id: str
    ) -> None:
        """
        Execute full analysis pipeline (Phase 2→3→4) in background thread.

        This method spawns a background thread that:
        1. Executes Phase 2 packet analysis
        2. Creates and executes Phase 3 security analysis
        3. Creates and executes Phase 4 intelligence analysis
        4. Updates job statuses throughout

        The HTTP request returns immediately while analysis continues.

        Args:
            evidence_id: Evidence identifier
            phase2_job_id: Phase 2 job identifier
        """
        thread = threading.Thread(
            target=DemoExecutor._run_full_analysis,
            args=(evidence_id, phase2_job_id),
            daemon=True,
            name=f"demo-analysis-{phase2_job_id[:8]}"
        )
        thread.start()
        logger.info(
            f"Demo analysis started in background thread: {thread.name}",
            extra={"evidence_id": evidence_id, "job_id": phase2_job_id}
        )

    @staticmethod
    def _run_full_analysis(evidence_id: str, phase2_job_id: str) -> None:
        """
        Internal method that runs the full analysis pipeline.

        This runs in a background thread with its own database session.
        """
        db: Optional[Session] = None
        phase3_job_id: Optional[str] = None
        phase4_job_id: Optional[str] = None

        try:
            # Create database session for this thread
            db = SessionLocal()

            logger.info(
                f"Starting Phase 2 analysis for evidence {evidence_id}",
                extra={"evidence_id": evidence_id, "job_id": phase2_job_id}
            )

            # Phase 2: Packet Analysis
            try:
                phase2_result = execute_phase2_analysis(db, phase2_job_id)
                packet_analysis_id = phase2_result.get("packet_analysis_id")

                logger.info(
                    f"Phase 2 completed successfully",
                    extra={
                        "job_id": phase2_job_id,
                        "packet_analysis_id": packet_analysis_id
                    }
                )
            except AnalysisExecutionError as e:
                logger.error(
                    f"Phase 2 failed: {e.code} - {e.message}",
                    extra={"job_id": phase2_job_id, "error_code": e.code}
                )
                # Phase 2 job is already marked as FAILED by execute_phase2_analysis
                return
            except Exception as e:
                logger.error(
                    f"Phase 2 unexpected error: {e}",
                    extra={"job_id": phase2_job_id},
                    exc_info=True
                )
                # Mark job as failed
                job = db.query(AnalysisJob).filter(
                    AnalysisJob.job_id == phase2_job_id
                ).first()
                if job:
                    job.status = JobStatus.FAILED
                    job.error_code = "PHASE2_UNEXPECTED_ERROR"
                    job.error_message = str(e)[:500]
                    job.completed_at = datetime.now(timezone.utc)
                    db.commit()
                return

            # Phase 3: Security Analysis
            try:
                phase3_job_id = generate_job_id()
                phase3_job = AnalysisJob(
                    job_id=phase3_job_id,
                    evidence_id=evidence_id,
                    job_type=JobType.SECURITY_ANALYSIS,
                    status=JobStatus.QUEUED,
                    stage="QUEUED_FOR_SECURITY_ANALYSIS"
                )
                db.add(phase3_job)
                db.commit()

                logger.info(
                    f"Starting Phase 3 security analysis",
                    extra={"job_id": phase3_job_id, "evidence_id": evidence_id}
                )

                phase3_result = execute_phase3_analysis(
                    db,
                    phase3_job_id,
                    packet_analysis_id
                )
                security_analysis_id = phase3_result.get("security_analysis_id")

                logger.info(
                    f"Phase 3 completed successfully",
                    extra={
                        "job_id": phase3_job_id,
                        "security_analysis_id": security_analysis_id,
                        "finding_count": phase3_result.get("finding_count", 0)
                    }
                )
            except AnalysisExecutionError as e:
                logger.error(
                    f"Phase 3 failed: {e.code} - {e.message}",
                    extra={"job_id": phase3_job_id, "error_code": e.code}
                )
                # Phase 3 job is already marked as FAILED
                return
            except Exception as e:
                logger.error(
                    f"Phase 3 unexpected error: {e}",
                    extra={"job_id": phase3_job_id},
                    exc_info=True
                )
                if phase3_job_id:
                    job = db.query(AnalysisJob).filter(
                        AnalysisJob.job_id == phase3_job_id
                    ).first()
                    if job:
                        job.status = JobStatus.FAILED
                        job.error_code = "PHASE3_UNEXPECTED_ERROR"
                        job.error_message = str(e)[:500]
                        job.completed_at = datetime.now(timezone.utc)
                        db.commit()
                return

            # Phase 4: Intelligence Analysis
            try:
                phase4_job_id = generate_job_id()
                phase4_job = AnalysisJob(
                    job_id=phase4_job_id,
                    evidence_id=evidence_id,
                    job_type=JobType.INTELLIGENCE,
                    status=JobStatus.QUEUED,
                    stage="QUEUED_FOR_INTELLIGENCE_ANALYSIS"
                )
                db.add(phase4_job)
                db.commit()

                logger.info(
                    f"Starting Phase 4 intelligence analysis",
                    extra={"job_id": phase4_job_id, "evidence_id": evidence_id}
                )

                phase4_result = execute_phase4_analysis(
                    db,
                    phase4_job_id,
                    security_analysis_id,
                    enable_ml=False  # ML disabled for demo
                )

                logger.info(
                    f"Phase 4 completed successfully",
                    extra={
                        "job_id": phase4_job_id,
                        "intelligence_report_id": phase4_result.get("intelligence_report_id"),
                        "posture_grade": phase4_result.get("posture_grade")
                    }
                )

                logger.info(
                    f"Full analysis pipeline completed successfully for evidence {evidence_id}",
                    extra={
                        "evidence_id": evidence_id,
                        "phase2_job": phase2_job_id,
                        "phase3_job": phase3_job_id,
                        "phase4_job": phase4_job_id
                    }
                )

            except AnalysisExecutionError as e:
                logger.error(
                    f"Phase 4 failed: {e.code} - {e.message}",
                    extra={"job_id": phase4_job_id, "error_code": e.code}
                )
                # Phase 4 job is already marked as FAILED
                return
            except Exception as e:
                logger.error(
                    f"Phase 4 unexpected error: {e}",
                    extra={"job_id": phase4_job_id},
                    exc_info=True
                )
                if phase4_job_id:
                    job = db.query(AnalysisJob).filter(
                        AnalysisJob.job_id == phase4_job_id
                    ).first()
                    if job:
                        job.status = JobStatus.FAILED
                        job.error_code = "PHASE4_UNEXPECTED_ERROR"
                        job.error_message = str(e)[:500]
                        job.completed_at = datetime.now(timezone.utc)
                        db.commit()
                return

        except Exception as e:
            logger.error(
                f"Fatal error in demo analysis pipeline: {e}",
                extra={"evidence_id": evidence_id},
                exc_info=True
            )

        finally:
            if db:
                db.close()


# Module-level instance
demo_executor = DemoExecutor()
