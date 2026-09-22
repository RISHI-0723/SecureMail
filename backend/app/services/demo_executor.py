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
                "DEMO_ANALYSIS_TRIGGERED",
                extra={
                    "event": "DEMO_ANALYSIS_TRIGGERED",
                    "evidence_id": evidence_id,
                    "job_id": phase2_job_id
                }
            )

            # Phase 2: Packet Analysis
            try:
                logger.info(
                    "DEMO_PHASE2_STARTED",
                    extra={
                        "event": "DEMO_PHASE2_STARTED",
                        "job_id": phase2_job_id,
                        "evidence_id": evidence_id
                    }
                )

                phase2_start = datetime.now(timezone.utc)
                phase2_result = execute_phase2_analysis(db, phase2_job_id)
                phase2_duration = (datetime.now(timezone.utc) - phase2_start).total_seconds()
                packet_analysis_id = phase2_result.get("packet_analysis_id")

                logger.info(
                    "DEMO_PHASE2_COMPLETED",
                    extra={
                        "event": "DEMO_PHASE2_COMPLETED",
                        "job_id": phase2_job_id,
                        "evidence_id": evidence_id,
                        "packet_analysis_id": packet_analysis_id,
                        "duration_seconds": phase2_duration
                    }
                )
            except AnalysisExecutionError as e:
                logger.error(
                    "DEMO_PHASE2_FAILED",
                    extra={
                        "event": "DEMO_PHASE2_FAILED",
                        "job_id": phase2_job_id,
                        "evidence_id": evidence_id,
                        "error_code": e.code,
                        "error_message": e.message,
                        "phase": "Phase 2"
                    }
                )
                # Phase 2 job is already marked as FAILED by execute_phase2_analysis
                _update_case_status_on_failure(db, evidence_id)
                return
            except Exception as e:
                logger.error(
                    "DEMO_PHASE2_FAILED",
                    extra={
                        "event": "DEMO_PHASE2_FAILED",
                        "job_id": phase2_job_id,
                        "evidence_id": evidence_id,
                        "error_code": "PHASE2_UNEXPECTED_ERROR",
                        "error_message": str(e)[:500],
                        "error_type": type(e).__name__,
                        "phase": "Phase 2"
                    },
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
                _update_case_status_on_failure(db, evidence_id)
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
                    "DEMO_PHASE3_STARTED",
                    extra={
                        "event": "DEMO_PHASE3_STARTED",
                        "job_id": phase3_job_id,
                        "evidence_id": evidence_id
                    }
                )

                phase3_start = datetime.now(timezone.utc)
                phase3_result = execute_phase3_analysis(
                    db,
                    phase3_job_id,
                    packet_analysis_id
                )
                phase3_duration = (datetime.now(timezone.utc) - phase3_start).total_seconds()
                security_analysis_id = phase3_result.get("security_analysis_id")

                logger.info(
                    "DEMO_PHASE3_COMPLETED",
                    extra={
                        "event": "DEMO_PHASE3_COMPLETED",
                        "job_id": phase3_job_id,
                        "evidence_id": evidence_id,
                        "security_analysis_id": security_analysis_id,
                        "finding_count": phase3_result.get("finding_count", 0),
                        "duration_seconds": phase3_duration
                    }
                )
            except AnalysisExecutionError as e:
                logger.error(
                    "DEMO_PHASE3_FAILED",
                    extra={
                        "event": "DEMO_PHASE3_FAILED",
                        "job_id": phase3_job_id,
                        "evidence_id": evidence_id,
                        "error_code": e.code,
                        "error_message": e.message,
                        "phase": "Phase 3"
                    }
                )
                # Phase 3 job is already marked as FAILED
                _update_case_status_on_failure(db, evidence_id)
                return
            except Exception as e:
                logger.error(
                    "DEMO_PHASE3_FAILED",
                    extra={
                        "event": "DEMO_PHASE3_FAILED",
                        "job_id": phase3_job_id,
                        "evidence_id": evidence_id,
                        "error_code": "PHASE3_UNEXPECTED_ERROR",
                        "error_message": str(e)[:500],
                        "error_type": type(e).__name__,
                        "phase": "Phase 3"
                    },
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
                _update_case_status_on_failure(db, evidence_id)
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
                    "DEMO_PHASE4_STARTED",
                    extra={
                        "event": "DEMO_PHASE4_STARTED",
                        "job_id": phase4_job_id,
                        "evidence_id": evidence_id
                    }
                )

                phase4_start = datetime.now(timezone.utc)
                phase4_result = execute_phase4_analysis(
                    db,
                    phase4_job_id,
                    security_analysis_id,
                    enable_ml=False  # ML disabled for demo
                )
                phase4_duration = (datetime.now(timezone.utc) - phase4_start).total_seconds()

                logger.info(
                    "DEMO_PHASE4_COMPLETED",
                    extra={
                        "event": "DEMO_PHASE4_COMPLETED",
                        "job_id": phase4_job_id,
                        "evidence_id": evidence_id,
                        "intelligence_report_id": phase4_result.get("intelligence_report_id"),
                        "posture_grade": phase4_result.get("posture_grade"),
                        "duration_seconds": phase4_duration
                    }
                )

                logger.info(
                    "DEMO_ANALYSIS_COMPLETED",
                    extra={
                        "event": "DEMO_ANALYSIS_COMPLETED",
                        "evidence_id": evidence_id,
                        "phase2_job": phase2_job_id,
                        "phase3_job": phase3_job_id,
                        "phase4_job": phase4_job_id
                    }
                )

                # Update parent case status after all phases complete
                try:
                    from app.services.case_service import case_service
                    from app.models.evidence import PcapEvidence

                    # Get case_id from evidence
                    evidence = db.query(PcapEvidence).filter(
                        PcapEvidence.evidence_id == evidence_id
                    ).first()

                    if evidence and evidence.case_id:
                        case_status = case_service.update_case_status(db, evidence.case_id)
                        logger.info(
                            "DEMO_CASE_STATUS_UPDATED",
                            extra={
                                "event": "DEMO_CASE_STATUS_UPDATED",
                                "case_id": evidence.case_id,
                                "evidence_id": evidence_id,
                                "case_status": case_status.value
                            }
                        )
                except Exception as e:
                    logger.error(
                        "DEMO_CASE_STATUS_UPDATE_FAILED",
                        extra={
                            "event": "DEMO_CASE_STATUS_UPDATE_FAILED",
                            "evidence_id": evidence_id,
                            "error_message": str(e)
                        },
                        exc_info=True
                    )

            except AnalysisExecutionError as e:
                logger.error(
                    "DEMO_PHASE4_FAILED",
                    extra={
                        "event": "DEMO_PHASE4_FAILED",
                        "job_id": phase4_job_id,
                        "evidence_id": evidence_id,
                        "error_code": e.code,
                        "error_message": e.message,
                        "phase": "Phase 4"
                    }
                )
                # Phase 4 job is already marked as FAILED
                _update_case_status_on_failure(db, evidence_id)
                return
            except Exception as e:
                logger.error(
                    "DEMO_PHASE4_FAILED",
                    extra={
                        "event": "DEMO_PHASE4_FAILED",
                        "job_id": phase4_job_id,
                        "evidence_id": evidence_id,
                        "error_code": "PHASE4_UNEXPECTED_ERROR",
                        "error_message": str(e)[:500],
                        "error_type": type(e).__name__,
                        "phase": "Phase 4"
                    },
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
                _update_case_status_on_failure(db, evidence_id)
                return

        except Exception as e:
            logger.error(
                "DEMO_ANALYSIS_FAILED",
                extra={
                    "event": "DEMO_ANALYSIS_FAILED",
                    "evidence_id": evidence_id,
                    "error_code": "PIPELINE_FATAL_ERROR",
                    "error_message": str(e)[:500],
                    "error_type": type(e).__name__
                },
                exc_info=True
            )

        finally:
            if db:
                db.close()


def _update_case_status_on_failure(db: Session, evidence_id: str) -> None:
    """Update case status when analysis fails."""
    try:
        from app.services.case_service import case_service
        from app.models.evidence import PcapEvidence

        # Get case_id from evidence
        evidence = db.query(PcapEvidence).filter(
            PcapEvidence.evidence_id == evidence_id
        ).first()

        if evidence and evidence.case_id:
            case_service.update_case_status(db, evidence.case_id)
            logger.info(
                "Case status updated after analysis failure",
                extra={"case_id": evidence.case_id, "evidence_id": evidence_id}
            )
    except Exception as e:
        logger.warning(
            f"Failed to update case status after analysis failure: {e}",
            extra={"evidence_id": evidence_id}
        )


# Module-level instance
demo_executor = DemoExecutor()
