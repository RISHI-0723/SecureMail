"""Case management service with proper deletion handling.

This module provides case management operations with explicit
handling of cascading deletions to avoid FK constraint violations.
"""
import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.case import Case, CaseStatus
from app.models.evidence import PcapEvidence
from app.models.analysis_job import AnalysisJob, JobStatus, JobType
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis
from app.models.intelligence import (
    IntelligenceReport,
    Correlation,
    Recommendation,
    MLPrediction,
    GeneratedReport,
    EvidenceIntegrity
)
from app.services.ingestion.storage import evidence_storage, StorageError

logger = logging.getLogger(__name__)


class CaseServiceError(Exception):
    """Base exception for case service errors."""
    def __init__(self, message: str, code: str):
        self.message = message
        self.code = code
        super().__init__(message)


class CaseService:
    """
    Service for case management operations.

    Provides proper deletion handling with explicit cascade
    to avoid foreign key constraint violations.
    """

    def delete_case(self, db: Session, case_id: str) -> bool:
        """
        Delete a case and all associated data.

        This method explicitly deletes all dependent records in the correct order:
        1. Phase 4 intelligence data (correlations, recommendations, ML, reports, integrity)
        2. Phase 4 intelligence reports
        3. Phase 3 security analyses
        4. Phase 2 packet analyses
        5. Analysis jobs
        6. Evidence files (both DB records and storage)
        7. Case

        Args:
            db: Database session
            case_id: Case identifier

        Returns:
            True if deleted successfully

        Raises:
            CaseServiceError: If deletion fails
        """
        case = db.query(Case).filter(Case.case_id == case_id).first()
        if not case:
            return False

        try:
            # Get all evidence for this case
            evidence_list = db.query(PcapEvidence).filter(
                PcapEvidence.case_id == case_id
            ).all()

            evidence_ids = [ev.evidence_id for ev in evidence_list]
            logger.info(
                f"Deleting case {case_id} with {len(evidence_ids)} evidence files",
                extra={"case_id": case_id, "evidence_count": len(evidence_ids)}
            )

            if evidence_ids:
                # Get all analysis jobs for this evidence
                jobs = db.query(AnalysisJob).filter(
                    AnalysisJob.evidence_id.in_(evidence_ids)
                ).all()
                job_ids = [job.job_id for job in jobs]

                logger.info(
                    f"Found {len(job_ids)} analysis jobs to delete",
                    extra={"case_id": case_id, "job_count": len(job_ids)}
                )

                if job_ids:
                    # Step 1: Delete Phase 4 dependent data
                    intelligence_reports = db.query(IntelligenceReport).filter(
                        IntelligenceReport.evidence_id.in_(evidence_ids)
                    ).all()

                    intelligence_ids = [ir.report_id for ir in intelligence_reports]
                    if intelligence_ids:
                        # Delete correlations
                        db.query(Correlation).filter(
                            Correlation.intelligence_report_id.in_(intelligence_ids)
                        ).delete(synchronize_session=False)

                        # Delete recommendations
                        db.query(Recommendation).filter(
                            Recommendation.intelligence_report_id.in_(intelligence_ids)
                        ).delete(synchronize_session=False)

                        # Delete ML predictions
                        db.query(MLPrediction).filter(
                            MLPrediction.intelligence_report_id.in_(intelligence_ids)
                        ).delete(synchronize_session=False)

                        # Delete generated reports
                        db.query(GeneratedReport).filter(
                            GeneratedReport.intelligence_report_id.in_(intelligence_ids)
                        ).delete(synchronize_session=False)

                        logger.info(
                            f"Deleted Phase 4 dependent data for {len(intelligence_ids)} reports",
                            extra={"case_id": case_id}
                        )

                    # Delete evidence integrity records
                    db.query(EvidenceIntegrity).filter(
                        EvidenceIntegrity.evidence_id.in_(evidence_ids)
                    ).delete(synchronize_session=False)

                    # Step 2: Delete intelligence reports
                    db.query(IntelligenceReport).filter(
                        IntelligenceReport.evidence_id.in_(evidence_ids)
                    ).delete(synchronize_session=False)

                    # Step 3: Delete security analyses
                    db.query(SecurityAnalysis).filter(
                        SecurityAnalysis.evidence_id.in_(evidence_ids)
                    ).delete(synchronize_session=False)

                    # Step 4: Delete packet analyses
                    db.query(PacketAnalysis).filter(
                        PacketAnalysis.evidence_id.in_(evidence_ids)
                    ).delete(synchronize_session=False)

                    # Step 5: Delete analysis jobs
                    db.query(AnalysisJob).filter(
                        AnalysisJob.evidence_id.in_(evidence_ids)
                    ).delete(synchronize_session=False)

                # Step 6: Delete evidence files from storage and DB
                for evidence in evidence_list:
                    try:
                        evidence_storage.delete(evidence.stored_filename)
                        logger.debug(
                            f"Deleted evidence file from storage: {evidence.stored_filename}",
                            extra={"evidence_id": evidence.evidence_id}
                        )
                    except StorageError as e:
                        logger.warning(
                            f"Failed to delete evidence file from storage: {e.message}",
                            extra={"evidence_id": evidence.evidence_id, "filename": evidence.stored_filename}
                        )

                    db.delete(evidence)

            # Step 7: Delete the case
            db.delete(case)
            db.commit()

            logger.info(
                f"Case deleted successfully: {case_id}",
                extra={
                    "case_id": case_id,
                    "evidence_count": len(evidence_ids)
                }
            )

            return True

        except IntegrityError as e:
            db.rollback()
            logger.error(
                f"Integrity error deleting case {case_id}: {e}",
                extra={"case_id": case_id},
                exc_info=True
            )
            raise CaseServiceError(
                f"Foreign key constraint violation during deletion: {str(e)}",
                code="INTEGRITY_ERROR"
            )
        except Exception as e:
            db.rollback()
            logger.error(
                f"Unexpected error deleting case {case_id}: {e}",
                extra={"case_id": case_id},
                exc_info=True
            )
            raise CaseServiceError(
                f"Failed to delete case: {str(e)}",
                code="DELETE_FAILED"
            )

    def update_case_status(self, db: Session, case_id: str) -> CaseStatus:
        """
        Update case status based on all evidence analysis jobs.

        Aggregates status from all evidence files in the case:
        - If any job is QUEUED or RUNNING → Case = PROCESSING
        - If all jobs are COMPLETED → Case = COMPLETED
        - If any job is FAILED → Case = PARTIAL or FAILED (depending on others)

        Args:
            db: Database session
            case_id: Case identifier

        Returns:
            Updated case status

        Raises:
            CaseServiceError: If case not found
        """
        case = db.query(Case).filter(Case.case_id == case_id).first()
        if not case:
            raise CaseServiceError(
                f"Case not found: {case_id}",
                code="CASE_NOT_FOUND"
            )

        # Get all evidence for this case
        evidence_list = db.query(PcapEvidence).filter(
            PcapEvidence.case_id == case_id
        ).all()

        if not evidence_list:
            # No evidence → case can be OPEN
            if case.status != CaseStatus.OPEN:
                case.status = CaseStatus.OPEN
                db.commit()
            return case.status

        # Get all analysis jobs for all evidence
        evidence_ids = [ev.evidence_id for ev in evidence_list]

        # For each evidence, get the latest FULL_ANALYSIS job (Phase 2)
        # Phase 3 and Phase 4 are triggered automatically in demo mode
        latest_jobs = []
        for evidence_id in evidence_ids:
            job = db.query(AnalysisJob).filter(
                AnalysisJob.evidence_id == evidence_id,
                AnalysisJob.job_type == JobType.FULL_ANALYSIS
            ).order_by(AnalysisJob.created_at.desc()).first()

            if job:
                latest_jobs.append(job)

        if not latest_jobs:
            # No analysis jobs → case is OPEN
            if case.status != CaseStatus.OPEN:
                case.status = CaseStatus.OPEN
                db.commit()
            return case.status

        # Aggregate status
        has_queued = False
        has_running = False
        has_completed = False
        has_failed = False

        for job in latest_jobs:
            if job.status == JobStatus.QUEUED:
                has_queued = True
            elif job.status == JobStatus.RUNNING:
                has_running = True
            elif job.status == JobStatus.COMPLETED:
                has_completed = True
            elif job.status in (JobStatus.FAILED, JobStatus.TIMEOUT):
                has_failed = True

        # Determine case status
        new_status = case.status

        if has_queued or has_running:
            # Any job still processing → Case = PROCESSING
            new_status = CaseStatus.PROCESSING
        elif has_failed and not has_completed:
            # All jobs failed → Case = FAILED
            new_status = CaseStatus.FAILED
        elif has_failed and has_completed:
            # Some failed, some completed → Case = PARTIAL
            new_status = CaseStatus.PARTIAL
        elif has_completed and not has_failed and not has_queued and not has_running:
            # All jobs completed successfully → Case = COMPLETED
            new_status = CaseStatus.COMPLETED
        else:
            # Default to OPEN
            new_status = CaseStatus.OPEN

        # Update if changed
        if case.status != new_status:
            logger.info(
                f"Updating case status: {case.status.value} → {new_status.value}",
                extra={
                    "case_id": case_id,
                    "old_status": case.status.value,
                    "new_status": new_status.value,
                    "evidence_count": len(evidence_ids),
                    "jobs_queued": has_queued,
                    "jobs_running": has_running,
                    "jobs_completed": has_completed,
                    "jobs_failed": has_failed
                }
            )
            case.status = new_status
            db.commit()

        return case.status


# Global service instance
case_service = CaseService()
