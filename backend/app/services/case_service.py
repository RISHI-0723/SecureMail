"""Case management service with proper deletion handling.

This module provides case management operations with explicit
handling of cascading deletions to avoid FK constraint violations.
"""
import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.case import Case
from app.models.evidence import PcapEvidence
from app.models.analysis_job import AnalysisJob
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


# Global service instance
case_service = CaseService()
