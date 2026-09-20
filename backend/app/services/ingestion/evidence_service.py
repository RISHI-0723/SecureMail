"""Evidence ingestion service coordinating validation, storage, and database operations."""
import logging
from typing import BinaryIO

from sqlalchemy.orm import Session

from app.models.case import Case, CaseStatus
from app.models.evidence import PcapEvidence, EvidenceStatus
from app.models.analysis_job import AnalysisJob, JobStatus, JobType
from app.services.ingestion.storage import EvidenceStorage, StorageError, evidence_storage
from app.services.ingestion.validation import FileValidator, ValidationResult, file_validator

logger = logging.getLogger(__name__)


class EvidenceServiceError(Exception):
    """Base exception for evidence service errors."""
    def __init__(self, message: str, code: str):
        self.message = message
        self.code = code
        super().__init__(message)


class DuplicateEvidenceError(EvidenceServiceError):
    """Exception raised when duplicate evidence is detected."""
    def __init__(
        self,
        message: str,
        existing_evidence_id: str,
        existing_case_id: str,
        sha256: str
    ):
        super().__init__(message, "DUPLICATE_EVIDENCE")
        self.existing_evidence_id = existing_evidence_id
        self.existing_case_id = existing_case_id
        self.sha256 = sha256


class EvidenceService:
    """
    Service for handling evidence ingestion workflow.

    Coordinates:
    1. File validation (magic bytes, size, SHA-256)
    2. Duplicate detection
    3. Secure storage
    4. Database persistence
    5. Analysis job creation
    """

    def __init__(
        self,
        storage: EvidenceStorage | None = None,
        validator: FileValidator | None = None
    ):
        """
        Initialize evidence service.

        Args:
            storage: Evidence storage instance
            validator: File validator instance
        """
        self.storage = storage or evidence_storage
        self.validator = validator or file_validator

    def check_duplicate(
        self,
        db: Session,
        sha256: str,
        case_id: str
    ) -> PcapEvidence | None:
        """
        Check if evidence with same hash already exists.

        Args:
            db: Database session
            sha256: SHA-256 hash to check
            case_id: Case ID to check within

        Returns:
            Existing evidence if found, None otherwise
        """
        # Check for duplicate in same case
        existing = db.query(PcapEvidence).filter(
            PcapEvidence.sha256 == sha256,
            PcapEvidence.case_id == case_id
        ).first()

        return existing

    def check_duplicate_any_case(
        self,
        db: Session,
        sha256: str
    ) -> PcapEvidence | None:
        """
        Check if evidence with same hash exists in any case.

        Args:
            db: Database session
            sha256: SHA-256 hash to check

        Returns:
            Existing evidence if found, None otherwise
        """
        return db.query(PcapEvidence).filter(
            PcapEvidence.sha256 == sha256
        ).first()

    def ingest_evidence(
        self,
        db: Session,
        case_id: str,
        file_data: BinaryIO,
        filename: str,
        file_size: int
    ) -> tuple[PcapEvidence, AnalysisJob]:
        """
        Ingest evidence file into the system.

        This method:
        1. Validates the file (magic bytes, size)
        2. Calculates SHA-256
        3. Checks for duplicates
        4. Stores the file
        5. Creates database records
        6. Creates analysis job

        Args:
            db: Database session
            case_id: ID of the case to add evidence to
            file_data: File-like object containing evidence
            filename: Original filename
            file_size: File size in bytes

        Returns:
            Tuple of (PcapEvidence, AnalysisJob)

        Raises:
            EvidenceServiceError: If ingestion fails
            DuplicateEvidenceError: If duplicate evidence exists
        """
        # Step 1: Verify case exists
        case = db.query(Case).filter(Case.case_id == case_id).first()
        if not case:
            raise EvidenceServiceError(
                f"Case not found: {case_id}",
                code="CASE_NOT_FOUND"
            )

        # Step 2: Validate file
        validation_result = self.validator.validate(file_data, filename, file_size)

        if not validation_result.valid:
            raise EvidenceServiceError(
                validation_result.error_message or "Validation failed",
                code=validation_result.error_code or "VALIDATION_FAILED"
            )

        # Step 3: Check for duplicates
        existing = self.check_duplicate(db, validation_result.sha256, case_id)
        if existing:
            raise DuplicateEvidenceError(
                f"Evidence with same content already exists in this case",
                existing_evidence_id=existing.evidence_id,
                existing_case_id=existing.case_id,
                sha256=validation_result.sha256
            )

        # Step 4: Store the file
        try:
            # Reset file position for storage
            file_data.seek(0)
            storage_meta = self.storage.save(
                file_data,
                filename,
                file_size
            )
        except StorageError as e:
            logger.error(f"Storage failed: {e.message}")
            raise EvidenceServiceError(e.message, code=e.code)

        # Step 5: Create evidence record
        try:
            safe_filename = self.validator.sanitize_filename(filename)

            evidence = PcapEvidence(
                case_id=case_id,
                original_filename=safe_filename,
                stored_filename=storage_meta.stored_filename,
                file_format=validation_result.file_format,
                file_size_bytes=validation_result.file_size_bytes,
                sha256=validation_result.sha256,
                status=EvidenceStatus.VALIDATED,
                storage_location=storage_meta.storage_location
            )
            db.add(evidence)
            db.flush()  # Get evidence_id

            # Step 6: Create analysis job
            job = AnalysisJob(
                evidence_id=evidence.evidence_id,
                job_type=JobType.FULL_ANALYSIS,
                status=JobStatus.QUEUED
            )
            db.add(job)

            # Update case status if first evidence
            if case.status == CaseStatus.OPEN:
                case.status = CaseStatus.PROCESSING

            db.commit()
            db.refresh(evidence)
            db.refresh(job)

            logger.info(
                f"Evidence ingested: {evidence.evidence_id}, "
                f"job: {job.job_id}, sha256: {validation_result.sha256[:16]}...",
                extra={
                    "evidence_id": evidence.evidence_id,
                    "case_id": case_id,
                    "job_id": job.job_id,
                    "sha256_prefix": validation_result.sha256[:16]
                }
            )

            return evidence, job

        except Exception as e:
            db.rollback()
            # Clean up stored file
            try:
                self.storage.delete(storage_meta.stored_filename)
            except Exception:
                logger.error(
                    f"Failed to clean up stored file: {storage_meta.stored_filename}"
                )
            logger.error(f"Database operation failed: {e}")
            raise EvidenceServiceError(
                f"Failed to save evidence record: {e}",
                code="DATABASE_ERROR"
            )

    def get_evidence(
        self,
        db: Session,
        evidence_id: str
    ) -> PcapEvidence | None:
        """
        Get evidence by ID.

        Args:
            db: Database session
            evidence_id: Evidence ID

        Returns:
            PcapEvidence or None if not found
        """
        return db.query(PcapEvidence).filter(
            PcapEvidence.evidence_id == evidence_id
        ).first()

    def get_case_evidence(
        self,
        db: Session,
        case_id: str
    ) -> list[PcapEvidence]:
        """
        Get all evidence for a case.

        Args:
            db: Database session
            case_id: Case ID

        Returns:
            List of PcapEvidence
        """
        return db.query(PcapEvidence).filter(
            PcapEvidence.case_id == case_id
        ).order_by(PcapEvidence.upload_timestamp.desc()).all()

    def delete_evidence(
        self,
        db: Session,
        evidence_id: str
    ) -> bool:
        """
        Delete evidence and its stored file.

        Args:
            db: Database session
            evidence_id: Evidence ID

        Returns:
            True if deleted, False if not found
        """
        evidence = self.get_evidence(db, evidence_id)
        if not evidence:
            return False

        # Delete stored file
        try:
            self.storage.delete(evidence.stored_filename)
        except StorageError:
            logger.warning(f"Could not delete stored file: {evidence.stored_filename}")

        # Delete database record (cascades to analysis jobs)
        db.delete(evidence)
        db.commit()

        logger.info(f"Evidence deleted: {evidence_id}")
        return True


# Global service instance
evidence_service = EvidenceService()
