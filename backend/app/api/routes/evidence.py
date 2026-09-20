"""Evidence management API endpoints."""
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings
from app.models.evidence import PcapEvidence
from app.models.analysis_job import AnalysisJob
from app.schemas.evidence import (
    EvidenceResponse,
    EvidenceUploadResponse,
    EvidenceListResponse,
    DuplicateEvidenceResponse,
)
from app.schemas.common import ApiResponse
from app.services.ingestion import (
    evidence_service,
    EvidenceServiceError,
    DuplicateEvidenceError,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/cases/{case_id}/evidence",
    response_model=ApiResponse[EvidenceUploadResponse],
    status_code=status.HTTP_201_CREATED,
    tags=["Evidence"],
    summary="Upload evidence to a case"
)
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(..., description="PCAP or PCAPNG file"),
    db: Session = Depends(get_db)
) -> ApiResponse[EvidenceUploadResponse]:
    """
    Upload PCAP/PCAPNG evidence to a case.

    This endpoint:
    1. Validates the file format (magic bytes)
    2. Enforces size limits
    3. Calculates SHA-256 hash
    4. Detects duplicate evidence
    5. Stores the file securely
    6. Creates an analysis job

    Args:
        case_id: Case identifier to add evidence to
        file: Uploaded PCAP/PCAPNG file
        db: Database session

    Returns:
        Evidence metadata and analysis job information
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "FILE_REQUIRED", "message": "No file provided"}
        )

    # Get file size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning

    logger.info(
        f"Evidence upload started: {file.filename}, size: {file_size}",
        extra={"case_id": case_id, "file_name": file.filename, "size": file_size}
    )

    try:
        evidence, job = evidence_service.ingest_evidence(
            db=db,
            case_id=case_id,
            file_data=file.file,
            filename=file.filename,
            file_size=file_size
        )

        response = EvidenceUploadResponse(
            evidence_id=evidence.evidence_id,
            case_id=evidence.case_id,
            original_filename=evidence.original_filename,
            file_size_bytes=evidence.file_size_bytes,
            file_format=evidence.file_format,
            sha256=evidence.sha256,
            evidence_status=evidence.status,
            analysis_job_id=job.job_id,
            analysis_status=job.status.value
        )

        logger.info(
            f"Evidence upload completed: {evidence.evidence_id}",
            extra={
                "evidence_id": evidence.evidence_id,
                "case_id": case_id,
                "job_id": job.job_id
            }
        )

        return ApiResponse.ok(response)

    except DuplicateEvidenceError as e:
        logger.warning(
            f"Duplicate evidence detected: {e.sha256[:16]}...",
            extra={
                "case_id": case_id,
                "existing_evidence_id": e.existing_evidence_id,
                "sha256_prefix": e.sha256[:16]
            }
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": e.code,
                "message": e.message,
                "existing_evidence_id": e.existing_evidence_id,
                "existing_case_id": e.existing_case_id,
                "sha256": e.sha256
            }
        )

    except EvidenceServiceError as e:
        logger.warning(f"Evidence upload failed: {e.code} - {e.message}")

        # Map error codes to appropriate HTTP status codes
        status_map = {
            "CASE_NOT_FOUND": status.HTTP_404_NOT_FOUND,
            "EMPTY_FILE": status.HTTP_400_BAD_REQUEST,
            "FILE_TOO_LARGE": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "UNSUPPORTED_FILE_TYPE": status.HTTP_400_BAD_REQUEST,
            "INVALID_PCAP": status.HTTP_400_BAD_REQUEST,
            "INVALID_PCAPNG": status.HTTP_400_BAD_REQUEST,
            "PATH_TRAVERSAL": status.HTTP_400_BAD_REQUEST,
        }
        http_status = status_map.get(e.code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        raise HTTPException(
            status_code=http_status,
            detail={"code": e.code, "message": e.message}
        )

    except Exception as e:
        logger.error(f"Unexpected error during evidence upload: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "UPLOAD_FAILED", "message": "Evidence upload failed"}
        )


@router.get(
    "/cases/{case_id}/evidence",
    response_model=ApiResponse[EvidenceListResponse],
    tags=["Evidence"],
    summary="List evidence in a case"
)
async def list_case_evidence(
    case_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[EvidenceListResponse]:
    """
    List all evidence files in a case.

    Args:
        case_id: Case identifier
        db: Database session

    Returns:
        List of evidence metadata
    """
    evidence_list = evidence_service.get_case_evidence(db, case_id)

    # Check if case exists (empty list could mean no evidence or no case)
    from app.models.case import Case
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case not found: {case_id}"}
        )

    response = EvidenceListResponse(
        evidence=[EvidenceResponse.model_validate(e) for e in evidence_list],
        total=len(evidence_list)
    )

    return ApiResponse.ok(response)


@router.get(
    "/evidence/{evidence_id}",
    response_model=ApiResponse[EvidenceResponse],
    tags=["Evidence"],
    summary="Get evidence details"
)
async def get_evidence(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[EvidenceResponse]:
    """
    Get metadata for a specific evidence file.

    Note: This endpoint returns metadata only, not the file contents.

    Args:
        evidence_id: Evidence identifier
        db: Database session

    Returns:
        Evidence metadata
    """
    evidence = evidence_service.get_evidence(db, evidence_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence not found: {evidence_id}"}
        )

    return ApiResponse.ok(EvidenceResponse.model_validate(evidence))


@router.delete(
    "/evidence/{evidence_id}",
    response_model=ApiResponse[dict],
    tags=["Evidence"],
    summary="Delete evidence"
)
async def delete_evidence(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[dict]:
    """
    Delete evidence and its stored file.

    Args:
        evidence_id: Evidence identifier
        db: Database session

    Returns:
        Deletion confirmation
    """
    deleted = evidence_service.delete_evidence(db, evidence_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence not found: {evidence_id}"}
        )

    return ApiResponse.ok({"deleted": True, "evidence_id": evidence_id})
