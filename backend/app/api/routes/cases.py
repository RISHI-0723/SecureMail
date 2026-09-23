"""Case management API endpoints."""
import logging
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.core.database import get_db
from app.models.case import Case, CaseStatus
from app.models.evidence import PcapEvidence
from app.models.intelligence import IntelligenceReport, IntelligenceStatus, GeneratedReport, ReportFormat as DbReportFormat
from app.schemas.case import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseWithEvidenceCount,
    CaseListResponse,
)
from app.schemas.common import ApiResponse
from app.services.case_service import case_service, CaseServiceError

logger = logging.getLogger(__name__)
router = APIRouter()


# Request/Response schemas for report generation
class ReportGenerationRequest(BaseModel):
    """Request to generate a report for a case."""
    format: str  # "json", "html", or "pdf"


class ReportGenerationResponse(BaseModel):
    """Response containing report generation result."""
    report_id: str
    download_url: str
    format: str


@router.post(
    "",
    response_model=ApiResponse[CaseResponse],
    status_code=status.HTTP_201_CREATED,
    tags=["Cases"],
    summary="Create a new forensic case"
)
async def create_case(
    case_data: CaseCreate,
    db: Session = Depends(get_db)
) -> ApiResponse[CaseResponse]:
    """
    Create a new forensic investigation case.

    Args:
        case_data: Case creation data
        db: Database session

    Returns:
        Created case details
    """
    try:
        case = Case(
            case_name=case_data.case_name,
            description=case_data.description,
            status=CaseStatus.OPEN
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        logger.info(
            f"Case created: {case.case_id}",
            extra={"case_id": case.case_id, "case_name": case.case_name}
        )

        return ApiResponse.ok(CaseResponse.model_validate(case))

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create case: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "DATABASE_ERROR", "message": "Failed to create case"}
        )


@router.get(
    "",
    response_model=ApiResponse[CaseListResponse],
    tags=["Cases"],
    summary="List all cases"
)
async def list_cases(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
) -> ApiResponse[CaseListResponse]:
    """
    List all forensic cases with evidence counts.

    Args:
        db: Database session
        skip: Number of records to skip
        limit: Maximum records to return

    Returns:
        List of cases with evidence counts
    """
    try:
        # Query cases with evidence count
        query = (
            db.query(Case, func.count(PcapEvidence.evidence_id).label("evidence_count"))
            .outerjoin(PcapEvidence, Case.case_id == PcapEvidence.case_id)
            .group_by(Case.case_id)
            .order_by(Case.created_at.desc())
            .offset(skip)
            .limit(limit)
        )

        results = query.all()
        total = db.query(func.count(Case.case_id)).scalar() or 0

        cases = [
            CaseWithEvidenceCount(
                case_id=case.case_id,
                case_name=case.case_name,
                description=case.description,
                status=case.status,
                created_at=case.created_at,
                updated_at=case.updated_at,
                evidence_count=count
            )
            for case, count in results
        ]

        return ApiResponse.ok(CaseListResponse(cases=cases, total=total))

    except Exception as e:
        logger.error(f"Failed to list cases: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "DATABASE_ERROR", "message": "Failed to list cases"}
        )


@router.get(
    "/{case_id}",
    response_model=ApiResponse[CaseWithEvidenceCount],
    tags=["Cases"],
    summary="Get case details"
)
async def get_case(
    case_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[CaseWithEvidenceCount]:
    """
    Get details of a specific case.

    Args:
        case_id: Case identifier
        db: Database session

    Returns:
        Case details with evidence count
    """
    result = (
        db.query(Case, func.count(PcapEvidence.evidence_id).label("evidence_count"))
        .outerjoin(PcapEvidence, Case.case_id == PcapEvidence.case_id)
        .filter(Case.case_id == case_id)
        .group_by(Case.case_id)
        .first()
    )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case not found: {case_id}"}
        )

    case, count = result
    response = CaseWithEvidenceCount(
        case_id=case.case_id,
        case_name=case.case_name,
        description=case.description,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        evidence_count=count
    )

    return ApiResponse.ok(response)


@router.patch(
    "/{case_id}",
    response_model=ApiResponse[CaseResponse],
    tags=["Cases"],
    summary="Update case details"
)
async def update_case(
    case_id: str,
    case_data: CaseUpdate,
    db: Session = Depends(get_db)
) -> ApiResponse[CaseResponse]:
    """
    Update case details.

    Args:
        case_id: Case identifier
        case_data: Fields to update
        db: Database session

    Returns:
        Updated case details
    """
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case not found: {case_id}"}
        )

    try:
        update_data = case_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(case, field, value)

        db.commit()
        db.refresh(case)

        logger.info(f"Case updated: {case_id}", extra={"case_id": case_id})
        return ApiResponse.ok(CaseResponse.model_validate(case))

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update case: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "DATABASE_ERROR", "message": "Failed to update case"}
        )


@router.post(
    "/{case_id}/report",
    response_model=ApiResponse[ReportGenerationResponse],
    tags=["Cases"],
    summary="Generate or retrieve case report"
)
async def generate_case_report(
    case_id: str,
    request: ReportGenerationRequest,
    db: Session = Depends(get_db)
) -> ApiResponse[ReportGenerationResponse]:
    """
    Generate or retrieve a forensic report for a case.

    Currently returns the first available evidence report in the requested format.
    TODO: Implement case-level consolidated reports combining all evidence.

    Args:
        case_id: Case identifier
        request: Report generation request with format
        db: Database session

    Returns:
        Report ID and download URL
    """
    # Verify case exists
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case not found: {case_id}"}
        )

    # Validate format
    format_lower = request.format.lower()
    if format_lower not in ["json", "html", "pdf"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_FORMAT", "message": f"Invalid format: {request.format}. Must be json, html, or pdf."}
        )

    # Map format string to enum
    format_map = {
        "json": DbReportFormat.JSON,
        "html": DbReportFormat.HTML,
        "pdf": DbReportFormat.PDF
    }
    db_format = format_map[format_lower]

    try:
        # Get all evidence for this case
        evidence_list = db.query(PcapEvidence).filter(
            PcapEvidence.case_id == case_id
        ).all()

        if not evidence_list:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "NO_EVIDENCE",
                    "message": f"No evidence found for case: {case_id}"
                }
            )

        # Find first completed intelligence report for any evidence in this case
        for evidence in evidence_list:
            # Get latest completed intelligence report for this evidence
            intel_report = db.query(IntelligenceReport).filter(
                IntelligenceReport.evidence_id == evidence.evidence_id,
                IntelligenceReport.status == IntelligenceStatus.COMPLETED
            ).order_by(IntelligenceReport.completed_at.desc()).first()

            if not intel_report:
                continue

            # Find existing generated report in requested format
            generated_report = db.query(GeneratedReport).filter(
                GeneratedReport.intelligence_report_id == intel_report.report_id,
                GeneratedReport.format == db_format
            ).first()

            if generated_report and generated_report.filename:
                # Return existing report
                download_url = f"/api/v1/reports/{generated_report.report_id}/download"

                logger.info(
                    f"Returning existing {format_lower} report for case {case_id}",
                    extra={
                        "case_id": case_id,
                        "report_id": generated_report.report_id,
                        "format": format_lower
                    }
                )

                return ApiResponse.ok(ReportGenerationResponse(
                    report_id=generated_report.report_id,
                    download_url=download_url,
                    format=format_lower
                ))

        # No completed reports found
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "NO_REPORTS_AVAILABLE",
                "message": f"No completed {format_lower} reports available for case {case_id}. Analysis may still be running."
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate case report: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "REPORT_GENERATION_FAILED", "message": "Failed to generate report"}
        )


@router.delete(
    "/{case_id}",
    response_model=ApiResponse[dict],
    tags=["Cases"],
    summary="Delete a case"
)
async def delete_case(
    case_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[dict]:
    """
    Delete a case and all associated evidence.

    This endpoint properly deletes all dependent records including:
    - Evidence files
    - Analysis jobs
    - Packet analyses
    - Security analyses
    - Intelligence reports and all Phase 4 data

    Args:
        case_id: Case identifier
        db: Database session

    Returns:
        Deletion confirmation
    """
    # Get evidence count before deletion
    evidence_count = db.query(func.count(PcapEvidence.evidence_id)).filter(
        PcapEvidence.case_id == case_id
    ).scalar() or 0

    try:
        deleted = case_service.delete_case(db, case_id)

        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "CASE_NOT_FOUND", "message": f"Case not found: {case_id}"}
            )

        return ApiResponse.ok({
            "deleted": True,
            "case_id": case_id,
            "evidence_removed": evidence_count
        })

    except HTTPException:
        # Re-raise HTTP exceptions (like 404 not found)
        raise
    except CaseServiceError as e:
        logger.error(f"Case deletion failed: {e.code} - {e.message}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": e.code, "message": e.message}
        )
    except Exception as e:
        logger.error(f"Unexpected error deleting case: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "DELETE_FAILED", "message": "Failed to delete case"}
        )
