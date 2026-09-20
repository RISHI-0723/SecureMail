"""Case management API endpoints."""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.case import Case, CaseStatus
from app.models.evidence import PcapEvidence
from app.schemas.case import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseWithEvidenceCount,
    CaseListResponse,
)
from app.schemas.common import ApiResponse

logger = logging.getLogger(__name__)
router = APIRouter()


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

    Args:
        case_id: Case identifier
        db: Database session

    Returns:
        Deletion confirmation
    """
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Case not found: {case_id}"}
        )

    try:
        # Get evidence for cleanup logging
        evidence_count = db.query(func.count(PcapEvidence.evidence_id)).filter(
            PcapEvidence.case_id == case_id
        ).scalar() or 0

        db.delete(case)
        db.commit()

        logger.info(
            f"Case deleted: {case_id}, evidence removed: {evidence_count}",
            extra={"case_id": case_id, "evidence_removed": evidence_count}
        )

        return ApiResponse.ok({
            "deleted": True,
            "case_id": case_id,
            "evidence_removed": evidence_count
        })

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete case: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "DATABASE_ERROR", "message": "Failed to delete case"}
        )
