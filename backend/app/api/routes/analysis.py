"""Analysis job API endpoints."""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.analysis_job import AnalysisJob
from app.models.evidence import PcapEvidence
from app.schemas.analysis import AnalysisJobResponse, AnalysisJobListResponse
from app.schemas.common import ApiResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/analysis/{job_id}",
    response_model=ApiResponse[AnalysisJobResponse],
    tags=["Analysis"],
    summary="Get analysis job status"
)
async def get_analysis_job(
    job_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[AnalysisJobResponse]:
    """
    Get the status and details of an analysis job.

    Note: In Phase 1, analysis jobs are created but not processed.
    Full forensic analysis begins in Phase 2.

    Args:
        job_id: Analysis job identifier
        db: Database session

    Returns:
        Analysis job details
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_JOB_NOT_FOUND",
                "message": f"Analysis job not found: {job_id}"
            }
        )

    return ApiResponse.ok(AnalysisJobResponse.model_validate(job))


@router.get(
    "/evidence/{evidence_id}/analysis",
    response_model=ApiResponse[AnalysisJobListResponse],
    tags=["Analysis"],
    summary="Get analysis jobs for evidence"
)
async def get_evidence_analysis_jobs(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[AnalysisJobListResponse]:
    """
    Get all analysis jobs for a specific evidence file.

    Args:
        evidence_id: Evidence identifier
        db: Database session

    Returns:
        List of analysis jobs
    """
    # Check evidence exists
    evidence = db.query(PcapEvidence).filter(
        PcapEvidence.evidence_id == evidence_id
    ).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "EVIDENCE_NOT_FOUND",
                "message": f"Evidence not found: {evidence_id}"
            }
        )

    jobs = db.query(AnalysisJob).filter(
        AnalysisJob.evidence_id == evidence_id
    ).order_by(AnalysisJob.created_at.desc()).all()

    response = AnalysisJobListResponse(
        jobs=[AnalysisJobResponse.model_validate(job) for job in jobs],
        total=len(jobs)
    )

    return ApiResponse.ok(response)


@router.get(
    "/analysis",
    response_model=ApiResponse[AnalysisJobListResponse],
    tags=["Analysis"],
    summary="List all analysis jobs"
)
async def list_analysis_jobs(
    db: Session = Depends(get_db),
    status_filter: str | None = None,
    skip: int = 0,
    limit: int = 100
) -> ApiResponse[AnalysisJobListResponse]:
    """
    List all analysis jobs with optional filtering.

    Args:
        db: Database session
        status_filter: Optional status to filter by
        skip: Number of records to skip
        limit: Maximum records to return

    Returns:
        List of analysis jobs
    """
    query = db.query(AnalysisJob)

    if status_filter:
        query = query.filter(AnalysisJob.status == status_filter)

    total = query.count()
    jobs = query.order_by(AnalysisJob.created_at.desc()).offset(skip).limit(limit).all()

    response = AnalysisJobListResponse(
        jobs=[AnalysisJobResponse.model_validate(job) for job in jobs],
        total=total
    )

    return ApiResponse.ok(response)
