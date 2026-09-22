"""Analysis job API endpoints.

Phase 2 adds packet analysis summary and protocol detection endpoints.
Phase 5 adds demo mode execution support for free deployments.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis_job import AnalysisJob, JobStatus
from app.models.evidence import PcapEvidence
from app.models.packet_analysis import PacketAnalysis
from app.schemas.analysis import (
    AnalysisJobResponse,
    AnalysisJobListResponse,
    PacketAnalysisSummaryResponse,
    ProtocolSummaryResponse,
    ProtocolDetectionResponse,
    SessionCandidateResponse,
    TriggerAnalysisResponse,
)
from app.schemas.common import ApiResponse
from app.workers.tasks import analyze_evidence
from app.core.config import settings
from app.services.analysis_executor import (
    execute_phase2_analysis,
    execute_phase3_analysis,
    execute_phase4_analysis,
    AnalysisExecutionError
)
from app.models.analysis_job import generate_job_id, JobType

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
    "/analysis/{job_id}/summary",
    response_model=ApiResponse[PacketAnalysisSummaryResponse],
    tags=["Analysis"],
    summary="Get packet analysis summary"
)
async def get_analysis_summary(
    job_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[PacketAnalysisSummaryResponse]:
    """
    Get the packet analysis summary for a completed job.

    Phase 2 endpoint providing packet counts, protocol detection,
    and session candidate information.

    Args:
        job_id: Analysis job identifier
        db: Database session

    Returns:
        Packet analysis summary
    """
    # Get the job first
    job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_JOB_NOT_FOUND",
                "message": f"Analysis job not found: {job_id}"
            }
        )

    # Get packet analysis
    analysis = db.query(PacketAnalysis).filter(
        PacketAnalysis.job_id == job_id
    ).first()

    if not analysis:
        # No analysis yet - check job status
        if job.status == JobStatus.QUEUED:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "ANALYSIS_NOT_STARTED",
                    "message": "Analysis has not started yet"
                }
            )
        elif job.status == JobStatus.RUNNING:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "ANALYSIS_IN_PROGRESS",
                    "message": f"Analysis is in progress: {job.stage}"
                }
            )
        elif job.status in (JobStatus.FAILED, JobStatus.TIMEOUT):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": job.error_code or "ANALYSIS_FAILED",
                    "message": job.error_message or "Analysis failed"
                }
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "ANALYSIS_NOT_FOUND",
                    "message": "No analysis results found"
                }
            )

    # Build response
    response = PacketAnalysisSummaryResponse(
        analysis_id=analysis.analysis_id,
        job_id=analysis.job_id,
        evidence_id=analysis.evidence_id,
        status=job.status.value,
        tshark_version=analysis.tshark_version,
        analysis_timestamp=analysis.analysis_timestamp,
        duration_seconds=analysis.duration_seconds,
        total_packets=analysis.total_packets,
        email_packets=analysis.email_packets,
        smtp_packets=analysis.smtp_packets,
        imap_packets=analysis.imap_packets,
        pop3_packets=analysis.pop3_packets,
        tls_packets=analysis.tls_packets,
        other_packets=analysis.other_packets,
        protocols_detected=analysis.protocols_detected or [],
        protocol_detections=[
            ProtocolDetectionResponse(**d) for d in (analysis.protocol_detections or [])
        ],
        session_candidates=[
            SessionCandidateResponse(**c) for c in (analysis.session_candidates or [])
        ],
        message=analysis.message,
    )

    return ApiResponse.ok(response)


@router.get(
    "/analysis/{job_id}/protocols",
    response_model=ApiResponse[ProtocolSummaryResponse],
    tags=["Analysis"],
    summary="Get detected protocols summary"
)
async def get_protocols_summary(
    job_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[ProtocolSummaryResponse]:
    """
    Get a summary of detected protocols for an analysis job.

    Provides a quick overview of which email protocols were detected.

    Args:
        job_id: Analysis job identifier
        db: Database session

    Returns:
        Protocol detection summary
    """
    # Get the job
    job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_JOB_NOT_FOUND",
                "message": f"Analysis job not found: {job_id}"
            }
        )

    # Get packet analysis
    analysis = db.query(PacketAnalysis).filter(
        PacketAnalysis.job_id == job_id
    ).first()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_NOT_FOUND",
                "message": "No analysis results found for this job"
            }
        )

    response = ProtocolSummaryResponse(
        protocols_detected=analysis.protocols_detected or [],
        protocol_counts={
            "SMTP": analysis.smtp_packets,
            "IMAP": analysis.imap_packets,
            "POP3": analysis.pop3_packets,
            "TLS": analysis.tls_packets,
        },
        total_email_packets=analysis.email_packets,
        has_tls=analysis.tls_packets > 0,
        session_count=len(analysis.session_candidates or []),
    )

    return ApiResponse.ok(response)


@router.post(
    "/evidence/{evidence_id}/analyze",
    response_model=ApiResponse[TriggerAnalysisResponse],
    tags=["Analysis"],
    summary="Trigger analysis for evidence"
)
async def trigger_analysis(
    evidence_id: str,
    db: Session = Depends(get_db)
) -> ApiResponse[TriggerAnalysisResponse]:
    """
    Trigger packet analysis for evidence.

    If a QUEUED job exists, it will be started. Otherwise returns
    the status of the existing job.

    Args:
        evidence_id: Evidence identifier
        db: Database session

    Returns:
        Analysis trigger result
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

    # Get the latest job for this evidence
    job = db.query(AnalysisJob).filter(
        AnalysisJob.evidence_id == evidence_id
    ).order_by(AnalysisJob.created_at.desc()).first()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ANALYSIS_JOB_NOT_FOUND",
                "message": "No analysis job found for this evidence"
            }
        )

    # Check job status
    if job.status == JobStatus.QUEUED:
        # Check execution mode
        execution_mode = settings.analysis_execution_mode.lower()

        if execution_mode == "demo":
            # DEMO MODE: Execute synchronously
            logger.info(
                f"Triggering DEMO MODE analysis for job {job.job_id}",
                extra={"job_id": job.job_id, "evidence_id": evidence_id, "mode": "demo"}
            )

            try:
                # Execute Phase 2 synchronously
                phase2_result = execute_phase2_analysis(db, job.job_id)

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

                # Execute Phase 3 synchronously
                phase3_result = execute_phase3_analysis(db, phase3_job_id, phase2_result.get("packet_analysis_id"))

                # Create Phase 4 job
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

                # Execute Phase 4 synchronously
                execute_phase4_analysis(db, phase4_job_id, phase3_result.get("security_analysis_id"), enable_ml=False)

                return ApiResponse.ok(TriggerAnalysisResponse(
                    job_id=job.job_id,
                    status="COMPLETED",
                    message="Analysis completed successfully (demo mode: Phase 2-3-4)"
                ))

            except AnalysisExecutionError as e:
                logger.error(f"Demo mode analysis failed: {e.code} - {e.message}")
                return ApiResponse.ok(TriggerAnalysisResponse(
                    job_id=job.job_id,
                    status="FAILED",
                    message=f"Analysis failed: {e.message}"
                ))

        else:
            # CELERY MODE: Use asynchronous Celery task (production)
            logger.info(
                f"Triggering CELERY MODE analysis for job {job.job_id}",
                extra={"job_id": job.job_id, "evidence_id": evidence_id, "mode": "celery"}
            )
            analyze_evidence.delay(job.job_id)

            return ApiResponse.ok(TriggerAnalysisResponse(
                job_id=job.job_id,
                status="TRIGGERED",
                message="Analysis has been triggered"
            ))

    elif job.status == JobStatus.RUNNING:
        return ApiResponse.ok(TriggerAnalysisResponse(
            job_id=job.job_id,
            status="RUNNING",
            message=f"Analysis is already running: {job.stage}"
        ))

    elif job.status == JobStatus.COMPLETED:
        return ApiResponse.ok(TriggerAnalysisResponse(
            job_id=job.job_id,
            status="COMPLETED",
            message="Analysis has already completed"
        ))

    else:  # FAILED, TIMEOUT, etc.
        return ApiResponse.ok(TriggerAnalysisResponse(
            job_id=job.job_id,
            status=job.status.value,
            message=job.error_message or f"Analysis {job.status.value}"
        ))


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
