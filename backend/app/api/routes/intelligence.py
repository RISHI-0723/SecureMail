"""Phase 4 Intelligence Analysis API endpoints.

Endpoints for:
- Intelligence analysis summary
- Correlations
- Recommendations
- ML insights and anomalies
- Reports (JSON/HTML/PDF)
- Evidence integrity
- Triggering intelligence analysis

IMPORTANT: These endpoints return Phase 4 intelligence results.
They do NOT re-run Phase 3 or TShark.
"""
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis_job import AnalysisJob, JobStatus, JobType, generate_job_id
from app.models.evidence import PcapEvidence
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.models.intelligence import (
    IntelligenceReport,
    IntelligenceStatus,
    Correlation,
    Recommendation,
    MLPrediction,
    GeneratedReport,
    EvidenceIntegrity,
    ReportFormat,
    ReportStatus,
    IntegrityStatus,
    CorrelationType,
    RecommendationPriority,
)
from app.schemas.common import ApiResponse
from app.schemas.intelligence import (
    IntelligenceSummaryResponse,
    CorrelationResponse,
    CorrelationsResponse,
    RecommendationResponse,
    RecommendationsResponse,
    MLInsightsResponse,
    AnomalyResponse,
    ReportListResponse,
    ReportInfoResponse,
    IntegrityResponse,
    TriggerIntelligenceRequest,
    TriggerIntelligenceResponse,
    SecurityPostureResponse,
)
from app.workers.security_tasks import run_intelligence_analysis

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_intelligence_report(
    evidence_id: str,
    db: Session
) -> IntelligenceReport:
    """Get intelligence report for evidence, raising appropriate errors."""
    report = db.query(IntelligenceReport).filter(
        IntelligenceReport.evidence_id == evidence_id
    ).order_by(IntelligenceReport.created_at.desc()).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "INTELLIGENCE_NOT_FOUND",
                "message": f"No intelligence analysis found for evidence: {evidence_id}"
            }
        )

    if report.status == IntelligenceStatus.QUEUED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "INTELLIGENCE_NOT_STARTED",
                "message": "Intelligence analysis has not started yet"
            }
        )

    if report.status == IntelligenceStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "INTELLIGENCE_IN_PROGRESS",
                "message": "Intelligence analysis is in progress"
            }
        )

    if report.status == IntelligenceStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": report.error_code or "INTELLIGENCE_FAILED",
                "message": report.error_message or "Intelligence analysis failed"
            }
        )

    return report


@router.get(
    "/evidence/{evidence_id}/intelligence",
    response_model=ApiResponse[IntelligenceSummaryResponse],
    summary="Get intelligence analysis summary",
    description="Get Phase 4 intelligence analysis summary for evidence."
)
def get_intelligence_summary(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Get intelligence analysis summary for evidence."""
    report = _get_intelligence_report(evidence_id, db)

    # Get counts
    correlations_count = db.query(Correlation).filter(
        Correlation.intelligence_report_id == report.report_id
    ).count()

    recommendations_count = db.query(Recommendation).filter(
        Recommendation.intelligence_report_id == report.report_id
    ).count()

    return ApiResponse(
        success=True,
        data=IntelligenceSummaryResponse(
            report_id=report.report_id,
            evidence_id=report.evidence_id,
            security_analysis_id=report.security_analysis_id,
            status=report.status.value,
            created_at=report.created_at,
            completed_at=report.completed_at,
            duration_seconds=report.duration_seconds,
            total_correlations=correlations_count,
            total_recommendations=recommendations_count,
            ml_enabled=report.ml_enabled,
            ml_predictions_count=report.ml_predictions_count,
            anomalies_detected=report.anomalies_detected,
            security_posture_score=report.security_posture_score,
            security_posture_grade=report.security_posture_grade,
            tls_security_score=report.tls_security_score,
            certificate_security_score=report.certificate_security_score,
            protocol_security_score=report.protocol_security_score,
            configuration_security_score=report.configuration_security_score,
            executive_summary=report.executive_summary,
        )
    )


@router.get(
    "/evidence/{evidence_id}/intelligence/posture",
    response_model=ApiResponse[SecurityPostureResponse],
    summary="Get security posture",
    description="Get security posture assessment from intelligence analysis."
)
def get_security_posture(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Get security posture from intelligence analysis."""
    report = _get_intelligence_report(evidence_id, db)

    return ApiResponse(
        success=True,
        data=SecurityPostureResponse(
            overall_score=report.security_posture_score or 0.0,
            grade=report.security_posture_grade or "N/A",
            tls_security_score=report.tls_security_score or 0.0,
            certificate_security_score=report.certificate_security_score or 0.0,
            protocol_security_score=report.protocol_security_score or 0.0,
            configuration_security_score=report.configuration_security_score or 0.0,
            aggregated_findings=report.aggregated_findings or [],
            correlation_summary=report.correlation_summary or {},
            recommendation_summary=report.recommendation_summary or {},
        )
    )


@router.get(
    "/evidence/{evidence_id}/correlations",
    response_model=ApiResponse[CorrelationsResponse],
    summary="Get correlations",
    description="Get security correlations identified in Phase 4."
)
def get_correlations(
    evidence_id: str,
    correlation_type: Optional[str] = Query(None, description="Filter by correlation type"),
    min_strength: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum strength"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get correlations for evidence."""
    report = _get_intelligence_report(evidence_id, db)

    query = db.query(Correlation).filter(
        Correlation.intelligence_report_id == report.report_id
    )

    if correlation_type:
        try:
            ct = CorrelationType(correlation_type)
            query = query.filter(Correlation.correlation_type == ct)
        except ValueError:
            pass

    if min_strength is not None:
        query = query.filter(Correlation.strength >= min_strength)

    total = query.count()
    correlations = query.order_by(Correlation.strength.desc()).offset(offset).limit(limit).all()

    return ApiResponse(
        success=True,
        data=CorrelationsResponse(
            total=total,
            correlations=[
                CorrelationResponse(
                    correlation_id=c.correlation_id,
                    correlation_type=c.correlation_type.value,
                    strength=c.strength,
                    confidence=c.confidence,
                    title=c.title,
                    description=c.description,
                    linked_findings=c.linked_findings or [],
                    linked_sessions=c.linked_sessions or [],
                    linked_certificates=c.linked_certificates or [],
                    common_attribute=c.common_attribute,
                    common_value=c.common_value,
                    combined_severity=c.combined_severity,
                    combined_risk_score=c.combined_risk_score,
                    created_at=c.created_at,
                )
                for c in correlations
            ]
        )
    )


@router.get(
    "/evidence/{evidence_id}/recommendations",
    response_model=ApiResponse[RecommendationsResponse],
    summary="Get recommendations",
    description="Get security recommendations from Phase 4."
)
def get_recommendations(
    evidence_id: str,
    priority: Optional[str] = Query(None, description="Filter by priority"),
    category: Optional[str] = Query(None, description="Filter by category"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get recommendations for evidence."""
    report = _get_intelligence_report(evidence_id, db)

    query = db.query(Recommendation).filter(
        Recommendation.intelligence_report_id == report.report_id
    )

    if priority:
        try:
            p = RecommendationPriority(priority)
            query = query.filter(Recommendation.priority == p)
        except ValueError:
            pass

    if category:
        query = query.filter(Recommendation.category == category)

    if status_filter:
        query = query.filter(Recommendation.status == status_filter)

    total = query.count()

    # Order by priority
    priority_order = {
        RecommendationPriority.CRITICAL: 1,
        RecommendationPriority.HIGH: 2,
        RecommendationPriority.MEDIUM: 3,
        RecommendationPriority.LOW: 4,
        RecommendationPriority.INFO: 5,
    }

    recommendations = query.offset(offset).limit(limit).all()
    recommendations.sort(key=lambda r: priority_order.get(r.priority, 5))

    return ApiResponse(
        success=True,
        data=RecommendationsResponse(
            total=total,
            recommendations=[
                RecommendationResponse(
                    recommendation_id=r.recommendation_id,
                    priority=r.priority.value,
                    category=r.category.value,
                    title=r.title,
                    description=r.description,
                    remediation_steps=r.remediation_steps or [],
                    estimated_effort=r.estimated_effort,
                    technical_impact=r.technical_impact,
                    business_impact=r.business_impact,
                    affected_findings=r.affected_findings or [],
                    affected_sessions=r.affected_sessions or [],
                    affected_certificates=r.affected_certificates or [],
                    compliance_references=r.compliance_references,
                    status=r.status,
                    created_at=r.created_at,
                )
                for r in recommendations
            ]
        )
    )


@router.get(
    "/evidence/{evidence_id}/ml",
    response_model=ApiResponse[MLInsightsResponse],
    summary="Get ML insights",
    description="Get ML-based insights and anomaly detection results."
)
def get_ml_insights(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Get ML insights for evidence."""
    report = _get_intelligence_report(evidence_id, db)

    if not report.ml_enabled:
        return ApiResponse(
            success=True,
            data=MLInsightsResponse(
                ml_enabled=False,
                message="ML analysis was not performed or is not available",
                model_version=None,
                total_predictions=0,
                anomalies_detected=0,
                anomalies=[],
                top_risk_factors=[],
                confidence=0.0,
            )
        )

    # Get anomaly predictions
    predictions = db.query(MLPrediction).filter(
        MLPrediction.intelligence_report_id == report.report_id,
        MLPrediction.is_anomaly == True
    ).order_by(MLPrediction.anomaly_score.asc()).limit(10).all()

    # Extract top risk factors from ML insights
    ml_insights = report.ml_insights or {}
    top_risk_factors = ml_insights.get("top_risk_factors", [])

    return ApiResponse(
        success=True,
        data=MLInsightsResponse(
            ml_enabled=True,
            model_version=report.ml_model_version,
            total_predictions=report.ml_predictions_count or 0,
            anomalies_detected=report.anomalies_detected or 0,
            anomalies=[
                AnomalyResponse(
                    prediction_id=p.prediction_id,
                    target_type=p.target_type,
                    target_id=p.target_id,
                    anomaly_score=p.anomaly_score,
                    confidence=p.confidence,
                    feature_importance=p.feature_importance,
                    explanation=ml_insights.get("summary", ""),
                )
                for p in predictions
            ],
            top_risk_factors=top_risk_factors,
            confidence=report.ml_confidence_score or 0.0,
        )
    )


@router.get(
    "/evidence/{evidence_id}/reports",
    response_model=ApiResponse[ReportListResponse],
    summary="Get generated reports",
    description="List generated reports for evidence."
)
def get_reports(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Get list of generated reports for evidence."""
    report = _get_intelligence_report(evidence_id, db)

    reports = db.query(GeneratedReport).filter(
        GeneratedReport.intelligence_report_id == report.report_id
    ).all()

    return ApiResponse(
        success=True,
        data=ReportListResponse(
            total=len(reports),
            reports=[
                ReportInfoResponse(
                    report_id=r.report_id,
                    format=r.format.value,
                    status=r.status.value,
                    filename=r.filename,
                    file_size_bytes=r.file_size_bytes,
                    content_hash=r.content_hash,
                    generated_at=r.generated_at,
                    error_message=r.error_message,
                )
                for r in reports
            ]
        )
    )


@router.get(
    "/reports/{report_id}/download",
    summary="Download report",
    description="Download a generated report file."
)
def download_report(
    report_id: str,
    db: Session = Depends(get_db)
):
    """Download a generated report."""
    from app.core.config import settings

    report = db.query(GeneratedReport).filter(
        GeneratedReport.report_id == report_id
    ).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_NOT_FOUND", "message": "Report not found"}
        )

    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_NOT_READY", "message": "Report generation not completed"}
        )

    if not report.filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_FILE_MISSING", "message": "Report file not available"}
        )

    # Construct file path using report_id (not user-supplied filename)
    reports_dir = Path(getattr(settings, 'REPORTS_DIR', './reports'))
    file_path = reports_dir / report.filename

    # Verify path doesn't escape reports directory (security)
    try:
        file_path = file_path.resolve()
        reports_dir = reports_dir.resolve()
        if not str(file_path).startswith(str(reports_dir)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "PATH_TRAVERSAL", "message": "Invalid file path"}
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_FILE_ERROR", "message": "Error accessing report file"}
        )

    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "REPORT_FILE_MISSING", "message": "Report file not found on disk"}
        )

    # Determine media type
    media_type_map = {
        ReportFormat.JSON: "application/json",
        ReportFormat.HTML: "text/html",
        ReportFormat.PDF: "application/pdf",
    }
    media_type = media_type_map.get(report.format, "application/octet-stream")

    return FileResponse(
        path=file_path,
        filename=report.filename,
        media_type=media_type,
    )


@router.get(
    "/evidence/{evidence_id}/integrity",
    response_model=ApiResponse[IntegrityResponse],
    summary="Get evidence integrity",
    description="Get evidence integrity and verification status."
)
def get_integrity(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Get evidence integrity status."""
    # Get latest integrity record
    integrity = db.query(EvidenceIntegrity).filter(
        EvidenceIntegrity.evidence_id == evidence_id
    ).order_by(EvidenceIntegrity.created_at.desc()).first()

    if not integrity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INTEGRITY_NOT_FOUND", "message": "No integrity record found"}
        )

    return ApiResponse(
        success=True,
        data=IntegrityResponse(
            integrity_id=integrity.integrity_id,
            evidence_id=integrity.evidence_id,
            status=integrity.status.value,
            evidence_sha256=integrity.evidence_sha256,
            evidence_sha512=integrity.evidence_sha512,
            analysis_hash=integrity.analysis_hash,
            report_hash=integrity.report_hash,
            merkle_root=integrity.merkle_root,
            blockchain_enabled=integrity.blockchain_enabled,
            blockchain_network=integrity.blockchain_network,
            transaction_hash=integrity.transaction_hash,
            block_number=integrity.block_number,
            anchor_timestamp=integrity.anchor_timestamp,
            created_at=integrity.created_at,
            verified_at=integrity.verified_at,
        )
    )


@router.post(
    "/integrity/verify",
    response_model=ApiResponse[IntegrityResponse],
    summary="Verify evidence integrity",
    description="Verify evidence integrity against stored hashes."
)
def verify_integrity(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    """Verify evidence integrity."""
    from app.services.integrity.integrity_service import IntegrityService, IntegrityRecord

    # Get evidence
    evidence = db.query(PcapEvidence).filter(
        PcapEvidence.evidence_id == evidence_id
    ).first()

    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": "Evidence not found"}
        )

    # Get integrity record
    integrity = db.query(EvidenceIntegrity).filter(
        EvidenceIntegrity.evidence_id == evidence_id
    ).order_by(EvidenceIntegrity.created_at.desc()).first()

    if not integrity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INTEGRITY_NOT_FOUND", "message": "No integrity record found to verify against"}
        )

    # Verify
    service = IntegrityService()
    stored_record = IntegrityRecord(
        evidence_id=evidence_id,
        evidence_sha256=integrity.evidence_sha256,
        evidence_sha512=integrity.evidence_sha512,
        blockchain_enabled=integrity.blockchain_enabled,
        transaction_hash=integrity.transaction_hash,
    )

    evidence_path = Path(evidence.storage_location) if evidence.storage_location else None

    if not evidence_path or not evidence_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_FILE_NOT_FOUND", "message": "Evidence file not found on disk"}
        )

    result = service.verify_evidence_integrity(evidence_path, stored_record)

    # Update integrity record
    if result.evidence_hash_match:
        integrity.status = IntegrityStatus.VERIFIED
        integrity.verified_at = datetime.now(timezone.utc)
    else:
        integrity.status = IntegrityStatus.FAILED
        integrity.verified_at = datetime.now(timezone.utc)

    db.commit()

    return ApiResponse(
        success=True,
        data=IntegrityResponse(
            integrity_id=integrity.integrity_id,
            evidence_id=integrity.evidence_id,
            status=integrity.status.value,
            evidence_sha256=integrity.evidence_sha256,
            evidence_sha512=integrity.evidence_sha512,
            analysis_hash=integrity.analysis_hash,
            report_hash=integrity.report_hash,
            merkle_root=integrity.merkle_root,
            blockchain_enabled=integrity.blockchain_enabled,
            blockchain_network=integrity.blockchain_network,
            transaction_hash=integrity.transaction_hash,
            block_number=integrity.block_number,
            anchor_timestamp=integrity.anchor_timestamp,
            created_at=integrity.created_at,
            verified_at=integrity.verified_at,
            verification_message=result.message,
        )
    )


@router.post(
    "/evidence/{evidence_id}/intelligence",
    response_model=ApiResponse[TriggerIntelligenceResponse],
    summary="Trigger intelligence analysis",
    description="Trigger Phase 4 intelligence analysis for evidence."
)
def trigger_intelligence_analysis(
    evidence_id: str,
    request: TriggerIntelligenceRequest = None,
    db: Session = Depends(get_db)
):
    """
    Trigger Phase 4 intelligence analysis.

    Requires completed Phase 3 security analysis.
    """
    # Verify evidence exists
    evidence = db.query(PcapEvidence).filter(
        PcapEvidence.evidence_id == evidence_id
    ).first()

    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": "Evidence not found"}
        )

    # Check for completed Phase 3 analysis
    security_analysis = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.evidence_id == evidence_id,
        SecurityAnalysis.status == SecurityAnalysisStatus.COMPLETED
    ).order_by(SecurityAnalysis.completed_at.desc()).first()

    if not security_analysis:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "PHASE3_NOT_COMPLETED",
                "message": "Phase 3 security analysis must be completed before Phase 4"
            }
        )

    # Check if intelligence analysis is already running
    existing = db.query(IntelligenceReport).filter(
        IntelligenceReport.evidence_id == evidence_id,
        IntelligenceReport.status == IntelligenceStatus.RUNNING
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "INTELLIGENCE_ALREADY_RUNNING",
                "message": "Intelligence analysis is already running for this evidence"
            }
        )

    # Create job
    job_id = generate_job_id()
    job = AnalysisJob(
        job_id=job_id,
        evidence_id=evidence_id,
        job_type=JobType.INTELLIGENCE,
        status=JobStatus.QUEUED,
        stage="QUEUED",
    )
    db.add(job)
    db.commit()

    # Queue Celery task
    enable_ml = request.enable_ml if request else True
    generate_reports = request.generate_reports if request else True

    run_intelligence_analysis.delay(
        job_id=job_id,
        security_analysis_id=security_analysis.analysis_id,
        generate_reports=generate_reports,
        enable_ml=enable_ml,
    )

    logger.info(
        f"Intelligence analysis triggered for evidence {evidence_id}",
        extra={"job_id": job_id, "evidence_id": evidence_id}
    )

    return ApiResponse(
        success=True,
        data=TriggerIntelligenceResponse(
            job_id=job_id,
            evidence_id=evidence_id,
            status="QUEUED",
            message="Intelligence analysis queued successfully",
            security_analysis_id=security_analysis.analysis_id,
        )
    )
