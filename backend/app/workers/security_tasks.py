"""Phase 3 Celery tasks for security analysis.

Phase 3 Security Intelligence Engine task.

IMPORTANT: This task is SEPARATE from Phase 2 analyze_evidence.
It consumes Phase 2 results and DOES NOT re-run TShark.

This task:
1. Reads Phase 2 packet analysis results
2. Reconstructs TCP streams
3. Analyzes email security (STARTTLS/STLS)
4. Analyzes TLS observations
5. Analyzes certificates
6. Generates security findings
7. Calculates risk assessment
8. Persists results to security_analyses table

Boundary Enforcement:
- NO TShark calls
- NO ML inference
- NO PDF generation
- NO blockchain
- Deterministic analysis only
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from celery import Task
from sqlalchemy.exc import OperationalError, InterfaceError

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.analysis_job import AnalysisJob, JobStatus, JobType
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.services.packet.models import PacketRecord, ProtocolSessionCandidate

# Phase 3 services
from app.services.tcp import TcpStreamReconstructor
from app.services.email import EmailSecurityAnalyzer
from app.services.tls import TlsAnalyzer
from app.services.certificates import CertificateAnalyzer
from app.services.crypto import RulesEngine, get_default_policy
from app.services.findings import FindingEngine
from app.services.risk import RiskEngine

logger = logging.getLogger(__name__)

# Database retry configuration
DB_MAX_RETRIES = 2
DB_RETRY_COUNTDOWN = 10


class SecurityAnalysisTask(Task):
    """Base task with database retry handling for security analysis."""

    autoretry_for = (OperationalError, InterfaceError)
    retry_kwargs = {'max_retries': DB_MAX_RETRIES, 'countdown': DB_RETRY_COUNTDOWN}
    retry_backoff = False


@celery_app.task(
    name="app.workers.security_tasks.run_security_analysis",
    bind=True,
    base=SecurityAnalysisTask,
    acks_late=True,
)
def run_security_analysis(
    self,
    job_id: str,
    packet_analysis_id: Optional[str] = None
) -> dict:
    """
    Run Phase 3 security analysis on Phase 2 results.

    IMPORTANT: This task does NOT re-run TShark.
    It consumes Phase 2 PacketAnalysis results.

    Args:
        job_id: Analysis job identifier (Phase 3 job)
        packet_analysis_id: Optional Phase 2 PacketAnalysis ID.
            If not provided, looks up by evidence_id.

    Returns:
        Analysis result dictionary
    """
    db = SessionLocal()
    job = None
    security_analysis = None
    start_time = datetime.now(timezone.utc)

    try:
        # Get the analysis job
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            logger.error(f"Analysis job not found: {job_id}")
            return {
                "status": "FAILED",
                "error_code": "ANALYSIS_JOB_NOT_FOUND",
                "error_message": f"Job not found: {job_id}"
            }

        # Update job to RUNNING
        job.status = JobStatus.RUNNING
        job.started_at = start_time
        job.stage = "INITIALIZING_SECURITY_ANALYSIS"
        db.commit()

        # Get Phase 2 packet analysis results
        packet_analysis = None
        if packet_analysis_id:
            packet_analysis = db.query(PacketAnalysis).filter(
                PacketAnalysis.analysis_id == packet_analysis_id
            ).first()
        else:
            # Look up by evidence_id
            packet_analysis = db.query(PacketAnalysis).filter(
                PacketAnalysis.evidence_id == job.evidence_id
            ).first()

        if not packet_analysis:
            logger.warning(
                f"No Phase 2 packet analysis found for job {job_id}. "
                "Will create limited security analysis."
            )

        # Create SecurityAnalysis record
        security_analysis = SecurityAnalysis(
            job_id=job_id,
            evidence_id=job.evidence_id,
            packet_analysis_id=packet_analysis.analysis_id if packet_analysis else None,
            status=SecurityAnalysisStatus.RUNNING,
            started_at=start_time,
            policy_version=get_default_policy().version
        )
        db.add(security_analysis)
        db.commit()

        logger.info(
            f"Starting security analysis for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "packet_analysis_id": packet_analysis.analysis_id if packet_analysis else None
            }
        )

        # Initialize services
        stream_reconstructor = TcpStreamReconstructor()
        email_analyzer = EmailSecurityAnalyzer()
        tls_analyzer = TlsAnalyzer()
        certificate_analyzer = CertificateAnalyzer()
        finding_engine = FindingEngine()
        risk_engine = RiskEngine()

        # Step 1: Reconstruct TCP streams from Phase 2 session candidates
        job.stage = "RECONSTRUCTING_TCP_STREAMS"
        job.progress_percent = "10"
        db.commit()

        if packet_analysis and packet_analysis.session_candidates:
            # Convert session candidates to packet records for stream reconstruction
            packets = _session_candidates_to_packets(packet_analysis.session_candidates)
            stream_reconstructor.process_packets(packets)

        stream_result = stream_reconstructor.get_result(job.evidence_id, job_id)
        streams = stream_reconstructor.get_streams()

        logger.info(
            f"TCP stream reconstruction complete",
            extra={
                "job_id": job_id,
                "total_streams": stream_result.total_streams
            }
        )

        # Step 2: Analyze email security
        job.stage = "ANALYZING_EMAIL_SECURITY"
        job.progress_percent = "25"
        db.commit()

        email_analyzer.analyze_streams(streams)
        email_result = email_analyzer.get_result(job.evidence_id, job_id)
        sessions = email_analyzer.get_sessions()

        logger.info(
            f"Email security analysis complete",
            extra={
                "job_id": job_id,
                "total_sessions": email_result.total_sessions
            }
        )

        # Step 3: Analyze TLS observations
        job.stage = "ANALYZING_TLS"
        job.progress_percent = "40"
        db.commit()

        tls_analyzer.analyze_sessions(sessions, streams)
        tls_result = tls_analyzer.get_result(job.evidence_id, job_id)
        tls_observations = tls_analyzer.get_observations()

        logger.info(
            f"TLS analysis complete",
            extra={
                "job_id": job_id,
                "total_observations": tls_result.total_observations
            }
        )

        # Step 4: Analyze certificates
        job.stage = "ANALYZING_CERTIFICATES"
        job.progress_percent = "55"
        db.commit()

        certificate_analyzer.analyze_tls_observations(tls_observations)
        cert_result = certificate_analyzer.get_result(job.evidence_id, job_id)
        certificates = certificate_analyzer.get_certificates()

        logger.info(
            f"Certificate analysis complete",
            extra={
                "job_id": job_id,
                "total_certificates": cert_result.total_certificates
            }
        )

        # Step 5: Generate findings
        job.stage = "GENERATING_FINDINGS"
        job.progress_percent = "70"
        db.commit()

        finding_engine.analyze_streams(streams, job.evidence_id, job_id)
        finding_engine.analyze_email_sessions(sessions, job.evidence_id, job_id)
        finding_engine.analyze_tls_observations(tls_observations, job.evidence_id, job_id)
        finding_engine.analyze_certificates(certificates, job.evidence_id, job_id)
        findings_result = finding_engine.get_result(job.evidence_id, job_id)

        logger.info(
            f"Finding generation complete",
            extra={
                "job_id": job_id,
                "total_findings": findings_result.summary.total_findings
            }
        )

        # Step 6: Calculate risk assessment
        job.stage = "CALCULATING_RISK"
        job.progress_percent = "85"
        db.commit()

        risk_assessment = risk_engine.assess_risk(
            findings_result,
            total_streams=len(streams),
            total_sessions=len(sessions),
            total_certificates=len(certificates),
            confidence=_determine_confidence(packet_analysis),
            coverage=_determine_coverage(packet_analysis)
        )

        logger.info(
            f"Risk assessment complete",
            extra={
                "job_id": job_id,
                "overall_risk": risk_assessment.posture.overall_risk.value,
                "overall_score": risk_assessment.posture.overall_score
            }
        )

        # Step 7: Persist results
        job.stage = "PERSISTING_RESULTS"
        job.progress_percent = "95"
        db.commit()

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Update SecurityAnalysis with results
        security_analysis.status = SecurityAnalysisStatus.COMPLETED
        security_analysis.completed_at = end_time
        security_analysis.duration_seconds = duration

        # Counts
        security_analysis.total_streams = len(streams)
        security_analysis.total_sessions = len(sessions)
        security_analysis.total_tls_observations = len(tls_observations)
        security_analysis.total_certificates = len(certificates)
        security_analysis.total_findings = findings_result.summary.total_findings

        # Finding severities
        security_analysis.critical_findings = findings_result.summary.critical_count
        security_analysis.high_findings = findings_result.summary.high_count
        security_analysis.medium_findings = findings_result.summary.medium_count
        security_analysis.low_findings = findings_result.summary.low_count
        security_analysis.info_findings = findings_result.summary.info_count

        # Risk
        security_analysis.overall_risk_level = risk_assessment.posture.overall_risk.value
        security_analysis.overall_risk_score = risk_assessment.posture.overall_score

        # Metadata
        security_analysis.confidence = risk_assessment.posture.confidence
        security_analysis.coverage = risk_assessment.posture.coverage

        # JSON data
        security_analysis.tcp_streams = [s.model_dump() for s in streams]
        security_analysis.email_sessions = [s.model_dump() for s in sessions]
        security_analysis.tls_observations = [o.model_dump() for o in tls_observations]
        security_analysis.certificates = [c.model_dump() for c in certificates]
        security_analysis.findings = [f.model_dump() for f in findings_result.findings]
        security_analysis.risk_assessment = risk_assessment.model_dump()

        # Update job
        job.status = JobStatus.COMPLETED
        job.completed_at = end_time
        job.stage = "COMPLETED"
        job.progress_percent = "100"
        job.error_code = None
        job.error_message = None

        db.commit()

        logger.info(
            f"Security analysis completed successfully for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "duration_seconds": duration,
                "total_findings": findings_result.summary.total_findings,
                "overall_risk": risk_assessment.posture.overall_risk.value
            }
        )

        # Chain to Phase 4 Intelligence Analysis
        phase4_job_id = _trigger_phase4_analysis(db, job.evidence_id, security_analysis.analysis_id)

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "analysis_id": security_analysis.analysis_id,
            "total_streams": len(streams),
            "total_sessions": len(sessions),
            "total_findings": findings_result.summary.total_findings,
            "overall_risk": risk_assessment.posture.overall_risk.value,
            "overall_score": risk_assessment.posture.overall_score,
            "duration_seconds": duration,
            "phase4_job_id": phase4_job_id
        }

    except (OperationalError, InterfaceError) as e:
        logger.warning(f"Database error in security analysis task: {e}, will retry")
        db.rollback()
        raise  # Let Celery handle retry

    except Exception as e:
        logger.error(f"Unexpected error in security analysis task: {e}", exc_info=True)
        db.rollback()

        # Try to mark as failed
        if security_analysis:
            try:
                security_analysis.status = SecurityAnalysisStatus.FAILED
                security_analysis.error_code = "SECURITY_ANALYSIS_FAILED"
                security_analysis.error_message = str(e)[:500]
                security_analysis.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception:
                db.rollback()

        if job:
            try:
                job.status = JobStatus.FAILED
                job.error_code = "SECURITY_ANALYSIS_FAILED"
                job.error_message = str(e)[:500]
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception:
                pass

        return {
            "status": "FAILED",
            "error_code": "SECURITY_ANALYSIS_FAILED",
            "error_message": str(e)
        }

    finally:
        db.close()


def _session_candidates_to_packets(
    session_candidates: list[dict]
) -> list[PacketRecord]:
    """
    Convert Phase 2 session candidates to packet records.

    Phase 2 stores aggregate session candidate data, not individual packets.
    This function creates synthetic packet records for stream reconstruction.
    """
    packets = []
    for candidate in session_candidates:
        # Create a representative packet for each session candidate
        packet = PacketRecord(
            frame_number=candidate.get("first_packet_number", 0),
            timestamp=candidate.get("start_time"),
            src_ip=candidate.get("client_ip", ""),
            dst_ip=candidate.get("server_ip", ""),
            src_port=candidate.get("client_port", 0),
            dst_port=candidate.get("server_port", 0),
            protocol=candidate.get("protocol", "TCP"),
            stream_id=candidate.get("stream_id"),
            tcp_flags=0,
            tcp_seq=0,
            tcp_ack=0,
            payload_length=candidate.get("packet_count", 0),
            info=f"Session candidate for {candidate.get('protocol', 'unknown')}"
        )
        packets.append(packet)

        # If we have packet count > 1, create additional synthetic packets
        # to represent the session's data volume
        packet_count = candidate.get("packet_count", 1)
        if packet_count > 1:
            # Add a second packet to represent the response direction
            response_packet = PacketRecord(
                frame_number=candidate.get("first_packet_number", 0) + 1,
                timestamp=candidate.get("start_time"),
                src_ip=candidate.get("server_ip", ""),
                dst_ip=candidate.get("client_ip", ""),
                src_port=candidate.get("server_port", 0),
                dst_port=candidate.get("client_port", 0),
                protocol=candidate.get("protocol", "TCP"),
                stream_id=candidate.get("stream_id"),
                tcp_flags=0,
                tcp_seq=0,
                tcp_ack=0,
                payload_length=0,
                info=f"Response for {candidate.get('protocol', 'unknown')}"
            )
            packets.append(response_packet)

    return packets


def _determine_confidence(packet_analysis: Optional[PacketAnalysis]) -> str:
    """Determine analysis confidence based on Phase 2 results."""
    if not packet_analysis:
        return "LOW"

    if packet_analysis.total_packets == 0:
        return "LOW"

    if packet_analysis.email_packets == 0:
        return "MEDIUM"  # No email traffic, but analyzed successfully

    return "HIGH"


def _determine_coverage(packet_analysis: Optional[PacketAnalysis]) -> str:
    """Determine analysis coverage based on Phase 2 results."""
    if not packet_analysis:
        return "UNKNOWN"

    if packet_analysis.total_packets == 0:
        return "UNKNOWN"

    # Check if we have session candidates
    if packet_analysis.session_candidates:
        return "COMPLETE"

    return "PARTIAL"


def _trigger_phase4_analysis(db, evidence_id: str, security_analysis_id: str) -> str:
    """
    Trigger Phase 4 intelligence analysis after Phase 3 completes.

    Returns the Phase 4 job ID.
    """
    from app.models.analysis_job import generate_job_id

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

    logger.info(
        f"Triggering Phase 4 intelligence analysis",
        extra={
            "phase4_job_id": phase4_job_id,
            "evidence_id": evidence_id,
            "security_analysis_id": security_analysis_id
        }
    )

    # Enqueue Phase 4 task
    run_intelligence_analysis.delay(
        job_id=phase4_job_id,
        security_analysis_id=security_analysis_id,
        generate_reports=True,
        enable_ml=True
    )

    return phase4_job_id


# ==============================================================================
# PHASE 4: INTELLIGENCE ANALYSIS TASK
# ==============================================================================
# This task consumes Phase 3 security analysis results and produces:
# - Intelligence aggregation
# - Correlations
# - Recommendations
# - ML feature engineering
# - Anomaly detection
# - Reports (JSON/HTML/PDF)
# - Evidence integrity records
#
# IMPORTANT: This task does NOT re-run TShark or Phase 3 analysis.
# It consumes Phase 3 results and DOES NOT modify them.
#
# Retry Policy:
# - ML failure: NO retry (deterministic results continue)
# - PDF failure: NO retry (JSON/HTML continue)
# - Blockchain failure: NO retry (local integrity continues)
# - Transient DB errors: Retry max 2 times with 60s backoff
# ==============================================================================

from app.models.intelligence import (
    IntelligenceReport,
    IntelligenceStatus,
    Correlation as CorrelationModel,
    Recommendation as RecommendationModel,
    MLPrediction,
    GeneratedReport,
    EvidenceIntegrity,
    CorrelationType as DbCorrelationType,
    RecommendationPriority as DbRecommendationPriority,
    RecommendationCategory as DbRecommendationCategory,
    ReportFormat as DbReportFormat,
    ReportStatus as DbReportStatus,
    IntegrityStatus as DbIntegrityStatus,
)


# Phase 4 DB retry configuration (60s backoff as per spec)
PHASE4_DB_MAX_RETRIES = 2
PHASE4_DB_RETRY_COUNTDOWN = 60


class IntelligenceAnalysisTask(Task):
    """
    Base task for Phase 4 intelligence analysis.

    Retry policy:
    - Transient DB errors: max 2 retries, 60s backoff
    - ML failures: NO retry
    - Report failures: NO retry
    - Blockchain failures: NO retry
    """

    autoretry_for = (OperationalError, InterfaceError)
    retry_kwargs = {'max_retries': PHASE4_DB_MAX_RETRIES, 'countdown': PHASE4_DB_RETRY_COUNTDOWN}
    retry_backoff = False


@celery_app.task(
    name="app.workers.security_tasks.run_intelligence_analysis",
    bind=True,
    base=IntelligenceAnalysisTask,
    acks_late=True,
)
def run_intelligence_analysis(
    self,
    job_id: str,
    security_analysis_id: Optional[str] = None,
    generate_reports: bool = True,
    enable_ml: bool = True,
) -> dict:
    """
    Run Phase 4 intelligence analysis on Phase 3 results.

    IMPORTANT: This task does NOT re-run TShark or Phase 3.
    It consumes Phase 3 SecurityAnalysis results.

    Args:
        job_id: Analysis job identifier (Phase 4 job)
        security_analysis_id: Optional Phase 3 SecurityAnalysis ID.
            If not provided, looks up by evidence_id.
        generate_reports: Whether to generate JSON/HTML/PDF reports
        enable_ml: Whether to run ML feature engineering and anomaly detection

    Returns:
        Analysis result dictionary
    """
    from pathlib import Path
    from app.models.evidence import PcapEvidence
    from app.services.intelligence import IntelligenceAggregator
    from app.services.intelligence.correlation_engine import CorrelationEngine
    from app.services.intelligence.recommendation_engine import RecommendationEngine
    from app.services.intelligence.models import IntelligenceResult, IntelligenceSummary
    from app.services.ml.feature_engineering import FeatureEngineer
    from app.services.ml.anomaly_detector import AnomalyDetector
    from app.services.ml.models import MLInsights
    from app.services.reports.report_generator import ReportGenerator
    from app.services.reports.models import ReportFormat
    from app.services.integrity.integrity_service import IntegrityService
    from app.services.findings.models import SecurityFinding
    from app.services.tls.models import TlsObservation
    from app.services.certificates.models import CertificateObservation
    from app.services.email.models import EmailSecuritySession
    from app.services.risk.models import RiskAssessment
    from app.core.config import settings

    db = SessionLocal()
    job = None
    intelligence_report = None
    start_time = datetime.now(timezone.utc)

    # ML status tracking
    ml_status = "NOT_ATTEMPTED"
    ml_error = None

    try:
        # Get the analysis job
        job = db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id).first()
        if not job:
            logger.error(f"Analysis job not found: {job_id}")
            return {
                "status": "FAILED",
                "error_code": "ANALYSIS_JOB_NOT_FOUND",
                "error_message": f"Job not found: {job_id}"
            }

        # Verify this is a Phase 4 job type
        if job.job_type and job.job_type != JobType.INTELLIGENCE:
            logger.warning(f"Job {job_id} is not an intelligence job type")

        # Update job to RUNNING
        job.status = JobStatus.RUNNING
        job.started_at = start_time
        job.stage = "INITIALIZING_INTELLIGENCE_ANALYSIS"
        db.commit()

        # Get Phase 3 security analysis results
        security_analysis = None
        if security_analysis_id:
            security_analysis = db.query(SecurityAnalysis).filter(
                SecurityAnalysis.analysis_id == security_analysis_id
            ).first()
        else:
            # Look up by evidence_id (most recent completed)
            security_analysis = db.query(SecurityAnalysis).filter(
                SecurityAnalysis.evidence_id == job.evidence_id,
                SecurityAnalysis.status == SecurityAnalysisStatus.COMPLETED
            ).order_by(SecurityAnalysis.completed_at.desc()).first()

        if not security_analysis:
            logger.error(f"No Phase 3 security analysis found for job {job_id}")
            _fail_phase4_job(db, job, "PHASE3_NOT_FOUND", "No completed Phase 3 security analysis found")
            return {
                "status": "FAILED",
                "error_code": "PHASE3_NOT_FOUND",
                "error_message": "No completed Phase 3 security analysis found"
            }

        if security_analysis.status != SecurityAnalysisStatus.COMPLETED:
            logger.error(f"Phase 3 analysis not completed: {security_analysis.status}")
            _fail_phase4_job(db, job, "PHASE3_NOT_COMPLETED", f"Phase 3 status: {security_analysis.status}")
            return {
                "status": "FAILED",
                "error_code": "PHASE3_NOT_COMPLETED",
                "error_message": f"Phase 3 analysis status: {security_analysis.status}"
            }

        # Check for duplicate concurrent execution
        existing_intelligence = db.query(IntelligenceReport).filter(
            IntelligenceReport.evidence_id == job.evidence_id,
            IntelligenceReport.status == IntelligenceStatus.RUNNING
        ).first()

        if existing_intelligence and existing_intelligence.job_id != job_id:
            logger.warning(f"Duplicate intelligence analysis detected for evidence {job.evidence_id}")
            _fail_phase4_job(db, job, "DUPLICATE_EXECUTION", "Intelligence analysis already running")
            return {
                "status": "FAILED",
                "error_code": "DUPLICATE_EXECUTION",
                "error_message": "Intelligence analysis already running for this evidence"
            }

        # Create IntelligenceReport record
        intelligence_report = IntelligenceReport(
            evidence_id=job.evidence_id,
            security_analysis_id=security_analysis.analysis_id,
            job_id=job_id,
            status=IntelligenceStatus.RUNNING,
            created_at=start_time,
        )
        db.add(intelligence_report)
        db.commit()

        logger.info(
            f"Starting intelligence analysis for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "security_analysis_id": security_analysis.analysis_id
            }
        )

        # Deserialize Phase 3 data
        findings = [SecurityFinding(**f) for f in (security_analysis.findings or [])]
        tls_observations = [TlsObservation(**o) for o in (security_analysis.tls_observations or [])]
        certificates = [CertificateObservation(**c) for c in (security_analysis.certificates or [])]
        sessions = [EmailSecuritySession(**s) for s in (security_analysis.email_sessions or [])]
        risk_assessment = None
        if security_analysis.risk_assessment:
            risk_assessment = RiskAssessment(**security_analysis.risk_assessment)

        # Build findings result for aggregation
        from app.services.findings.models import FindingsResult, FindingSummary
        findings_result = FindingsResult(
            evidence_id=job.evidence_id,
            job_id=job_id,
            findings=findings,
            summary=FindingSummary(
                total_findings=len(findings),
                critical_count=security_analysis.critical_findings or 0,
                high_count=security_analysis.high_findings or 0,
                medium_count=security_analysis.medium_findings or 0,
                low_count=security_analysis.low_findings or 0,
                info_count=security_analysis.info_findings or 0,
            ),
            streams_analyzed=security_analysis.total_streams or 0,
            sessions_analyzed=security_analysis.total_sessions or 0,
            certificates_analyzed=security_analysis.total_certificates or 0,
        )

        # Step 1: Intelligence Aggregation
        job.stage = "AGGREGATING_INTELLIGENCE"
        job.progress_percent = "10"
        db.commit()

        aggregator = IntelligenceAggregator()
        aggregated_findings, posture, summary = aggregator.aggregate_findings(
            findings_result, risk_assessment
        )

        logger.info(
            f"Intelligence aggregation complete",
            extra={
                "job_id": job_id,
                "aggregated_findings": len(aggregated_findings),
                "posture_grade": posture.grade.value
            }
        )

        # Step 2: Correlation Engine
        job.stage = "FINDING_CORRELATIONS"
        job.progress_percent = "25"
        db.commit()

        correlation_engine = CorrelationEngine()
        correlations = correlation_engine.find_correlations(
            findings, tls_observations, certificates, sessions
        )

        logger.info(
            f"Correlation analysis complete",
            extra={"job_id": job_id, "correlations_found": len(correlations)}
        )

        # Step 3: Recommendation Engine
        job.stage = "GENERATING_RECOMMENDATIONS"
        job.progress_percent = "40"
        db.commit()

        recommendation_engine = RecommendationEngine()
        recommendations = recommendation_engine.generate_recommendations(
            aggregated_findings, correlations, posture, findings
        )

        logger.info(
            f"Recommendation generation complete",
            extra={"job_id": job_id, "recommendations_generated": len(recommendations)}
        )

        # Step 4: ML Feature Engineering and Anomaly Detection (optional)
        ml_insights = MLInsights(ml_enabled=False, summary="ML not performed")
        anomaly_results = []

        if enable_ml:
            job.stage = "ML_FEATURE_ENGINEERING"
            job.progress_percent = "50"
            db.commit()

            try:
                feature_engineer = FeatureEngineer()
                feature_vectors = feature_engineer.extract_all_features(
                    sessions, tls_observations, certificates, findings
                )

                if feature_vectors:
                    job.stage = "ML_ANOMALY_DETECTION"
                    job.progress_percent = "55"
                    db.commit()

                    anomaly_detector = AnomalyDetector()

                    # Fit on current data (or load pre-trained model)
                    if anomaly_detector.fit(feature_vectors):
                        anomaly_results = anomaly_detector.predict_batch(feature_vectors)
                        ml_insights = anomaly_detector.get_ml_insights(anomaly_results)
                        ml_status = "COMPLETED"

                        logger.info(
                            f"ML analysis complete",
                            extra={
                                "job_id": job_id,
                                "anomalies_detected": ml_insights.anomalies_detected
                            }
                        )
                    else:
                        ml_status = "INSUFFICIENT_DATA"
                        ml_insights = MLInsights(
                            ml_enabled=False,
                            summary="Insufficient data for ML analysis"
                        )
                else:
                    ml_status = "NO_FEATURES"
                    ml_insights = MLInsights(
                        ml_enabled=False,
                        summary="No features extracted for ML analysis"
                    )

            except Exception as ml_error_exc:
                ml_status = "FAILED"
                ml_error = str(ml_error_exc)
                logger.warning(
                    f"ML analysis failed (deterministic results continue): {ml_error_exc}",
                    extra={"job_id": job_id}
                )
                ml_insights = MLInsights(
                    ml_enabled=False,
                    summary=f"ML analysis failed: {ml_error}"
                )

        # Step 5: Persist correlations to database
        job.stage = "PERSISTING_CORRELATIONS"
        job.progress_percent = "60"
        db.commit()

        for corr in correlations:
            db_corr = CorrelationModel(
                intelligence_report_id=intelligence_report.report_id,
                correlation_type=DbCorrelationType(corr.correlation_type.value),
                strength=corr.strength,
                confidence=corr.confidence,
                title=corr.title,
                description=corr.description,
                linked_findings=corr.linked_findings,
                linked_sessions=corr.linked_sessions,
                linked_certificates=corr.linked_certificates,
                linked_streams=corr.linked_streams,
                common_attribute=corr.common_attribute,
                common_value=corr.common_value,
                combined_severity=corr.combined_severity,
                combined_risk_score=corr.combined_risk_score,
            )
            db.add(db_corr)

        # Step 6: Persist recommendations to database
        job.stage = "PERSISTING_RECOMMENDATIONS"
        job.progress_percent = "65"
        db.commit()

        for rec in recommendations:
            db_rec = RecommendationModel(
                intelligence_report_id=intelligence_report.report_id,
                priority=DbRecommendationPriority(rec.priority.value),
                category=DbRecommendationCategory(rec.category.value),
                title=rec.title,
                description=rec.description,
                remediation_steps=rec.remediation_steps,
                estimated_effort=rec.estimated_effort,
                technical_impact=rec.technical_impact,
                business_impact=rec.business_impact,
                affected_findings=rec.affected_findings,
                affected_sessions=rec.affected_sessions,
                affected_certificates=rec.affected_certificates,
                compliance_references=rec.compliance_references,
            )
            db.add(db_rec)

        db.commit()

        # Step 7: Generate Reports (if enabled)
        generated_reports = []
        if generate_reports:
            job.stage = "GENERATING_REPORTS"
            job.progress_percent = "70"
            db.commit()

            # Get evidence info
            evidence = db.query(PcapEvidence).filter(
                PcapEvidence.evidence_id == job.evidence_id
            ).first()

            evidence_info = {
                "original_filename": evidence.original_filename if evidence else "unknown",
                "sha256": evidence.sha256 if evidence else "",
                "file_size_bytes": evidence.file_size_bytes if evidence else 0,
                "upload_timestamp": evidence.upload_timestamp if evidence else None,
                "case_name": evidence.case.case_name if evidence and evidence.case else None,
                "packets_analyzed": security_analysis.total_streams or 0,
            }

            # Build intelligence result for reports
            intelligence_result = IntelligenceResult(
                evidence_id=job.evidence_id,
                job_id=job_id,
                security_analysis_id=security_analysis.analysis_id,
                summary=summary,
                aggregated_findings=aggregated_findings,
                correlations=correlations,
                recommendations=recommendations,
                streams_analyzed=security_analysis.total_streams or 0,
                sessions_analyzed=security_analysis.total_sessions or 0,
                certificates_analyzed=security_analysis.total_certificates or 0,
            )

            # Update summary with final counts
            summary.total_correlations = len(correlations)
            summary.total_recommendations = len(recommendations)
            summary.ml_enabled = ml_insights.ml_enabled
            summary.anomalies_detected = ml_insights.anomalies_detected

            # Get reports directory from settings or use default
            reports_dir = Path(getattr(settings, 'REPORTS_DIR', './reports'))

            report_generator = ReportGenerator(output_dir=reports_dir)

            # Generate JSON report
            try:
                json_report_info = report_generator.generate_report(
                    intelligence_result, evidence_info, ml_insights, ReportFormat.JSON
                )
                generated_reports.append(("JSON", json_report_info))

                # Save to database
                db_json_report = GeneratedReport(
                    intelligence_report_id=intelligence_report.report_id,
                    evidence_id=job.evidence_id,
                    format=DbReportFormat.JSON,
                    status=DbReportStatus.COMPLETED if json_report_info.status.value == "COMPLETED" else DbReportStatus.FAILED,
                    filename=json_report_info.filename,
                    file_size_bytes=json_report_info.file_size_bytes,
                    content_hash=json_report_info.content_hash,
                    generated_at=json_report_info.generated_at,
                    error_message=json_report_info.error_message,
                )
                db.add(db_json_report)
            except Exception as e:
                logger.warning(f"JSON report generation failed: {e}")

            # Generate HTML report
            try:
                html_report_info = report_generator.generate_report(
                    intelligence_result, evidence_info, ml_insights, ReportFormat.HTML
                )
                generated_reports.append(("HTML", html_report_info))

                db_html_report = GeneratedReport(
                    intelligence_report_id=intelligence_report.report_id,
                    evidence_id=job.evidence_id,
                    format=DbReportFormat.HTML,
                    status=DbReportStatus.COMPLETED if html_report_info.status.value == "COMPLETED" else DbReportStatus.FAILED,
                    filename=html_report_info.filename,
                    file_size_bytes=html_report_info.file_size_bytes,
                    content_hash=html_report_info.content_hash,
                    generated_at=html_report_info.generated_at,
                    error_message=html_report_info.error_message,
                )
                db.add(db_html_report)
            except Exception as e:
                logger.warning(f"HTML report generation failed: {e}")

            # Generate PDF report (optional, may fail if weasyprint not available)
            try:
                pdf_report_info = report_generator.generate_report(
                    intelligence_result, evidence_info, ml_insights, ReportFormat.PDF
                )
                generated_reports.append(("PDF", pdf_report_info))

                db_pdf_report = GeneratedReport(
                    intelligence_report_id=intelligence_report.report_id,
                    evidence_id=job.evidence_id,
                    format=DbReportFormat.PDF,
                    status=DbReportStatus.COMPLETED if pdf_report_info.status.value == "COMPLETED" else DbReportStatus.FAILED,
                    filename=pdf_report_info.filename,
                    file_size_bytes=pdf_report_info.file_size_bytes,
                    content_hash=pdf_report_info.content_hash,
                    generated_at=pdf_report_info.generated_at,
                    error_message=pdf_report_info.error_message,
                )
                db.add(db_pdf_report)
            except Exception as e:
                logger.warning(f"PDF report generation failed (continuing): {e}")

            db.commit()

        # Step 8: Evidence Integrity
        job.stage = "GENERATING_INTEGRITY"
        job.progress_percent = "85"
        db.commit()

        integrity_service = IntegrityService(
            blockchain_enabled=getattr(settings, 'BLOCKCHAIN_ENABLED', False)
        )

        # Get evidence path
        evidence = db.query(PcapEvidence).filter(
            PcapEvidence.evidence_id == job.evidence_id
        ).first()

        integrity_record = None
        if evidence and evidence.storage_location:
            try:
                evidence_path = Path(evidence.storage_location)
                if evidence_path.exists():
                    integrity_record = integrity_service.create_complete_integrity_record(
                        evidence_path=evidence_path,
                        evidence_id=job.evidence_id,
                        job_id=job_id,
                        analysis_data={
                            "findings_count": len(findings),
                            "correlations_count": len(correlations),
                            "recommendations_count": len(recommendations),
                            "posture_score": posture.overall_score,
                            "posture_grade": posture.grade.value,
                        },
                        intelligence_report_id=intelligence_report.report_id,
                    )

                    # Save to database
                    db_integrity = EvidenceIntegrity(
                        evidence_id=job.evidence_id,
                        intelligence_report_id=intelligence_report.report_id,
                        status=DbIntegrityStatus(integrity_record.status),
                        evidence_sha256=integrity_record.evidence_sha256,
                        evidence_sha512=integrity_record.evidence_sha512,
                        analysis_hash=integrity_record.analysis_hash,
                        merkle_root=integrity_record.merkle_root,
                        blockchain_enabled=integrity_record.blockchain_enabled,
                        blockchain_network=integrity_record.blockchain_network,
                        transaction_hash=integrity_record.transaction_hash,
                        block_number=integrity_record.block_number,
                        anchor_timestamp=integrity_record.anchor_timestamp,
                        verified_at=integrity_record.verified_at,
                    )
                    db.add(db_integrity)
            except Exception as e:
                logger.warning(f"Integrity generation failed (continuing): {e}")

        # Step 9: Finalize Intelligence Report
        job.stage = "FINALIZING"
        job.progress_percent = "95"
        db.commit()

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Update intelligence report with results
        intelligence_report.status = IntelligenceStatus.COMPLETED
        intelligence_report.completed_at = end_time
        intelligence_report.duration_seconds = duration

        # Counts
        intelligence_report.total_correlations = len(correlations)
        intelligence_report.total_recommendations = len(recommendations)
        intelligence_report.ml_predictions_count = len(anomaly_results)
        intelligence_report.anomalies_detected = ml_insights.anomalies_detected

        # Posture
        intelligence_report.security_posture_score = posture.overall_score
        intelligence_report.security_posture_grade = posture.grade.value
        intelligence_report.tls_security_score = posture.tls_security.score
        intelligence_report.certificate_security_score = posture.certificate_security.score
        intelligence_report.protocol_security_score = posture.protocol_security.score
        intelligence_report.configuration_security_score = posture.configuration_security.score

        # ML
        intelligence_report.ml_enabled = ml_insights.ml_enabled
        intelligence_report.ml_model_version = ml_insights.model_version
        intelligence_report.ml_confidence_score = ml_insights.overall_confidence

        # Summary
        intelligence_report.executive_summary = summary.executive_summary
        intelligence_report.aggregated_findings = [af.model_dump() for af in aggregated_findings]
        intelligence_report.correlation_summary = {
            "total": len(correlations),
            "by_type": {}
        }
        intelligence_report.recommendation_summary = {
            "total": len(recommendations),
            "by_priority": {}
        }
        if ml_insights.ml_enabled:
            intelligence_report.ml_insights = ml_insights.model_dump()
            intelligence_report.anomaly_summary = {
                "total_anomalies": ml_insights.anomalies_detected,
                "confidence": ml_insights.overall_confidence
            }

        # Update job
        job.status = JobStatus.COMPLETED
        job.completed_at = end_time
        job.stage = "COMPLETED"
        job.progress_percent = "100"
        job.error_code = None
        job.error_message = None

        db.commit()

        logger.info(
            f"Intelligence analysis completed successfully for job {job_id}",
            extra={
                "job_id": job_id,
                "evidence_id": job.evidence_id,
                "duration_seconds": duration,
                "correlations": len(correlations),
                "recommendations": len(recommendations),
                "posture_grade": posture.grade.value,
                "ml_status": ml_status,
            }
        )

        return {
            "status": "COMPLETED",
            "job_id": job_id,
            "intelligence_report_id": intelligence_report.report_id,
            "total_correlations": len(correlations),
            "total_recommendations": len(recommendations),
            "posture_score": posture.overall_score,
            "posture_grade": posture.grade.value,
            "ml_status": ml_status,
            "anomalies_detected": ml_insights.anomalies_detected if ml_insights.ml_enabled else 0,
            "reports_generated": len(generated_reports),
            "duration_seconds": duration
        }

    except (OperationalError, InterfaceError) as e:
        logger.warning(f"Database error in intelligence analysis task: {e}, will retry")
        db.rollback()
        raise  # Let Celery handle retry

    except Exception as e:
        logger.error(f"Unexpected error in intelligence analysis task: {e}", exc_info=True)
        db.rollback()

        # Try to mark as failed
        if intelligence_report:
            try:
                intelligence_report.status = IntelligenceStatus.FAILED
                intelligence_report.error_code = "INTELLIGENCE_ANALYSIS_FAILED"
                intelligence_report.error_message = str(e)[:500]
                intelligence_report.completed_at = datetime.now(timezone.utc)
                db.commit()
            except Exception:
                db.rollback()

        if job:
            try:
                _fail_phase4_job(db, job, "INTELLIGENCE_ANALYSIS_FAILED", str(e)[:500])
            except Exception:
                pass

        return {
            "status": "FAILED",
            "error_code": "INTELLIGENCE_ANALYSIS_FAILED",
            "error_message": str(e)
        }

    finally:
        db.close()


def _fail_phase4_job(db, job: AnalysisJob, error_code: str, error_message: str):
    """Mark a Phase 4 job as failed with error details."""
    job.status = JobStatus.FAILED
    job.error_code = error_code
    job.error_message = error_message[:500] if error_message else None
    job.completed_at = datetime.now(timezone.utc)
    db.commit()
    logger.error(
        f"Phase 4 job failed: {job.job_id}",
        extra={"job_id": job.job_id, "error_code": error_code}
    )
