"""Test complete demo pipeline: Phase 2→3→4 + Case status updates.

This test verifies the ENTIRE demo mode lifecycle from upload to completion,
including Phase 4 intelligence analysis and parent case status updates.
"""
import pytest
from sqlalchemy.orm import Session

from app.models.case import Case, CaseStatus
from app.models.evidence import PcapEvidence, EvidenceStatus
from app.models.analysis_job import AnalysisJob, JobStatus, JobType, generate_job_id
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.models.intelligence import IntelligenceReport, IntelligenceStatus
from app.services.analysis_executor import execute_phase2_analysis, execute_phase3_analysis, execute_phase4_analysis
from app.services.case_service import case_service


class TestDemoCompletePipeline:
    """Test suite for complete demo pipeline execution."""

    def test_phase4_completes_and_sets_status(self, test_db: Session):
        """
        Test that Phase 4 execution properly sets intelligence report status.

        This is the critical bug fix: Phase 4 must set status=COMPLETED
        so the frontend intelligence endpoint doesn't return 404.
        """
        # Create case
        case = Case(
            case_name="Test Phase 4 Status",
            description="Test Phase 4 status setting",
            status=CaseStatus.PROCESSING
        )
        test_db.add(case)
        test_db.flush()

        # Create evidence
        evidence = PcapEvidence(
            case_id=case.case_id,
            original_filename="test.pcap",
            stored_filename="test.pcap",
            file_format="pcap",
            file_size_bytes=1000,
            sha256="test_hash",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/test.pcap"
        )
        test_db.add(evidence)
        test_db.flush()

        # Create mock Phase 2 packet analysis
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.COMPLETED
        )
        test_db.add(phase2_job)
        test_db.commit()

        packet_analysis = PacketAnalysis(
            job_id=phase2_job.job_id,
            evidence_id=evidence.evidence_id,
            total_packets=10,
            email_packets=0,
            smtp_packets=0,
            imap_packets=0,
            pop3_packets=0,
            tls_packets=0,
            other_packets=10,
            protocols_detected=[],
            protocol_detections=[],
            session_candidates=[],
            message="No email traffic detected",
            duration_seconds=1.0
        )
        test_db.add(packet_analysis)
        test_db.commit()

        # Create Phase 3 security analysis
        phase3_job_id = generate_job_id()
        phase3_job = AnalysisJob(
            job_id=phase3_job_id,
            evidence_id=evidence.evidence_id,
            job_type=JobType.SECURITY_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase3_job)
        test_db.commit()

        phase3_result = execute_phase3_analysis(
            test_db,
            phase3_job_id,
            packet_analysis.analysis_id
        )
        test_db.refresh(phase3_job)

        assert phase3_job.status == JobStatus.COMPLETED
        security_analysis_id = phase3_result["security_analysis_id"]

        # Execute Phase 4
        phase4_job_id = generate_job_id()
        phase4_job = AnalysisJob(
            job_id=phase4_job_id,
            evidence_id=evidence.evidence_id,
            job_type=JobType.INTELLIGENCE,
            status=JobStatus.QUEUED
        )
        test_db.add(phase4_job)
        test_db.commit()

        phase4_result = execute_phase4_analysis(
            test_db,
            phase4_job_id,
            security_analysis_id,
            enable_ml=False
        )

        # Verify Phase 4 job completed
        test_db.refresh(phase4_job)
        assert phase4_job.status == JobStatus.COMPLETED
        assert phase4_result["status"] == "COMPLETED"
        assert "intelligence_report_id" in phase4_result

        # CRITICAL: Verify intelligence report status is COMPLETED
        intelligence_report = test_db.query(IntelligenceReport).filter(
            IntelligenceReport.report_id == phase4_result["intelligence_report_id"]
        ).first()

        assert intelligence_report is not None
        assert intelligence_report.status == IntelligenceStatus.COMPLETED, \
            "Intelligence report status must be COMPLETED for frontend to retrieve it"

        # Verify all fields are populated
        assert intelligence_report.security_posture_score is not None
        assert intelligence_report.security_posture_grade is not None
        assert intelligence_report.duration_seconds is not None
        assert intelligence_report.completed_at is not None
        assert intelligence_report.aggregated_findings is not None
        assert intelligence_report.correlation_summary is not None
        assert intelligence_report.recommendation_summary is not None

        # Verify counts
        assert isinstance(intelligence_report.total_correlations, int)
        assert isinstance(intelligence_report.total_recommendations, int)

        print(f"\n✅ Phase 4 completed with status: {intelligence_report.status.value}")
        print(f"   Posture score: {intelligence_report.security_posture_score}")
        print(f"   Posture grade: {intelligence_report.security_posture_grade}")
        print(f"   Duration: {intelligence_report.duration_seconds}s")

    def test_case_status_updates_after_single_evidence_completion(self, test_db: Session):
        """
        Test that case status updates to COMPLETED after single evidence analysis finishes.

        This is the second critical bug fix: Case must transition from
        PROCESSING → COMPLETED when all evidence analyses are done.
        """
        # Create case
        case = Case(
            case_name="Test Case Status",
            description="Test case status updates",
            status=CaseStatus.PROCESSING
        )
        test_db.add(case)
        test_db.flush()

        # Create evidence
        evidence = PcapEvidence(
            case_id=case.case_id,
            original_filename="test.pcap",
            stored_filename="test.pcap",
            file_format="pcap",
            file_size_bytes=1000,
            sha256="test_hash",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/test.pcap"
        )
        test_db.add(evidence)
        test_db.commit()

        # Create completed Phase 2 job
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.COMPLETED
        )
        test_db.add(phase2_job)
        test_db.commit()

        # Update case status
        new_status = case_service.update_case_status(test_db, case.case_id)

        # Verify case is now COMPLETED
        test_db.refresh(case)
        assert case.status == CaseStatus.COMPLETED
        assert new_status == CaseStatus.COMPLETED

        print(f"\n✅ Case status updated to: {case.status.value}")

    def test_case_status_remains_processing_with_running_job(self, test_db: Session):
        """
        Test that case remains PROCESSING when jobs are still running.
        """
        # Create case
        case = Case(
            case_name="Test Processing Status",
            description="Test case with running job",
            status=CaseStatus.PROCESSING
        )
        test_db.add(case)
        test_db.flush()

        # Create evidence
        evidence = PcapEvidence(
            case_id=case.case_id,
            original_filename="test.pcap",
            stored_filename="test.pcap",
            file_format="pcap",
            file_size_bytes=1000,
            sha256="test_hash",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/test.pcap"
        )
        test_db.add(evidence)
        test_db.commit()

        # Create RUNNING Phase 2 job
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.RUNNING
        )
        test_db.add(phase2_job)
        test_db.commit()

        # Update case status
        new_status = case_service.update_case_status(test_db, case.case_id)

        # Verify case remains PROCESSING
        test_db.refresh(case)
        assert case.status == CaseStatus.PROCESSING
        assert new_status == CaseStatus.PROCESSING

        print(f"\n✅ Case status correctly remains: {case.status.value}")

    def test_case_status_multiple_evidence_files(self, test_db: Session):
        """
        Test case status aggregation with multiple evidence files.

        Rules:
        - If any job is RUNNING → Case = PROCESSING
        - If all jobs are COMPLETED → Case = COMPLETED
        """
        # Create case
        case = Case(
            case_name="Test Multiple Evidence",
            description="Test case with multiple evidence files",
            status=CaseStatus.PROCESSING
        )
        test_db.add(case)
        test_db.flush()

        # Create first evidence (completed)
        evidence1 = PcapEvidence(
            case_id=case.case_id,
            original_filename="test1.pcap",
            stored_filename="test1.pcap",
            file_format="pcap",
            file_size_bytes=1000,
            sha256="test_hash1",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/test1.pcap"
        )
        test_db.add(evidence1)
        test_db.flush()

        # Create second evidence (running)
        evidence2 = PcapEvidence(
            case_id=case.case_id,
            original_filename="test2.pcap",
            stored_filename="test2.pcap",
            file_format="pcap",
            file_size_bytes=1000,
            sha256="test_hash2",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/test2.pcap"
        )
        test_db.add(evidence2)
        test_db.commit()

        # First evidence: COMPLETED
        job1 = AnalysisJob(
            evidence_id=evidence1.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.COMPLETED
        )
        test_db.add(job1)

        # Second evidence: RUNNING
        job2 = AnalysisJob(
            evidence_id=evidence2.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.RUNNING
        )
        test_db.add(job2)
        test_db.commit()

        # Update case status - should remain PROCESSING
        status1 = case_service.update_case_status(test_db, case.case_id)
        test_db.refresh(case)
        assert case.status == CaseStatus.PROCESSING
        print(f"\n✅ With 1 completed + 1 running: {case.status.value}")

        # Now complete second job
        job2.status = JobStatus.COMPLETED
        test_db.commit()

        # Update case status - should become COMPLETED
        status2 = case_service.update_case_status(test_db, case.case_id)
        test_db.refresh(case)
        assert case.status == CaseStatus.COMPLETED
        print(f"✅ With both completed: {case.status.value}")

    def test_case_status_with_failed_job(self, test_db: Session):
        """
        Test case status when a job fails.
        """
        # Create case
        case = Case(
            case_name="Test Failed Job",
            description="Test case with failed job",
            status=CaseStatus.PROCESSING
        )
        test_db.add(case)
        test_db.flush()

        # Create evidence
        evidence = PcapEvidence(
            case_id=case.case_id,
            original_filename="test.pcap",
            stored_filename="test.pcap",
            file_format="pcap",
            file_size_bytes=1000,
            sha256="test_hash",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/test.pcap"
        )
        test_db.add(evidence)
        test_db.commit()

        # Create FAILED Phase 2 job
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.FAILED,
            error_code="TEST_FAILURE",
            error_message="Test failure"
        )
        test_db.add(phase2_job)
        test_db.commit()

        # Update case status
        new_status = case_service.update_case_status(test_db, case.case_id)

        # Verify case is FAILED
        test_db.refresh(case)
        assert case.status == CaseStatus.FAILED
        assert new_status == CaseStatus.FAILED

        print(f"\n✅ Case status correctly set to: {case.status.value}")
