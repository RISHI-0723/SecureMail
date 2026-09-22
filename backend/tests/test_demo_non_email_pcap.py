"""Test demo mode with non-email PCAP files (ping, DNS, etc.)

This test verifies that the analysis pipeline handles PCAPs gracefully
when they contain NO email traffic (SMTP/IMAP/POP3).

Per CLAUDE.md: "Do not call 'no email traffic detected' a secure email posture."
The system should return UNKNOWN risk when no email evidence exists.
"""
import os
import pytest
from pathlib import Path
from unittest.mock import patch

from app.services.analysis_executor import execute_phase2_analysis, execute_phase3_analysis
from app.models.analysis_job import AnalysisJob, JobStatus, JobType
from app.models.evidence import PcapEvidence, EvidenceStatus
from app.models.packet_analysis import PacketAnalysis
from app.models.security_analysis import SecurityAnalysis, SecurityAnalysisStatus
from app.models.case import Case, CaseStatus


@pytest.fixture
def ping_pcap_path():
    """Path to the ping PCAP test file."""
    # Try to find ping-request-and-reply.pcapng in the repository root
    repo_root = Path(__file__).parent.parent.parent
    pcap_path = repo_root / "ping-request-and-reply.pcapng"

    if not pcap_path.exists():
        pytest.skip(f"Test PCAP not found: {pcap_path}")

    return str(pcap_path)


@pytest.fixture
def case_with_ping_evidence(test_db, ping_pcap_path):
    """Create a test case with ping PCAP evidence."""
    # Create case
    case = Case(
        case_name="Test Non-Email PCAP",
        description="Testing with ping/ICMP traffic only",
        status=CaseStatus.OPEN
    )
    test_db.add(case)
    test_db.flush()

    # Create evidence
    evidence = PcapEvidence(
        case_id=case.case_id,
        original_filename="ping-request-and-reply.pcapng",
        stored_filename="test_ping.pcapng",
        file_format="pcapng",
        file_size_bytes=os.path.getsize(ping_pcap_path),
        sha256="test_sha256_ping",
        status=EvidenceStatus.VALIDATED,
        storage_location=ping_pcap_path  # Use actual path for test
    )
    test_db.add(evidence)
    test_db.commit()
    test_db.refresh(case)
    test_db.refresh(evidence)

    return case, evidence


class TestDemoNonEmailPCAP:
    """Test suite for non-email PCAP handling in demo mode."""

    def test_phase2_ping_pcap_completes_successfully(
        self,
        test_db,
        case_with_ping_evidence
    ):
        """
        Test Phase 2 analysis with ping PCAP.

        Expected behavior:
        - Analysis completes successfully
        - No email traffic detected
        - Job status is COMPLETED (not FAILED)
        - PacketAnalysis record created with email_packets=0
        """
        case, evidence = case_with_ping_evidence

        # Create analysis job
        job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(job)
        test_db.commit()

        # Execute Phase 2
        result = execute_phase2_analysis(test_db, job.job_id)

        # Refresh job
        test_db.refresh(job)

        # Assertions
        assert job.status == JobStatus.COMPLETED, \
            f"Job should complete successfully, got: {job.status}"

        assert result is not None
        assert "packet_analysis_id" in result

        # Get packet analysis
        packet_analysis = test_db.query(PacketAnalysis).filter(
            PacketAnalysis.analysis_id == result["packet_analysis_id"]
        ).first()

        assert packet_analysis is not None
        assert packet_analysis.total_packets > 0, \
            "Should detect packets in ping PCAP"
        assert packet_analysis.email_packets == 0, \
            "Should find NO email packets"
        assert len(packet_analysis.protocols_detected) == 0, \
            "Should detect NO email protocols"
        assert "No supported email protocols" in packet_analysis.message or \
               "No SMTP, IMAP, or POP3" in packet_analysis.message, \
            f"Message should mention no email traffic: {packet_analysis.message}"

    def test_phase3_ping_pcap_uses_empty_risk_assessment(
        self,
        test_db,
        case_with_ping_evidence
    ):
        """
        Test Phase 3 analysis with ping PCAP.

        Expected behavior:
        - Analysis completes successfully
        - No email sessions created
        - Risk assessment uses assess_empty() → UNKNOWN status
        - SecurityAnalysis record created with total_sessions=0
        - Risk level is UNKNOWN (not MINIMAL)
        """
        case, evidence = case_with_ping_evidence

        # Create Phase 2 job
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase2_job)
        test_db.commit()

        # Execute Phase 2
        phase2_result = execute_phase2_analysis(test_db, phase2_job.job_id)
        packet_analysis_id = phase2_result["packet_analysis_id"]

        # Create Phase 3 job
        phase3_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.SECURITY_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase3_job)
        test_db.commit()

        # Execute Phase 3
        phase3_result = execute_phase3_analysis(
            test_db,
            phase3_job.job_id,
            packet_analysis_id
        )

        # Refresh job
        test_db.refresh(phase3_job)

        # Assertions
        assert phase3_job.status == JobStatus.COMPLETED, \
            f"Phase 3 should complete successfully, got: {phase3_job.status}"

        assert phase3_result is not None
        assert "security_analysis_id" in phase3_result

        # Get security analysis
        security_analysis = test_db.query(SecurityAnalysis).filter(
            SecurityAnalysis.analysis_id == phase3_result["security_analysis_id"]
        ).first()

        assert security_analysis is not None
        assert security_analysis.status == SecurityAnalysisStatus.COMPLETED

        # Verify no email sessions
        assert security_analysis.total_sessions == 0, \
            "Should have NO email sessions"
        assert security_analysis.total_findings >= 0, \
            "Findings count should be valid"

        # Verify risk assessment reflects lack of email traffic
        risk_assessment = security_analysis.risk_assessment
        assert risk_assessment is not None

        # CRITICAL: Risk should be UNKNOWN, not MINIMAL for non-email traffic
        # The risk is nested inside "posture"
        posture = risk_assessment.get("posture", {})
        assert posture.get("overall_risk") == "UNKNOWN", \
            f"Risk level should be UNKNOWN for non-email PCAP, got: {posture.get('overall_risk')}"

        # Also check the top-level field on SecurityAnalysis
        assert security_analysis.overall_risk_level == "UNKNOWN", \
            f"SecurityAnalysis.overall_risk_level should be UNKNOWN, got: {security_analysis.overall_risk_level}"

        assert posture.get("coverage") in ["UNKNOWN", "NONE"], \
            f"Coverage should indicate insufficient data, got: {posture.get('coverage')}"

    def test_phase3_empty_pcap_uses_empty_risk_assessment(
        self,
        test_db
    ):
        """
        Test Phase 3 with completely empty PCAP (0 packets).

        Expected behavior:
        - Phase 2 completes with 0 packets
        - Phase 3 completes successfully
        - Risk is UNKNOWN
        """
        # Create case
        case = Case(
            case_name="Empty PCAP Test",
            description="Testing empty capture",
            status=CaseStatus.OPEN
        )
        test_db.add(case)
        test_db.flush()

        # Create mock empty evidence
        evidence = PcapEvidence(
            case_id=case.case_id,
            original_filename="empty.pcap",
            stored_filename="empty.pcap",
            file_format="pcap",
            file_size_bytes=24,  # Just header
            sha256="empty_hash",
            status=EvidenceStatus.VALIDATED,
            storage_location="/tmp/empty.pcap"
        )
        test_db.add(evidence)
        test_db.commit()

        # Create Phase 2 job
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase2_job)
        test_db.commit()

        # Mock Phase 2 result (since we don't have actual empty file)
        packet_analysis = PacketAnalysis(
            job_id=phase2_job.job_id,
            evidence_id=evidence.evidence_id,
            total_packets=0,
            email_packets=0,
            smtp_packets=0,
            imap_packets=0,
            pop3_packets=0,
            tls_packets=0,
            other_packets=0,
            protocols_detected=[],
            protocol_detections=[],
            session_candidates=[],
            message="No packets were detected in this capture.",
            duration_seconds=0.1
        )
        test_db.add(packet_analysis)
        test_db.commit()

        phase2_job.status = JobStatus.COMPLETED
        test_db.commit()

        # Create Phase 3 job
        phase3_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.SECURITY_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase3_job)
        test_db.commit()

        # Execute Phase 3
        phase3_result = execute_phase3_analysis(
            test_db,
            phase3_job.job_id,
            packet_analysis.analysis_id
        )

        # Verify Phase 3 completed
        test_db.refresh(phase3_job)
        assert phase3_job.status == JobStatus.COMPLETED

        # Get security analysis
        security_analysis = test_db.query(SecurityAnalysis).filter(
            SecurityAnalysis.analysis_id == phase3_result["security_analysis_id"]
        ).first()

        assert security_analysis is not None
        assert security_analysis.total_sessions == 0
        assert security_analysis.total_streams >= 0

        # Verify risk is UNKNOWN for empty capture
        risk_assessment = security_analysis.risk_assessment
        posture = risk_assessment.get("posture", {})
        assert posture.get("overall_risk") == "UNKNOWN", \
            f"Empty PCAP should have UNKNOWN risk, got: {posture.get('overall_risk')}"
        assert security_analysis.overall_risk_level == "UNKNOWN", \
            f"SecurityAnalysis.overall_risk_level should be UNKNOWN, got: {security_analysis.overall_risk_level}"

    @pytest.mark.skipif(
        "TSHARK_BINARY" not in os.environ,
        reason="TShark binary not available in test environment"
    )
    def test_full_pipeline_ping_pcap(
        self,
        test_db,
        case_with_ping_evidence
    ):
        """
        End-to-end test of demo pipeline with ping PCAP.

        This test runs the FULL Phase 2 → Phase 3 pipeline.
        Skipped if TShark is not available.

        Expected outcome:
        - Phase 2: COMPLETED
        - Phase 3: COMPLETED
        - Risk: UNKNOWN
        - No fabricated email findings
        """
        case, evidence = case_with_ping_evidence

        # Phase 2
        phase2_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.FULL_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase2_job)
        test_db.commit()

        phase2_result = execute_phase2_analysis(test_db, phase2_job.job_id)
        test_db.refresh(phase2_job)

        assert phase2_job.status == JobStatus.COMPLETED
        assert phase2_result["packet_analysis_id"] is not None

        # Phase 3
        phase3_job = AnalysisJob(
            evidence_id=evidence.evidence_id,
            job_type=JobType.SECURITY_ANALYSIS,
            status=JobStatus.QUEUED
        )
        test_db.add(phase3_job)
        test_db.commit()

        phase3_result = execute_phase3_analysis(
            test_db,
            phase3_job.job_id,
            phase2_result["packet_analysis_id"]
        )
        test_db.refresh(phase3_job)

        assert phase3_job.status == JobStatus.COMPLETED

        # Final verification
        security_analysis = test_db.query(SecurityAnalysis).filter(
            SecurityAnalysis.analysis_id == phase3_result["security_analysis_id"]
        ).first()

        # Summary assertions
        assert security_analysis.total_packets > 0
        assert security_analysis.total_sessions == 0
        assert security_analysis.total_findings >= 0

        # Check risk assessment structure
        posture = security_analysis.risk_assessment.get("posture", {})
        assert posture.get("overall_risk") == "UNKNOWN", \
            f"Expected UNKNOWN risk for ping PCAP, got: {posture.get('overall_risk')}"
        assert security_analysis.overall_risk_level == "UNKNOWN"

        print(f"\n✅ Full pipeline test PASSED for ping PCAP")
        print(f"   Packets: {security_analysis.total_packets}")
        print(f"   Email sessions: {security_analysis.total_sessions}")
        print(f"   Findings: {security_analysis.total_findings}")
        print(f"   Risk: {security_analysis.overall_risk_level}")
