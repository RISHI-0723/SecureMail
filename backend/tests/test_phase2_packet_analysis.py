"""Phase 2: Packet and Email Protocol Analysis Tests.

These tests verify Phase 2 functionality:
- TShark service abstraction
- Packet parser
- Protocol detector
- Analysis task
- API endpoints

Tests also verify Phase 2 boundaries:
- Does NOT implement TCP stream reconstruction (Phase 3)
- Does NOT analyze STARTTLS success/failure (Phase 4)
- Does NOT perform TLS security analysis (Phase 5/6)
"""
import io
import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

from app.services.packet.models import (
    TSharkStatus,
    TSharkResult,
    PacketRecord,
    ProtocolDetection,
    ProtocolSessionCandidate,
    DetectionConfidence,
)
from app.services.packet.tshark_service import TSharkService
from app.services.packet.packet_parser import PacketParser
from app.services.packet.protocol_detector import ProtocolDetector
from app.models.analysis_job import JobStatus


# =============================================================================
# TSHARK SERVICE TESTS
# =============================================================================

class TestTSharkService:
    """Tests for TShark service abstraction."""

    def test_validate_binary_not_found(self):
        """Test TShark binary validation fails when binary doesn't exist."""
        service = TSharkService(binary_path="/nonexistent/tshark")
        is_valid, error = service.validate_binary()

        assert is_valid is False
        assert "not found" in error.lower() or "not exist" in error.lower()

    def test_validate_binary_success_with_mock(self):
        """Test TShark binary validation succeeds with mock."""
        with patch('shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/tshark"
            with patch('os.path.exists') as mock_exists:
                mock_exists.return_value = True
                with patch('pathlib.Path.is_file') as mock_is_file:
                    mock_is_file.return_value = True
                    with patch('os.access') as mock_access:
                        mock_access.return_value = True

                        service = TSharkService(binary_path="tshark")
                        is_valid, result = service.validate_binary()

                        assert is_valid is True

    def test_extract_packets_tshark_not_found(self):
        """Test extract_packets returns NOT_FOUND when TShark missing."""
        service = TSharkService(binary_path="/nonexistent/tshark")
        result = service.extract_packets("/some/evidence.pcap")

        assert result.status == TSharkStatus.NOT_FOUND
        assert result.exit_code is None
        assert result.timed_out is False

    def test_extract_packets_evidence_not_found(self):
        """Test extract_packets returns FAILED when evidence missing."""
        with patch.object(TSharkService, 'validate_binary') as mock_validate:
            mock_validate.return_value = (True, "/usr/bin/tshark")

            service = TSharkService()
            service._validated_binary = "/usr/bin/tshark"

            result = service.extract_packets("/nonexistent/evidence.pcap")

            assert result.status == TSharkStatus.FAILED
            assert "not found" in result.stderr.lower() or "not exist" in result.stderr.lower()

    def test_tshark_not_found_fails_fast(self):
        """Test that TShark not found fails immediately without waiting for timeout."""
        import time

        service = TSharkService(
            binary_path="/definitely/not/a/real/path/tshark",
            timeout_seconds=300
        )

        start = time.time()
        result = service.extract_packets("/some/evidence.pcap")
        duration = time.time() - start

        # Should fail fast, not wait 300 seconds
        assert duration < 5  # Should complete in under 5 seconds
        assert result.status == TSharkStatus.NOT_FOUND


# =============================================================================
# PACKET PARSER TESTS
# =============================================================================

class TestPacketParser:
    """Tests for TShark output parsing."""

    def test_parse_empty_result(self):
        """Test parsing empty TShark output."""
        parser = PacketParser()
        result = TSharkResult(
            status=TSharkStatus.SUCCESS,
            stdout="",
            stderr=""
        )

        packets = list(parser.parse(result))
        assert packets == []

    def test_parse_unsuccessful_result(self):
        """Test parsing unsuccessful TShark result."""
        parser = PacketParser()
        result = TSharkResult(
            status=TSharkStatus.FAILED,
            stdout="some data",
            stderr="error"
        )

        packets = list(parser.parse(result))
        assert packets == []

    def test_parse_header_only(self):
        """Test parsing TShark output with only header."""
        parser = PacketParser()
        result = TSharkResult(
            status=TSharkStatus.SUCCESS,
            stdout="frame.number\tframe.time_epoch\tip.src\tip.dst",
            stderr=""
        )

        packets = list(parser.parse(result))
        assert packets == []

    def test_parse_valid_packets(self):
        """Test parsing valid TShark output."""
        parser = PacketParser()
        output = (
            "frame.number\tframe.time_epoch\tip.src\tip.dst\tipv6.src\tipv6.dst\t"
            "tcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tip.proto\t"
            "_ws.col.Protocol\tframe.len\ttcp.stream\ttcp.flags\tip.version\tframe.protocols\n"
            "1\t1234567890.123\t192.168.1.1\t192.168.1.2\t\t\t12345\t25\t\t\t6\tSMTP\t100\t0\t0x018\t4\teth:ip:tcp:smtp\n"
            "2\t1234567890.456\t192.168.1.2\t192.168.1.1\t\t\t25\t12345\t\t\t6\tSMTP\t150\t0\t0x010\t4\teth:ip:tcp:smtp"
        )
        result = TSharkResult(
            status=TSharkStatus.SUCCESS,
            stdout=output,
            stderr=""
        )

        packets = list(parser.parse(result))

        assert len(packets) == 2
        assert packets[0].packet_number == 1
        assert packets[0].src_ip == "192.168.1.1"
        assert packets[0].dst_ip == "192.168.1.2"
        assert packets[0].src_port == 12345
        assert packets[0].dst_port == 25
        assert packets[0].detected_protocol == "SMTP"
        assert packets[0].tcp_stream == 0

    def test_parse_missing_fields(self):
        """Test parsing with missing optional fields."""
        parser = PacketParser()
        output = (
            "frame.number\tframe.time_epoch\tip.src\tip.dst\tipv6.src\tipv6.dst\t"
            "tcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tip.proto\t"
            "_ws.col.Protocol\tframe.len\ttcp.stream\ttcp.flags\tip.version\tframe.protocols\n"
            "1\t\t\t\t\t\t\t\t\t\t\tTCP\t100\t\t\t\t"
        )
        result = TSharkResult(
            status=TSharkStatus.SUCCESS,
            stdout=output,
            stderr=""
        )

        packets = list(parser.parse(result))

        assert len(packets) == 1
        assert packets[0].packet_number == 1
        assert packets[0].src_ip is None
        assert packets[0].dst_ip is None
        assert packets[0].detected_protocol == "TCP"

    def test_count_packets(self):
        """Test packet counting."""
        parser = PacketParser()
        output = (
            "frame.number\n"
            "1\n"
            "2\n"
            "3\n"
        )
        result = TSharkResult(
            status=TSharkStatus.SUCCESS,
            stdout=output,
            stderr=""
        )

        count = parser.count_packets(result)
        assert count == 3


# =============================================================================
# PROTOCOL DETECTOR TESTS
# =============================================================================

class TestProtocolDetector:
    """Tests for email protocol detection."""

    def test_detect_smtp(self):
        """Test SMTP detection."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(
                packet_number=1,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=12345,
                dst_port=25,
                detected_protocol="SMTP",
                tcp_stream=0
            ),
            PacketRecord(
                packet_number=2,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=25,
                dst_port=12345,
                detected_protocol="SMTP",
                tcp_stream=0
            ),
        ]

        detector.process_packets(iter(packets))

        assert "SMTP" in detector.get_detected_protocols()
        assert detector.get_protocol_counts()["SMTP"] == 2

    def test_detect_imap(self):
        """Test IMAP detection."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(
                packet_number=1,
                detected_protocol="IMAP",
                tcp_stream=0
            ),
        ]

        detector.process_packets(iter(packets))

        assert "IMAP" in detector.get_detected_protocols()
        assert detector.get_protocol_counts()["IMAP"] == 1

    def test_detect_pop3(self):
        """Test POP3 detection."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(
                packet_number=1,
                detected_protocol="POP",
                tcp_stream=0
            ),
        ]

        detector.process_packets(iter(packets))

        assert "POP3" in detector.get_detected_protocols()
        assert detector.get_protocol_counts()["POP3"] == 1

    def test_detect_tls(self):
        """Test TLS presence detection."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(
                packet_number=1,
                detected_protocol="TLSv1.2",
                tcp_stream=0
            ),
        ]

        detector.process_packets(iter(packets))

        assert detector.has_tls() is True
        assert detector.get_protocol_counts()["TLS"] == 1

    def test_detect_multiple_protocols(self):
        """Test detection of multiple protocols."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(packet_number=1, detected_protocol="SMTP", tcp_stream=0),
            PacketRecord(packet_number=2, detected_protocol="SMTP", tcp_stream=0),
            PacketRecord(packet_number=3, detected_protocol="IMAP", tcp_stream=1),
            PacketRecord(packet_number=4, detected_protocol="POP3", tcp_stream=2),
            PacketRecord(packet_number=5, detected_protocol="TLS", tcp_stream=3),
        ]

        detector.process_packets(iter(packets))

        protocols = detector.get_detected_protocols()
        assert "SMTP" in protocols
        assert "IMAP" in protocols
        assert "POP3" in protocols

        assert detector.get_email_packet_count() == 4  # SMTP(2) + IMAP(1) + POP3(1)

    def test_no_email_traffic(self):
        """Test handling of non-email traffic."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(packet_number=1, detected_protocol="HTTP"),
            PacketRecord(packet_number=2, detected_protocol="DNS"),
            PacketRecord(packet_number=3, detected_protocol="SSH"),
        ]

        detector.process_packets(iter(packets))

        assert detector.get_detected_protocols() == []
        assert detector.get_email_packet_count() == 0

    def test_session_candidates(self):
        """Test session candidate generation."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(
                packet_number=1,
                src_ip="10.0.0.1",
                src_port=12345,
                dst_ip="10.0.0.2",
                dst_port=25,
                detected_protocol="SMTP",
                tcp_stream=0
            ),
            PacketRecord(
                packet_number=2,
                src_ip="10.0.0.2",
                src_port=25,
                dst_ip="10.0.0.1",
                dst_port=12345,
                detected_protocol="SMTP",
                tcp_stream=0
            ),
        ]

        detector.process_packets(iter(packets))
        candidates = detector.get_session_candidates()

        assert len(candidates) == 1
        assert candidates[0].protocol == "SMTP"
        assert candidates[0].packet_count == 2
        assert candidates[0].tcp_stream == 0

    def test_protocol_detections_have_high_confidence(self):
        """Test that TShark-detected protocols have HIGH confidence."""
        detector = ProtocolDetector()
        packets = [
            PacketRecord(packet_number=1, detected_protocol="SMTP", tcp_stream=0),
        ]

        detector.process_packets(iter(packets))
        detections = detector.get_detections()

        assert len(detections) == 1
        assert detections[0].confidence == DetectionConfidence.HIGH
        assert detections[0].detection_source == "tshark_dissector"


# =============================================================================
# PHASE 2 BOUNDARY TESTS
# =============================================================================

class TestPhase2Boundaries:
    """Tests verifying Phase 2 does NOT implement future phase functionality."""

    def test_no_tcp_stream_reconstruction(self):
        """Verify Phase 2 does NOT reconstruct TCP streams."""
        # ProtocolSessionCandidate is a packet grouping, not a reconstructed stream
        candidate = ProtocolSessionCandidate(
            candidate_id="test",
            protocol="SMTP",
            packet_count=10,
            detection_confidence=DetectionConfidence.HIGH,
            detection_source="tshark_dissector"
        )

        # Should NOT have stream reconstruction attributes
        assert not hasattr(candidate, 'stream_integrity')
        assert not hasattr(candidate, 'stream_data')
        assert not hasattr(candidate, 'reconstructed_payload')

    def test_no_starttls_analysis(self):
        """Verify Phase 2 does NOT analyze STARTTLS success/failure."""
        # PacketRecord should not have STARTTLS success/failure fields
        record = PacketRecord(packet_number=1, detected_protocol="SMTP")

        assert not hasattr(record, 'starttls_success')
        assert not hasattr(record, 'starttls_detected')
        assert not hasattr(record, 'starttls_state')

    def test_no_tls_security_analysis(self):
        """Verify Phase 2 does NOT perform TLS security analysis."""
        # PacketRecord should not have TLS security fields
        record = PacketRecord(packet_number=1, detected_protocol="TLS")

        assert not hasattr(record, 'tls_version_secure')
        assert not hasattr(record, 'cipher_strength')
        assert not hasattr(record, 'security_rating')
        assert not hasattr(record, 'forward_secrecy')

    def test_no_certificate_analysis(self):
        """Verify Phase 2 does NOT analyze certificates."""
        record = PacketRecord(packet_number=1, detected_protocol="TLS")

        assert not hasattr(record, 'certificate')
        assert not hasattr(record, 'certificate_valid')
        assert not hasattr(record, 'certificate_expired')


# =============================================================================
# API ENDPOINT TESTS
# =============================================================================

class TestAnalysisAPI:
    """Tests for Phase 2 analysis API endpoints."""

    def _create_case_with_evidence(self, client, pcap_bytes, temp_storage_path):
        """Helper to create a case with evidence."""
        # Create case
        case_response = client.post(
            "/api/v1/cases",
            json={"case_name": "Test Case"}
        )
        case_id = case_response.json()["data"]["case_id"]

        # Upload evidence
        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            evidence_response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")}
            )

        evidence_data = evidence_response.json()["data"]
        return {
            "case_id": case_id,
            "evidence_id": evidence_data["evidence_id"],
            "job_id": evidence_data["analysis_job_id"]
        }

    def test_trigger_analysis(self, client, valid_pcap_bytes, temp_storage_path):
        """Test triggering analysis for evidence."""
        data = self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        with patch("app.api.routes.analysis.analyze_evidence") as mock_task:
            mock_task.delay = Mock()

            response = client.post(f"/api/v1/evidence/{data['evidence_id']}/analyze")

            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True
            assert result["data"]["status"] == "TRIGGERED"
            mock_task.delay.assert_called_once_with(data["job_id"])

    def test_get_analysis_summary_not_found(self, client, valid_pcap_bytes, temp_storage_path):
        """Test getting summary before analysis starts."""
        data = self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        response = client.get(f"/api/v1/analysis/{data['job_id']}/summary")

        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "ANALYSIS_NOT_STARTED"

    def test_get_protocols_not_found(self, client, valid_pcap_bytes, temp_storage_path):
        """Test getting protocols before analysis completes."""
        data = self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        response = client.get(f"/api/v1/analysis/{data['job_id']}/protocols")

        assert response.status_code == 404

    def test_trigger_analysis_evidence_not_found(self, client):
        """Test triggering analysis for nonexistent evidence."""
        response = client.post("/api/v1/evidence/nonexistent/analyze")

        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "EVIDENCE_NOT_FOUND"


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling:
    """Tests for Phase 2 error handling."""

    def test_tshark_timeout_result(self):
        """Test TShark timeout produces correct result."""
        result = TSharkResult(
            status=TSharkStatus.TIMEOUT,
            exit_code=None,
            stdout="",
            stderr="Process timed out",
            timed_out=True,
            duration_seconds=300.0
        )

        assert result.status == TSharkStatus.TIMEOUT
        assert result.timed_out is True

    def test_tshark_failed_result(self):
        """Test TShark failure produces correct result."""
        result = TSharkResult(
            status=TSharkStatus.FAILED,
            exit_code=2,
            stdout="",
            stderr="Error reading file",
            timed_out=False
        )

        assert result.status == TSharkStatus.FAILED
        assert result.exit_code == 2

    def test_tshark_invalid_output_result(self):
        """Test TShark invalid output produces correct result."""
        result = TSharkResult(
            status=TSharkStatus.INVALID_OUTPUT,
            exit_code=0,
            stdout="garbage data",
            stderr="",
            timed_out=False
        )

        assert result.status == TSharkStatus.INVALID_OUTPUT


# =============================================================================
# RETRY POLICY TESTS
# =============================================================================

class TestRetryPolicy:
    """Tests for Celery retry policy compliance."""

    def test_tshark_not_found_no_retry(self):
        """Verify TSHARK_NOT_FOUND does not trigger retry."""
        from app.workers.tasks import AnalysisTask

        # The task should NOT have TSHARK_NOT_FOUND in autoretry_for
        # Since it uses custom base class, check it's not retrying on generic Exception
        task = AnalysisTask()

        # autoretry_for should only include DB errors
        from sqlalchemy.exc import OperationalError, InterfaceError
        assert task.autoretry_for == (OperationalError, InterfaceError)

    def test_db_retry_config(self):
        """Verify database retry configuration."""
        from app.workers.tasks import AnalysisTask, DB_MAX_RETRIES, DB_RETRY_COUNTDOWN

        task = AnalysisTask()

        assert DB_MAX_RETRIES == 2
        assert DB_RETRY_COUNTDOWN == 10
        assert task.retry_kwargs['max_retries'] == 2
        assert task.retry_kwargs['countdown'] == 10
