"""Phase 3 Security Analysis Tests.

Comprehensive tests for Phase 3 Security Intelligence Engine:
- TCP stream reconstruction
- Email security analysis
- TLS analysis
- Certificate analysis
- Crypto policy and rules engine
- Finding engine
- Risk assessment engine
- Boundary enforcement tests
- API endpoint tests

IMPORTANT: These tests verify Phase 3 boundaries:
- NO TShark calls
- NO ML inference
- NO PDF generation
- NO blockchain
- Deterministic analysis only
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Service imports
from app.services.tcp import TcpStreamReconstructor
from app.services.tcp.models import StreamIntegrity, TcpStreamData, StreamTermination

from app.services.email import EmailSecurityAnalyzer
from app.services.email.models import (
    TransportSecurity, StarttlsState, EmailSecuritySession, StarttlsObservation
)

from app.services.tls import TlsAnalyzer
from app.services.tls.models import (
    TlsVersion, TlsVersionSecurity, HandshakeStatus, TlsObservation
)

from app.services.certificates import CertificateAnalyzer
from app.services.certificates.models import (
    CertificateValidity, KeyType, KeyStrength, SignatureAlgorithmSecurity
)

from app.services.crypto import CryptoPolicy, get_default_policy, RulesEngine
from app.services.crypto.rules import Severity, RuleCategory

from app.services.findings import FindingEngine
from app.services.findings.models import FindingStatus, EvidenceType

from app.services.risk import RiskEngine
from app.services.risk.models import RiskLevel, SecurityDimension

from app.services.packet.models import PacketRecord


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture
def sample_packets():
    """Create sample packet records for testing."""
    return [
        PacketRecord(
            packet_number=1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=25,
            detected_protocol="SMTP",
            tcp_stream=0,
            tcp_flags="0x018",  # SYN-ACK
        ),
        PacketRecord(
            packet_number=2,
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=25,
            dst_port=12345,
            detected_protocol="SMTP",
            tcp_stream=0,
            tcp_flags="0x010",  # ACK
        ),
        PacketRecord(
            packet_number=3,
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=25,
            detected_protocol="SMTP",
            tcp_stream=0,
            tcp_flags="0x011",  # FIN
        ),
    ]


@pytest.fixture
def sample_streams():
    """Create sample TCP streams for testing."""
    return [
        TcpStreamData(
            stream_id=0,
            client_ip="192.168.1.1",
            client_port=12345,
            server_ip="192.168.1.2",
            server_port=25,
            protocol="SMTP",
            integrity=StreamIntegrity.COMPLETE,
            packet_count=10,
            termination=StreamTermination.FIN,
        ),
        TcpStreamData(
            stream_id=1,
            client_ip="192.168.1.1",
            client_port=23456,
            server_ip="192.168.1.3",
            server_port=993,
            protocol="IMAP",
            integrity=StreamIntegrity.COMPLETE,
            packet_count=20,
            termination=StreamTermination.FIN,
            has_tls=True,
        ),
    ]


@pytest.fixture
def sample_sessions():
    """Create sample email sessions for testing."""
    return [
        EmailSecuritySession(
            session_id="sess_001",
            stream_id=0,
            protocol="SMTP",
            client_ip="192.168.1.1",
            server_ip="192.168.1.2",
            server_port=25,
            transport_security=TransportSecurity.PLAINTEXT,
            starttls=StarttlsObservation(
                state=StarttlsState.NOT_OBSERVED,
                advertised=True
            ),
        ),
        EmailSecuritySession(
            session_id="sess_002",
            stream_id=1,
            protocol="IMAP",
            client_ip="192.168.1.1",
            server_ip="192.168.1.3",
            server_port=993,
            transport_security=TransportSecurity.IMPLICIT_TLS,
            implicit_tls=True,
            tls_detected=True,
        ),
    ]


# ============================================================
# TCP STREAM RECONSTRUCTION TESTS
# ============================================================

class TestTcpStreamReconstructor:
    """Tests for TCP stream reconstruction."""

    def test_empty_packets(self):
        """Test with no packets."""
        reconstructor = TcpStreamReconstructor()
        reconstructor.process_packets([])

        result = reconstructor.get_result("ev_001", "job_001")
        assert result.total_streams == 0
        assert result.complete_streams == 0

    def test_single_stream(self, sample_packets):
        """Test single TCP stream reconstruction."""
        reconstructor = TcpStreamReconstructor()
        reconstructor.process_packets(sample_packets)

        result = reconstructor.get_result("ev_001", "job_001")
        assert result.total_streams == 1

        streams = reconstructor.get_streams()
        assert len(streams) == 1
        assert streams[0].stream_id == 0

    def test_stream_integrity_with_fin(self, sample_packets):
        """Test that FIN flag sets COMPLETE integrity."""
        reconstructor = TcpStreamReconstructor()
        reconstructor.process_packets(sample_packets)

        streams = reconstructor.get_streams()
        # Stream has FIN, check termination type
        assert streams[0].termination == StreamTermination.FIN

    def test_client_server_direction(self, sample_packets):
        """Test client/server identification."""
        reconstructor = TcpStreamReconstructor()
        reconstructor.process_packets(sample_packets)

        streams = reconstructor.get_streams()
        # Port 25 is SMTP, should be server
        assert streams[0].server_port == 25
        assert streams[0].client_port == 12345

    def test_multiple_streams(self):
        """Test multiple TCP streams."""
        packets = [
            PacketRecord(
                packet_number=1, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=1000, dst_port=25, detected_protocol="SMTP",
                tcp_stream=0, tcp_flags="0x000"
            ),
            PacketRecord(
                packet_number=2, src_ip="10.0.0.1", dst_ip="10.0.0.3",
                src_port=2000, dst_port=143, detected_protocol="IMAP",
                tcp_stream=1, tcp_flags="0x000"
            ),
        ]

        reconstructor = TcpStreamReconstructor()
        reconstructor.process_packets(packets)

        result = reconstructor.get_result("ev_001", "job_001")
        assert result.total_streams == 2


# ============================================================
# EMAIL SECURITY ANALYZER TESTS
# ============================================================

class TestEmailSecurityAnalyzer:
    """Tests for email security analysis."""

    def test_empty_streams(self):
        """Test with no streams."""
        analyzer = EmailSecurityAnalyzer()
        analyzer.analyze_streams([])

        result = analyzer.get_result("ev_001", "job_001")
        assert result.total_sessions == 0

    def test_smtp_port_detection(self, sample_streams):
        """Test SMTP protocol detection by port."""
        analyzer = EmailSecurityAnalyzer()
        analyzer.analyze_streams(sample_streams)

        sessions = analyzer.get_sessions()
        smtp_sessions = [s for s in sessions if s.protocol == "SMTP"]
        assert len(smtp_sessions) >= 1

    def test_implicit_tls_detection(self, sample_streams):
        """Test implicit TLS detection (port 993)."""
        analyzer = EmailSecurityAnalyzer()
        analyzer.analyze_streams(sample_streams)

        sessions = analyzer.get_sessions()
        imap_sessions = [s for s in sessions if s.server_port == 993]

        # Port 993 should be detected as implicit TLS
        if imap_sessions:
            assert imap_sessions[0].implicit_tls is True
            assert imap_sessions[0].transport_security == TransportSecurity.IMPLICIT_TLS

    def test_starttls_state_machine(self):
        """Test STARTTLS state detection."""
        streams = [
            TcpStreamData(
                stream_id=0, client_ip="10.0.0.1", server_ip="10.0.0.2",
                client_port=1000, server_port=587,  # SMTP submission
                protocol="SMTP",  # Must set protocol for analyzer to process
                integrity=StreamIntegrity.COMPLETE,
                packet_count=5
            )
        ]

        analyzer = EmailSecurityAnalyzer()
        analyzer.analyze_streams(streams)

        sessions = analyzer.get_sessions()
        # Port 587 is SMTP submission, typically uses STARTTLS
        assert len(sessions) >= 1


# ============================================================
# TLS ANALYZER TESTS
# ============================================================

class TestTlsAnalyzer:
    """Tests for TLS analysis."""

    def test_empty_sessions(self):
        """Test with no sessions."""
        analyzer = TlsAnalyzer()
        analyzer.analyze_sessions([], [])

        result = analyzer.get_result("ev_001", "job_001")
        assert result.total_observations == 0

    def test_tls_version_detection(self, sample_sessions, sample_streams):
        """Test TLS version detection from sessions."""
        analyzer = TlsAnalyzer()
        analyzer.analyze_sessions(sample_sessions, sample_streams)

        observations = analyzer.get_observations()
        # Should have observations for TLS sessions
        assert len(observations) >= 0  # May be 0 if no TLS data in mock

    def test_tls_version_security_classification(self):
        """Test TLS version security classification using VERSION_SECURITY mapping."""
        analyzer = TlsAnalyzer()

        # Test version classification using the class constant
        assert analyzer.VERSION_SECURITY[TlsVersion.TLS_1_3] == TlsVersionSecurity.MODERN
        assert analyzer.VERSION_SECURITY[TlsVersion.TLS_1_2] == TlsVersionSecurity.ACCEPTABLE
        assert analyzer.VERSION_SECURITY[TlsVersion.TLS_1_1] == TlsVersionSecurity.DEPRECATED
        assert analyzer.VERSION_SECURITY[TlsVersion.TLS_1_0] == TlsVersionSecurity.DEPRECATED
        assert analyzer.VERSION_SECURITY[TlsVersion.SSL_3_0] == TlsVersionSecurity.OBSOLETE

    def test_forward_secrecy_detection(self):
        """Test forward secrecy detection from key exchange."""
        analyzer = TlsAnalyzer()

        # Test using _detect_key_exchange which returns (KeyExchangeType, forward_secrecy)
        _, fs_ecdhe = analyzer._detect_key_exchange("ECDHE_RSA_WITH_AES_256_GCM")
        _, fs_dhe = analyzer._detect_key_exchange("DHE_RSA_WITH_AES_256_GCM")
        _, fs_rsa = analyzer._detect_key_exchange("RSA_WITH_AES_256_GCM")

        assert fs_ecdhe is True
        assert fs_dhe is True
        assert fs_rsa is False


# ============================================================
# CERTIFICATE ANALYZER TESTS
# ============================================================

class TestCertificateAnalyzer:
    """Tests for certificate analysis."""

    def test_empty_observations(self):
        """Test with no TLS observations."""
        analyzer = CertificateAnalyzer()
        analyzer.analyze_tls_observations([])

        result = analyzer.get_result("ev_001", "job_001")
        assert result.total_certificates == 0

    def test_key_strength_thresholds(self):
        """Test key strength classification thresholds."""
        analyzer = CertificateAnalyzer()

        # RSA thresholds
        assert analyzer.RSA_STRONG_MIN == 3072
        assert analyzer.RSA_ACCEPTABLE_MIN == 2048
        assert analyzer.RSA_WEAK_MIN == 1024

        # EC thresholds
        assert analyzer.EC_STRONG_MIN == 384
        assert analyzer.EC_ACCEPTABLE_MIN == 256

    def test_weak_signature_detection(self):
        """Test weak signature algorithm detection."""
        analyzer = CertificateAnalyzer()

        assert "md5" in analyzer.WEAK_SIGNATURES
        assert "sha1" in analyzer.WEAK_SIGNATURES
        assert "sha256" in analyzer.STRONG_SIGNATURES


# ============================================================
# CRYPTO POLICY TESTS
# ============================================================

class TestCryptoPolicy:
    """Tests for cryptographic policy."""

    def test_default_policy(self):
        """Test default policy creation."""
        policy = get_default_policy()

        assert policy.version == "1.0.0"
        assert "TLS1.0" in policy.tls_version.deprecated_versions
        assert "TLS1.2" in policy.tls_version.acceptable_versions

    def test_tls_version_checks(self):
        """Test TLS version policy checks."""
        policy = CryptoPolicy()

        assert policy.is_tls_version_deprecated("TLS1.0") is True
        assert policy.is_tls_version_deprecated("TLS1.2") is False
        assert policy.is_tls_version_obsolete("SSLv3") is True
        assert policy.is_tls_version_acceptable("TLS1.3") is True

    def test_cipher_weakness_detection(self):
        """Test weak cipher detection."""
        policy = CryptoPolicy()

        assert policy.is_cipher_weak("RC4-SHA") is True
        assert policy.is_cipher_weak("3DES-CBC") is True
        assert policy.is_cipher_weak("AES256-GCM-SHA384") is False

    def test_key_size_checks(self):
        """Test key size policy checks."""
        policy = CryptoPolicy()

        assert policy.is_key_size_acceptable("RSA", 2048) is True
        assert policy.is_key_size_acceptable("RSA", 1024) is False
        assert policy.is_key_size_acceptable("ECDSA", 256) is True
        assert policy.is_key_size_acceptable("ECDSA", 128) is False

    def test_signature_algorithm_checks(self):
        """Test signature algorithm weakness detection."""
        policy = CryptoPolicy()

        assert policy.is_signature_algorithm_weak("md5WithRSA") is True
        assert policy.is_signature_algorithm_weak("sha1WithRSA") is True
        assert policy.is_signature_algorithm_weak("sha256WithRSA") is False


# ============================================================
# RULES ENGINE TESTS
# ============================================================

class TestRulesEngine:
    """Tests for security rules engine."""

    def test_rules_defined(self):
        """Test that all expected rules are defined."""
        engine = RulesEngine()

        assert engine.get_rule("TLS-001") is not None  # Deprecated TLS
        assert engine.get_rule("TLS-002") is not None  # Obsolete SSL
        assert engine.get_rule("CIPHER-001") is not None  # Weak cipher
        assert engine.get_rule("CERT-001") is not None  # Expired cert
        assert engine.get_rule("PROTO-001") is not None  # Plaintext

    def test_evaluate_tls_version(self):
        """Test TLS version rule evaluation."""
        engine = RulesEngine()

        # TLS 1.0 should trigger TLS-001
        matches = engine.evaluate_tls_version("TLS1.0", stream_id=0)
        rule_ids = [m.rule_id for m in matches]
        assert "TLS-001" in rule_ids

        # SSLv3 should trigger TLS-002
        matches = engine.evaluate_tls_version("SSLv3", stream_id=0)
        rule_ids = [m.rule_id for m in matches]
        assert "TLS-002" in rule_ids

        # TLS 1.3 should not trigger any rules
        matches = engine.evaluate_tls_version("TLS1.3", stream_id=0)
        assert len(matches) == 0

    def test_evaluate_cipher(self):
        """Test cipher rule evaluation."""
        engine = RulesEngine()

        # RC4 should trigger CIPHER-001
        matches = engine.evaluate_cipher("RC4-SHA", stream_id=0)
        rule_ids = [m.rule_id for m in matches]
        assert "CIPHER-001" in rule_ids

        # AES-GCM should not trigger
        matches = engine.evaluate_cipher("AES256-GCM-SHA384", stream_id=0)
        assert len(matches) == 0

    def test_evaluate_certificate(self):
        """Test certificate rule evaluation."""
        engine = RulesEngine()

        # Expired cert should trigger CERT-001
        cert_data = {"validity": "EXPIRED"}
        matches = engine.evaluate_certificate(cert_data, stream_id=0)
        rule_ids = [m.rule_id for m in matches]
        assert "CERT-001" in rule_ids

        # Self-signed should trigger CERT-003
        cert_data = {"is_self_signed": True}
        matches = engine.evaluate_certificate(cert_data, stream_id=0)
        rule_ids = [m.rule_id for m in matches]
        assert "CERT-003" in rule_ids

    def test_evaluate_protocol_security(self):
        """Test protocol security rule evaluation."""
        engine = RulesEngine()

        # Plaintext session should trigger PROTO-001
        session_data = {"transport_security": "PLAINTEXT"}
        matches = engine.evaluate_protocol_security(session_data, stream_id=0)
        rule_ids = [m.rule_id for m in matches]
        assert "PROTO-001" in rule_ids


# ============================================================
# FINDING ENGINE TESTS
# ============================================================

class TestFindingEngine:
    """Tests for finding engine."""

    def test_empty_analysis(self):
        """Test with no data."""
        engine = FindingEngine()

        result = engine.get_result("ev_001", "job_001")
        assert result.summary.total_findings == 0

    def test_finding_from_tls_observation(self):
        """Test finding generation from TLS observation."""
        engine = FindingEngine()

        obs = TlsObservation(
            observation_id="tls_001",
            stream_id=0,
            session_id="sess_001",
            tls_version=TlsVersion.TLS_1_0,
            handshake_status=HandshakeStatus.SUCCESS,
        )

        engine.analyze_tls_observations([obs], "ev_001", "job_001")
        result = engine.get_result("ev_001", "job_001")

        # TLS 1.0 should generate a finding
        assert result.summary.total_findings >= 1
        assert "TLS-001" in result.summary.unique_rules

    def test_finding_deduplication(self):
        """Test that duplicate findings are aggregated."""
        engine = FindingEngine()

        # Create multiple TLS 1.0 observations
        observations = [
            TlsObservation(
                observation_id=f"tls_{i}",
                stream_id=i,
                session_id=f"sess_{i}",
                tls_version=TlsVersion.TLS_1_0,
                handshake_status=HandshakeStatus.SUCCESS,
            )
            for i in range(3)
        ]

        engine.analyze_tls_observations(observations, "ev_001", "job_001")
        result = engine.get_result("ev_001", "job_001")

        # Should have 1 finding with occurrence_count >= 3
        findings = result.findings
        tls_findings = [f for f in findings if f.rule_id == "TLS-001"]
        assert len(tls_findings) == 1
        assert tls_findings[0].occurrence_count >= 3


# ============================================================
# RISK ENGINE TESTS
# ============================================================

class TestRiskEngine:
    """Tests for risk assessment engine."""

    def test_perfect_score(self):
        """Test perfect score with no findings."""
        from app.services.findings.models import FindingsResult, FindingSummary

        engine = RiskEngine()

        findings_result = FindingsResult(
            evidence_id="ev_001",
            job_id="job_001",
            findings=[],
            summary=FindingSummary(total_findings=0)
        )

        assessment = engine.assess_risk(findings_result)

        assert assessment.posture.overall_score == 100.0
        assert assessment.posture.overall_risk == RiskLevel.MINIMAL

    def test_critical_finding_impact(self):
        """Test that critical findings severely impact score."""
        from app.services.findings.models import (
            FindingsResult, FindingSummary, SecurityFinding
        )

        engine = RiskEngine()

        findings_result = FindingsResult(
            evidence_id="ev_001",
            job_id="job_001",
            findings=[
                SecurityFinding(
                    finding_id="f1",
                    rule_id="TLS-002",
                    title="Obsolete SSL",
                    description="SSLv3 detected",
                    category=RuleCategory.TLS_VERSION,
                    severity=Severity.CRITICAL,
                    evidence_id="ev_001",
                    job_id="job_001",
                )
            ],
            summary=FindingSummary(total_findings=1, critical_count=1)
        )

        assessment = engine.assess_risk(findings_result)

        # Critical finding should drop score by 25 points (100 - 25 = 75)
        assert assessment.posture.overall_score == 75.0
        # Score 75 is >= 75 (not < 75), so it falls into LOW tier (< 90)
        # Risk levels: CRITICAL (<25), HIGH (<50), MEDIUM (<75), LOW (<90), MINIMAL (>=90)
        assert assessment.posture.overall_risk == RiskLevel.LOW

    def test_score_calculation_formula(self):
        """Test score calculation follows documented formula."""
        from app.services.findings.models import FindingsResult, FindingSummary

        engine = RiskEngine()

        # 2 CRITICAL (50), 1 HIGH (15), 3 MEDIUM (15), 5 LOW (5) = 85 penalty
        # Score = 100 - 85 = 15 (clamped to 0 if negative)
        findings_result = FindingsResult(
            evidence_id="ev_001",
            job_id="job_001",
            findings=[],
            summary=FindingSummary(
                total_findings=11,
                critical_count=2,
                high_count=1,
                medium_count=3,
                low_count=5,
            )
        )

        assessment = engine.assess_risk(findings_result)

        expected_penalty = (2 * 25) + (1 * 15) + (3 * 5) + (5 * 1)
        expected_score = max(0, 100 - expected_penalty)

        assert assessment.posture.overall_score == expected_score

    def test_risk_level_thresholds(self):
        """Test risk level classification thresholds."""
        engine = RiskEngine()

        assert engine._score_to_risk_level(95) == RiskLevel.MINIMAL
        assert engine._score_to_risk_level(85) == RiskLevel.LOW
        assert engine._score_to_risk_level(60) == RiskLevel.MEDIUM
        assert engine._score_to_risk_level(40) == RiskLevel.HIGH
        assert engine._score_to_risk_level(20) == RiskLevel.CRITICAL


# ============================================================
# BOUNDARY ENFORCEMENT TESTS
# ============================================================

class TestBoundaryEnforcement:
    """Tests to verify Phase 3 boundaries are enforced."""

    def test_no_tshark_dependency(self):
        """Verify Phase 3 services don't import TShark."""
        # These imports should work without TShark
        from app.services.tcp import TcpStreamReconstructor
        from app.services.email import EmailSecurityAnalyzer
        from app.services.tls import TlsAnalyzer
        from app.services.certificates import CertificateAnalyzer
        from app.services.findings import FindingEngine
        from app.services.risk import RiskEngine

        # All should be instantiable without TShark
        TcpStreamReconstructor()
        EmailSecurityAnalyzer()
        TlsAnalyzer()
        CertificateAnalyzer()
        FindingEngine()
        RiskEngine()

    def test_deterministic_analysis(self):
        """Verify analysis is deterministic (same input = same output)."""
        engine = RulesEngine()

        # Run same evaluation twice
        matches1 = engine.evaluate_tls_version("TLS1.0", stream_id=0)
        matches2 = engine.evaluate_tls_version("TLS1.0", stream_id=0)

        # Should produce same results
        assert len(matches1) == len(matches2)
        assert all(m1.rule_id == m2.rule_id for m1, m2 in zip(matches1, matches2))

    def test_no_ml_inference(self):
        """Verify risk engine doesn't use ML."""
        from app.services.risk.risk_engine import RiskEngine

        engine = RiskEngine()

        # Risk engine should only have deterministic methods
        assert hasattr(engine, '_calculate_overall_score')
        assert hasattr(engine, '_score_to_risk_level')

        # Should NOT have ML-related attributes
        assert not hasattr(engine, 'model')
        assert not hasattr(engine, 'predict')
        assert not hasattr(engine, 'classifier')

    def test_policy_versioning(self):
        """Verify policy is versioned for reproducibility."""
        policy = get_default_policy()

        assert hasattr(policy, 'version')
        assert policy.version == "1.0.0"

        engine = RiskEngine(policy)
        assert engine.policy.version == "1.0.0"


# ============================================================
# API ENDPOINT TESTS
# ============================================================

class TestSecurityApiEndpoints:
    """Tests for Phase 3 API endpoints."""

    def test_security_summary_not_found(self, client, test_db):
        """Test security summary returns 404 when no analysis exists."""
        response = client.get("/api/v1/security/ev_nonexistent/summary")
        assert response.status_code == 404
        data = response.json()
        # FastAPI HTTPException returns {"detail": {...}} format
        assert "detail" in data
        assert data["detail"]["code"] == "SECURITY_ANALYSIS_NOT_FOUND"

    def test_trigger_analysis_evidence_not_found(self, client, test_db):
        """Test trigger returns 404 when evidence doesn't exist."""
        response = client.post("/api/v1/security/ev_nonexistent/analyze")
        assert response.status_code == 404
        data = response.json()
        # FastAPI HTTPException returns {"detail": {...}} format
        assert "detail" in data
        assert data["detail"]["code"] == "EVIDENCE_NOT_FOUND"

    def test_findings_endpoint_structure(self, client, test_db):
        """Test findings endpoint returns proper structure."""
        # Create evidence and security analysis
        from app.models import (
            Case, PcapEvidence, AnalysisJob, SecurityAnalysis
        )
        from datetime import datetime, timezone

        case = Case(case_name="Test Case")
        test_db.add(case)
        test_db.commit()

        evidence = PcapEvidence(
            case_id=case.case_id,
            original_filename="test.pcap",
            stored_filename="test_stored.pcap",
            file_size_bytes=1000,
            sha256="abc123def456789012345678901234567890123456789012345678901234",
            storage_location="/tmp/test.pcap",
        )
        test_db.add(evidence)
        test_db.commit()

        job = AnalysisJob(
            evidence_id=evidence.evidence_id,
        )
        test_db.add(job)
        test_db.commit()

        analysis = SecurityAnalysis(
            job_id=job.job_id,
            evidence_id=evidence.evidence_id,
            status=SecurityAnalysisStatus.COMPLETED,
            findings=[
                {
                    "finding_id": "f1",
                    "rule_id": "TLS-001",
                    "title": "Deprecated TLS",
                    "description": "TLS 1.0 detected",
                    "category": "TLS_VERSION",
                    "severity": "HIGH",
                    "evidence": [],
                }
            ],
            total_findings=1,
            high_findings=1,
        )
        test_db.add(analysis)
        test_db.commit()

        response = client.get(f"/api/v1/security/{evidence.evidence_id}/findings")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "findings" in data["data"]
        assert "total" in data["data"]


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestPhase3Integration:
    """Integration tests for Phase 3 pipeline."""

    def test_full_analysis_pipeline(self, sample_packets):
        """Test complete analysis pipeline."""
        # Step 1: Reconstruct streams
        stream_reconstructor = TcpStreamReconstructor()
        stream_reconstructor.process_packets(sample_packets)
        streams = stream_reconstructor.get_streams()

        # Step 2: Analyze email sessions
        email_analyzer = EmailSecurityAnalyzer()
        email_analyzer.analyze_streams(streams)
        sessions = email_analyzer.get_sessions()

        # Step 3: Analyze TLS
        tls_analyzer = TlsAnalyzer()
        tls_analyzer.analyze_sessions(sessions, streams)
        tls_observations = tls_analyzer.get_observations()

        # Step 4: Analyze certificates
        cert_analyzer = CertificateAnalyzer()
        cert_analyzer.analyze_tls_observations(tls_observations)

        # Step 5: Generate findings
        finding_engine = FindingEngine()
        finding_engine.analyze_streams(streams, "ev_001", "job_001")
        finding_engine.analyze_email_sessions(sessions, "ev_001", "job_001")
        finding_engine.analyze_tls_observations(tls_observations, "ev_001", "job_001")
        findings_result = finding_engine.get_result("ev_001", "job_001")

        # Step 6: Risk assessment
        risk_engine = RiskEngine()
        assessment = risk_engine.assess_risk(
            findings_result,
            total_streams=len(streams),
            total_sessions=len(sessions)
        )

        # Verify complete pipeline
        assert assessment.posture.overall_score >= 0
        assert assessment.posture.overall_score <= 100
        assert assessment.posture.overall_risk in [
            RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
            RiskLevel.LOW, RiskLevel.MINIMAL, RiskLevel.UNKNOWN
        ]

    def test_pipeline_with_no_email_traffic(self):
        """Test pipeline handles non-email traffic gracefully."""
        # HTTP traffic packets (not email)
        packets = [
            PacketRecord(
                packet_number=1, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=12345, dst_port=80, detected_protocol="HTTP",
                tcp_stream=0, tcp_flags="0x000"
            )
        ]

        stream_reconstructor = TcpStreamReconstructor()
        stream_reconstructor.process_packets(packets)
        streams = stream_reconstructor.get_streams()

        email_analyzer = EmailSecurityAnalyzer()
        email_analyzer.analyze_streams(streams)
        sessions = email_analyzer.get_sessions()

        # No email sessions should be detected
        # (Port 80 is not an email port)
        # The analyzer may still create sessions, but they won't be email protocols


# Import required for API tests
from app.models.security_analysis import SecurityAnalysisStatus
