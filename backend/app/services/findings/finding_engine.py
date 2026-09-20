"""Finding engine - generates evidence-backed security findings.

Phase 3: Deterministic finding generation from rule matches.

This engine:
1. Takes analyzed data from all Phase 3 services
2. Evaluates security rules
3. Generates findings with full evidence traceability
4. Deduplicates findings
5. Aggregates occurrences

IMPORTANT: Findings are deterministic.
Same evidence + same policy = same findings.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from app.services.crypto.rules import RulesEngine, RuleMatch, Severity, RuleCategory
from app.services.crypto.policy import CryptoPolicy, get_default_policy
from app.services.tcp.models import TcpStreamData, StreamIntegrity
from app.services.email.models import (
    EmailSecuritySession,
    TransportSecurity,
    StarttlsState,
)
from app.services.tls.models import TlsObservation, TlsVersionSecurity, HandshakeStatus
from app.services.certificates.models import (
    CertificateObservation,
    CertificateValidity,
    KeyStrength,
    SignatureAlgorithmSecurity,
)
from app.services.findings.models import (
    SecurityFinding,
    FindingEvidence,
    FindingsResult,
    FindingSummary,
    FindingStatus,
    EvidenceType,
)

logger = logging.getLogger(__name__)


class FindingEngine:
    """
    Evidence-backed security finding engine.

    Generates deterministic findings from analyzed data.
    All findings are traceable to specific evidence.
    """

    def __init__(self, policy: Optional[CryptoPolicy] = None):
        """
        Initialize finding engine.

        Args:
            policy: Crypto policy to use. Defaults to default policy.
        """
        self.policy = policy or get_default_policy()
        self.rules_engine = RulesEngine(self.policy)
        self._findings: list[SecurityFinding] = []
        self._raw_matches: int = 0
        self._streams_analyzed: int = 0
        self._sessions_analyzed: int = 0
        self._certificates_analyzed: int = 0

    def reset(self):
        """Reset engine state."""
        self._findings = []
        self._raw_matches = 0
        self._streams_analyzed = 0
        self._sessions_analyzed = 0
        self._certificates_analyzed = 0

    def analyze_streams(
        self,
        streams: list[TcpStreamData],
        evidence_id: str,
        job_id: str
    ) -> None:
        """
        Analyze TCP streams for stream-level findings.

        Currently stream-level findings are minimal since most
        security issues are at higher layers (TLS, cert, protocol).

        Args:
            streams: TCP stream data
            evidence_id: Evidence identifier
            job_id: Job identifier
        """
        self._streams_analyzed = len(streams)
        # Stream integrity issues are informational
        # Real security findings come from TLS/cert/protocol analysis

    def analyze_email_sessions(
        self,
        sessions: list[EmailSecuritySession],
        evidence_id: str,
        job_id: str
    ) -> None:
        """
        Analyze email sessions for protocol security findings.

        Args:
            sessions: Email security sessions
            evidence_id: Evidence identifier
            job_id: Job identifier
        """
        self._sessions_analyzed = len(sessions)

        for session in sessions:
            self._analyze_email_session(session, evidence_id, job_id)

    def _analyze_email_session(
        self,
        session: EmailSecuritySession,
        evidence_id: str,
        job_id: str
    ) -> None:
        """Analyze single email session for findings."""
        session_data = {
            "transport_security": session.transport_security.value,
            "starttls_advertised": session.starttls.advertised,
            "starttls_requested": session.starttls.state in [
                StarttlsState.REQUESTED,
                StarttlsState.TLS_STARTED,
                StarttlsState.FAILED
            ],
            "starttls_failed": session.starttls.state == StarttlsState.FAILED,
        }

        matches = self.rules_engine.evaluate_protocol_security(
            session_data,
            session.stream_id
        )

        for match in matches:
            self._raw_matches += 1
            finding = self._create_finding_from_match(
                match=match,
                evidence_id=evidence_id,
                job_id=job_id,
                session_id=session.session_id,
                stream_id=session.stream_id,
                evidence_type=EvidenceType.EMAIL_SESSION,
                reference_id=session.session_id
            )
            self._add_finding(finding)

    def analyze_tls_observations(
        self,
        observations: list[TlsObservation],
        evidence_id: str,
        job_id: str
    ) -> None:
        """
        Analyze TLS observations for cryptographic findings.

        Args:
            observations: TLS observations
            evidence_id: Evidence identifier
            job_id: Job identifier
        """
        for obs in observations:
            self._analyze_tls_observation(obs, evidence_id, job_id)

    def _analyze_tls_observation(
        self,
        obs: TlsObservation,
        evidence_id: str,
        job_id: str
    ) -> None:
        """Analyze single TLS observation for findings."""
        # TLS version
        if obs.tls_version:
            version_str = obs.tls_version.value if hasattr(obs.tls_version, 'value') else str(obs.tls_version)
            # Normalize version string for policy check
            version_normalized = self._normalize_tls_version(version_str)

            matches = self.rules_engine.evaluate_tls_version(
                version_normalized,
                obs.stream_id
            )
            for match in matches:
                self._raw_matches += 1
                finding = self._create_finding_from_match(
                    match=match,
                    evidence_id=evidence_id,
                    job_id=job_id,
                    stream_id=obs.stream_id,
                    session_id=obs.session_id,
                    evidence_type=EvidenceType.TLS_OBSERVATION,
                    reference_id=obs.observation_id
                )
                self._add_finding(finding)

        # Cipher suite
        if obs.cipher_suite:
            matches = self.rules_engine.evaluate_cipher(
                obs.cipher_suite,
                obs.stream_id
            )
            for match in matches:
                self._raw_matches += 1
                finding = self._create_finding_from_match(
                    match=match,
                    evidence_id=evidence_id,
                    job_id=job_id,
                    stream_id=obs.stream_id,
                    session_id=obs.session_id,
                    evidence_type=EvidenceType.TLS_OBSERVATION,
                    reference_id=obs.observation_id
                )
                self._add_finding(finding)

        # Forward secrecy
        if obs.key_exchange:
            matches = self.rules_engine.evaluate_forward_secrecy(
                obs.forward_secrecy,
                obs.key_exchange,
                obs.stream_id
            )
            for match in matches:
                self._raw_matches += 1
                finding = self._create_finding_from_match(
                    match=match,
                    evidence_id=evidence_id,
                    job_id=job_id,
                    stream_id=obs.stream_id,
                    session_id=obs.session_id,
                    evidence_type=EvidenceType.TLS_OBSERVATION,
                    reference_id=obs.observation_id
                )
                self._add_finding(finding)

        # Handshake status
        if obs.handshake_status == HandshakeStatus.FAILED:
            matches = self.rules_engine.evaluate_handshake(
                "FAILED",
                obs.stream_id
            )
            for match in matches:
                self._raw_matches += 1
                finding = self._create_finding_from_match(
                    match=match,
                    evidence_id=evidence_id,
                    job_id=job_id,
                    stream_id=obs.stream_id,
                    session_id=obs.session_id,
                    evidence_type=EvidenceType.TLS_OBSERVATION,
                    reference_id=obs.observation_id
                )
                self._add_finding(finding)

    def _normalize_tls_version(self, version: str) -> str:
        """Normalize TLS version string for policy matching."""
        version_upper = version.upper()
        # Map various formats to policy format
        mappings = {
            "TLS_1_3": "TLS1.3",
            "TLS_1_2": "TLS1.2",
            "TLS_1_1": "TLS1.1",
            "TLS_1_0": "TLS1.0",
            "SSL_3_0": "SSLv3",
            "SSL_2_0": "SSLv2",
            "TLSV1.3": "TLS1.3",
            "TLSV1.2": "TLS1.2",
            "TLSV1.1": "TLS1.1",
            "TLSV1.0": "TLS1.0",
            "SSLV3": "SSLv3",
            "SSLV2": "SSLv2",
        }
        return mappings.get(version_upper.replace(" ", "_"), version)

    def analyze_certificates(
        self,
        certificates: list[CertificateObservation],
        evidence_id: str,
        job_id: str
    ) -> None:
        """
        Analyze certificates for security findings.

        Args:
            certificates: Certificate observations
            evidence_id: Evidence identifier
            job_id: Job identifier
        """
        self._certificates_analyzed = len(certificates)

        for cert in certificates:
            self._analyze_certificate(cert, evidence_id, job_id)

    def _analyze_certificate(
        self,
        cert: CertificateObservation,
        evidence_id: str,
        job_id: str
    ) -> None:
        """Analyze single certificate for findings."""
        # Skip certificates that couldn't be parsed
        if cert.parse_status not in ["PARSED", "CERTIFICATE_EXPECTED"]:
            return

        cert_data = {
            "validity": cert.validity.value if cert.validity else "UNKNOWN",
            "key_type": cert.key_type.value if cert.key_type else "",
            "key_size": cert.key_size_bits or 0,
            "signature_algorithm": cert.signature_algorithm or "",
            "is_self_signed": cert.is_self_signed,
        }

        matches = self.rules_engine.evaluate_certificate(
            cert_data,
            cert.stream_id
        )

        for match in matches:
            self._raw_matches += 1
            finding = self._create_finding_from_match(
                match=match,
                evidence_id=evidence_id,
                job_id=job_id,
                stream_id=cert.stream_id,
                session_id=cert.session_id,
                certificate_id=cert.certificate_id,
                evidence_type=EvidenceType.CERTIFICATE,
                reference_id=cert.certificate_id
            )
            self._add_finding(finding)

    def _create_finding_from_match(
        self,
        match: RuleMatch,
        evidence_id: str,
        job_id: str,
        evidence_type: EvidenceType,
        reference_id: str,
        stream_id: Optional[int] = None,
        session_id: Optional[str] = None,
        certificate_id: Optional[str] = None,
    ) -> SecurityFinding:
        """Create finding from rule match."""
        rule = self.rules_engine.get_rule(match.rule_id)
        if not rule:
            raise ValueError(f"Rule {match.rule_id} not found")

        finding_id = f"find_{uuid.uuid4().hex[:12]}"

        evidence = FindingEvidence(
            evidence_type=evidence_type,
            reference_id=reference_id,
            stream_id=stream_id,
            packet_numbers=match.evidence.get("packet_numbers", []),
            observed_value=match.observed_value,
            expected_value=match.expected_value,
            context=match.evidence
        )

        return SecurityFinding(
            finding_id=finding_id,
            rule_id=match.rule_id,
            title=rule.title,
            description=rule.description,
            category=rule.category,
            severity=rule.severity,
            evidence=[evidence],
            evidence_id=evidence_id,
            job_id=job_id,
            session_id=session_id,
            stream_id=stream_id,
            certificate_id=certificate_id,
            confidence="HIGH",
            remediation=rule.remediation,
            affected_streams=[stream_id] if stream_id else []
        )

    def _add_finding(self, finding: SecurityFinding) -> None:
        """
        Add finding with deduplication.

        Duplicate findings (same rule_id) are aggregated
        with occurrence count increased.
        """
        # Check for existing finding with same rule_id
        for existing in self._findings:
            if existing.rule_id == finding.rule_id:
                # Aggregate
                existing.occurrence_count += 1
                existing.evidence.extend(finding.evidence)
                if finding.stream_id and finding.stream_id not in existing.affected_streams:
                    existing.affected_streams.append(finding.stream_id)
                return

        # New finding
        self._findings.append(finding)

    def get_findings(self) -> list[SecurityFinding]:
        """Get all findings."""
        return self._findings

    def get_result(self, evidence_id: str, job_id: str) -> FindingsResult:
        """
        Get complete findings result.

        Args:
            evidence_id: Evidence identifier
            job_id: Job identifier

        Returns:
            FindingsResult with all findings and summary
        """
        findings = self._findings

        # Build summary
        summary = FindingSummary(
            total_findings=len(findings),
            critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in findings if f.severity == Severity.LOW),
            info_count=sum(1 for f in findings if f.severity == Severity.INFO),
            by_category={
                cat.value: sum(1 for f in findings if f.category == cat)
                for cat in RuleCategory
                if sum(1 for f in findings if f.category == cat) > 0
            },
            unique_rules=list(set(f.rule_id for f in findings))
        )

        return FindingsResult(
            evidence_id=evidence_id,
            job_id=job_id,
            findings=findings,
            summary=summary,
            rules_evaluated=len(self.rules_engine.get_all_rules()),
            streams_analyzed=self._streams_analyzed,
            sessions_analyzed=self._sessions_analyzed,
            certificates_analyzed=self._certificates_analyzed,
            raw_matches=self._raw_matches,
            deduplicated_findings=len(findings)
        )
