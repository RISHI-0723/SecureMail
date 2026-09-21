"""Correlation Engine - Phase 4.

Identifies patterns and correlations across sessions, findings,
and certificates. Correlations help identify systemic issues
that affect multiple parts of the infrastructure.

IMPORTANT: Correlations are derived from Phase 3 findings and
do not modify or replace deterministic security analysis.
"""
import logging
from typing import Optional
from collections import defaultdict

from app.services.findings.models import SecurityFinding
from app.services.tls.models import TlsObservation
from app.services.certificates.models import CertificateObservation
from app.services.email.models import EmailSecuritySession
from app.services.crypto.rules import Severity
from app.services.intelligence.models import (
    CorrelationData,
    CorrelationType,
)

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Identifies security correlations across the evidence.

    Correlation types:
    - SAME_CERTIFICATE: Multiple sessions using same certificate
    - SAME_CIPHER_WEAKNESS: Same weak cipher across sessions
    - SAME_TLS_VERSION: Deprecated TLS version across sessions
    - SAME_KEY_EXCHANGE: Same weak key exchange
    - SAME_SERVER: Multiple issues on same server
    - TEMPORAL_PATTERN: Time-based patterns
    - RISK_ESCALATION: Combined risks that escalate severity
    """

    # Minimum occurrences to create a correlation
    MIN_OCCURRENCES = 2

    def __init__(self):
        """Initialize the correlation engine."""
        self._correlations: list[CorrelationData] = []

    def find_correlations(
        self,
        findings: list[SecurityFinding],
        tls_observations: list[TlsObservation],
        certificates: list[CertificateObservation],
        sessions: list[EmailSecuritySession],
    ) -> list[CorrelationData]:
        """
        Find all correlations in the analyzed data.

        Args:
            findings: Phase 3 security findings
            tls_observations: TLS observation data
            certificates: Certificate observations
            sessions: Email security sessions

        Returns:
            List of correlation data
        """
        self._correlations = []

        # Find different types of correlations
        self._find_certificate_correlations(findings, certificates)
        self._find_cipher_correlations(findings, tls_observations)
        self._find_tls_version_correlations(findings, tls_observations)
        self._find_key_exchange_correlations(findings, tls_observations)
        self._find_server_correlations(findings, sessions)
        self._find_risk_escalation_patterns(findings)

        logger.info(f"Found {len(self._correlations)} correlations")
        return self._correlations

    def _find_certificate_correlations(
        self,
        findings: list[SecurityFinding],
        certificates: list[CertificateObservation],
    ) -> None:
        """Find correlations for same certificates used across sessions."""
        # Group certificates by fingerprint/serial
        cert_map: dict[str, list[CertificateObservation]] = defaultdict(list)
        for cert in certificates:
            key = cert.serial_number or cert.certificate_id
            if key:
                cert_map[key].append(cert)

        # Find certificates used in multiple streams
        for cert_key, certs in cert_map.items():
            if len(certs) >= self.MIN_OCCURRENCES:
                # Find related findings
                related_findings = [
                    f for f in findings
                    if f.certificate_id in [c.certificate_id for c in certs]
                ]

                if not related_findings:
                    continue

                # Determine combined severity
                severities = [f.severity for f in related_findings]
                combined_severity = self._get_highest_severity(severities)

                streams = list(set(c.stream_id for c in certs if c.stream_id))
                sessions = list(set(c.session_id for c in certs if c.session_id))

                correlation = CorrelationData(
                    correlation_type=CorrelationType.SAME_CERTIFICATE,
                    strength=min(1.0, len(certs) / 5.0),  # Scale by count
                    confidence="HIGH",
                    title=f"Same certificate used across {len(certs)} sessions",
                    description=(
                        f"Certificate {cert_key[:20]}... is used across multiple "
                        f"sessions with {len(related_findings)} related findings."
                    ),
                    linked_findings=[f.finding_id for f in related_findings],
                    linked_certificates=[c.certificate_id for c in certs],
                    linked_streams=streams,
                    linked_sessions=sessions,
                    common_attribute="certificate",
                    common_value=cert_key,
                    combined_severity=combined_severity.value if combined_severity else None,
                    combined_risk_score=self._calculate_combined_risk(related_findings),
                )
                self._correlations.append(correlation)

    def _find_cipher_correlations(
        self,
        findings: list[SecurityFinding],
        tls_observations: list[TlsObservation],
    ) -> None:
        """Find correlations for same weak ciphers across sessions."""
        # Group by cipher suite
        cipher_map: dict[str, list[TlsObservation]] = defaultdict(list)
        for obs in tls_observations:
            if obs.cipher_suite:
                cipher_map[obs.cipher_suite].append(obs)

        # Find weak ciphers used multiple times
        cipher_findings = [
            f for f in findings
            if "CIPHER" in f.rule_id.upper() or "cipher" in f.title.lower()
        ]

        for cipher, obs_list in cipher_map.items():
            if len(obs_list) >= self.MIN_OCCURRENCES:
                # Check if this cipher has associated findings
                related_findings = [
                    f for f in cipher_findings
                    if f.stream_id in [o.stream_id for o in obs_list]
                ]

                if not related_findings:
                    continue

                streams = list(set(o.stream_id for o in obs_list if o.stream_id))
                sessions = list(set(o.session_id for o in obs_list if o.session_id))

                correlation = CorrelationData(
                    correlation_type=CorrelationType.SAME_CIPHER_WEAKNESS,
                    strength=min(1.0, len(obs_list) / 5.0),
                    confidence="HIGH",
                    title=f"Weak cipher suite used across {len(obs_list)} sessions",
                    description=(
                        f"Cipher suite {cipher} is used across multiple sessions "
                        f"and has security concerns."
                    ),
                    linked_findings=[f.finding_id for f in related_findings],
                    linked_streams=streams,
                    linked_sessions=sessions,
                    common_attribute="cipher_suite",
                    common_value=cipher,
                    combined_severity=self._get_highest_severity(
                        [f.severity for f in related_findings]
                    ).value if related_findings else None,
                )
                self._correlations.append(correlation)

    def _find_tls_version_correlations(
        self,
        findings: list[SecurityFinding],
        tls_observations: list[TlsObservation],
    ) -> None:
        """Find correlations for deprecated TLS versions."""
        # Group by TLS version
        version_map: dict[str, list[TlsObservation]] = defaultdict(list)
        for obs in tls_observations:
            if obs.tls_version:
                version = obs.tls_version.value if hasattr(obs.tls_version, 'value') else str(obs.tls_version)
                version_map[version].append(obs)

        # Find TLS version findings
        tls_findings = [
            f for f in findings
            if "TLS" in f.rule_id.upper() or "VERSION" in f.rule_id.upper()
        ]

        for version, obs_list in version_map.items():
            if len(obs_list) >= self.MIN_OCCURRENCES:
                related_findings = [
                    f for f in tls_findings
                    if f.stream_id in [o.stream_id for o in obs_list]
                ]

                if not related_findings:
                    continue

                streams = list(set(o.stream_id for o in obs_list if o.stream_id))

                correlation = CorrelationData(
                    correlation_type=CorrelationType.SAME_TLS_VERSION,
                    strength=min(1.0, len(obs_list) / 5.0),
                    confidence="HIGH",
                    title=f"TLS version {version} used across {len(obs_list)} sessions",
                    description=(
                        f"TLS version {version} is used across multiple sessions. "
                        f"Consider upgrading to TLS 1.3."
                    ),
                    linked_findings=[f.finding_id for f in related_findings],
                    linked_streams=streams,
                    common_attribute="tls_version",
                    common_value=version,
                    combined_severity=self._get_highest_severity(
                        [f.severity for f in related_findings]
                    ).value if related_findings else None,
                )
                self._correlations.append(correlation)

    def _find_key_exchange_correlations(
        self,
        findings: list[SecurityFinding],
        tls_observations: list[TlsObservation],
    ) -> None:
        """Find correlations for weak key exchange methods."""
        # Group by key exchange
        kex_map: dict[str, list[TlsObservation]] = defaultdict(list)
        for obs in tls_observations:
            if obs.key_exchange:
                kex_map[obs.key_exchange].append(obs)

        # Find key exchange findings
        kex_findings = [
            f for f in findings
            if "KEY_EXCHANGE" in f.rule_id.upper() or "FORWARD_SECRECY" in f.rule_id.upper()
        ]

        for kex, obs_list in kex_map.items():
            if len(obs_list) >= self.MIN_OCCURRENCES:
                related_findings = [
                    f for f in kex_findings
                    if f.stream_id in [o.stream_id for o in obs_list]
                ]

                if not related_findings:
                    continue

                streams = list(set(o.stream_id for o in obs_list if o.stream_id))

                correlation = CorrelationData(
                    correlation_type=CorrelationType.SAME_KEY_EXCHANGE,
                    strength=min(1.0, len(obs_list) / 5.0),
                    confidence="HIGH",
                    title=f"Key exchange {kex} used across {len(obs_list)} sessions",
                    description=(
                        f"Key exchange method {kex} is used across multiple sessions "
                        f"and may lack forward secrecy."
                    ),
                    linked_findings=[f.finding_id for f in related_findings],
                    linked_streams=streams,
                    common_attribute="key_exchange",
                    common_value=kex,
                    combined_severity=self._get_highest_severity(
                        [f.severity for f in related_findings]
                    ).value if related_findings else None,
                )
                self._correlations.append(correlation)

    def _find_server_correlations(
        self,
        findings: list[SecurityFinding],
        sessions: list[EmailSecuritySession],
    ) -> None:
        """Find correlations for multiple issues on same server."""
        # Group findings by stream (proxy for server)
        stream_findings: dict[int, list[SecurityFinding]] = defaultdict(list)
        for f in findings:
            if f.stream_id:
                stream_findings[f.stream_id].append(f)

        # Find streams with multiple findings
        for stream_id, stream_f in stream_findings.items():
            if len(stream_f) >= self.MIN_OCCURRENCES:
                # Get unique rule categories
                categories = set(f.category for f in stream_f)

                if len(categories) >= 2:  # Multiple types of issues
                    correlation = CorrelationData(
                        correlation_type=CorrelationType.SAME_SERVER,
                        strength=min(1.0, len(stream_f) / 10.0),
                        confidence="HIGH",
                        title=f"Multiple security issues on stream {stream_id}",
                        description=(
                            f"Stream {stream_id} has {len(stream_f)} security findings "
                            f"across {len(categories)} categories."
                        ),
                        linked_findings=[f.finding_id for f in stream_f],
                        linked_streams=[stream_id],
                        common_attribute="stream_id",
                        common_value=str(stream_id),
                        combined_severity=self._get_highest_severity(
                            [f.severity for f in stream_f]
                        ).value,
                        combined_risk_score=self._calculate_combined_risk(stream_f),
                    )
                    self._correlations.append(correlation)

    def _find_risk_escalation_patterns(
        self,
        findings: list[SecurityFinding],
    ) -> None:
        """Find patterns where combined findings escalate risk."""
        # Look for dangerous combinations
        critical_or_high = [
            f for f in findings
            if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]

        if len(critical_or_high) >= 3:
            correlation = CorrelationData(
                correlation_type=CorrelationType.RISK_ESCALATION,
                strength=min(1.0, len(critical_or_high) / 10.0),
                confidence="HIGH",
                title=f"Risk escalation: {len(critical_or_high)} high-severity findings",
                description=(
                    f"The combination of {len(critical_or_high)} critical or high "
                    f"severity findings represents a significant risk escalation."
                ),
                linked_findings=[f.finding_id for f in critical_or_high],
                linked_streams=list(set(
                    f.stream_id for f in critical_or_high if f.stream_id
                )),
                combined_severity="CRITICAL",
                combined_risk_score=self._calculate_combined_risk(critical_or_high),
            )
            self._correlations.append(correlation)

    def _get_highest_severity(
        self,
        severities: list[Severity]
    ) -> Optional[Severity]:
        """Get the highest severity from a list."""
        if not severities:
            return None

        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        for sev in severity_order:
            if sev in severities:
                return sev

        return severities[0]

    def _calculate_combined_risk(
        self,
        findings: list[SecurityFinding]
    ) -> float:
        """Calculate combined risk score from multiple findings."""
        if not findings:
            return 0.0

        # Base score per severity
        severity_scores = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }

        total = sum(
            severity_scores.get(f.severity, 1) * f.occurrence_count
            for f in findings
        )

        # Cap at 100
        return min(100.0, total)

    def get_correlations(self) -> list[CorrelationData]:
        """Get all found correlations."""
        return self._correlations
