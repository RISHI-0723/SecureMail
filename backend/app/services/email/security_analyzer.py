"""Email security analyzer service.

Phase 3: Analyzes email protocol security state.

Implements state machines for:
- SMTP STARTTLS
- IMAP STARTTLS
- POP3 STLS
- Implicit TLS detection

IMPORTANT: This service consumes Phase 2/TCP reconstruction data.
It does NOT re-run TShark or access raw PCAP.
"""

import logging
import uuid
from typing import Optional

from app.services.tcp.models import TcpStreamData, StreamIntegrity
from app.services.email.models import (
    TransportSecurity,
    StarttlsState,
    AnalysisConfidence,
    AnalysisCoverage,
    StarttlsObservation,
    EmailSecuritySession,
    EmailSecurityResult,
)

logger = logging.getLogger(__name__)


class EmailSecurityAnalyzer:
    """
    Analyzer for email protocol security.

    Analyzes TCP streams to determine:
    - Transport security mode (plaintext, STARTTLS, implicit TLS)
    - STARTTLS/STLS negotiation state
    - Security transitions

    Limitations (due to Phase 2 data availability):
    - Full STARTTLS command/response analysis requires payload data
    - Without payload, analysis relies on protocol detection patterns
    - Analysis confidence is adjusted accordingly
    """

    # Implicit TLS ports
    SMTPS_PORTS = {465}
    IMAPS_PORTS = {993}
    POP3S_PORTS = {995}
    IMPLICIT_TLS_PORTS = SMTPS_PORTS | IMAPS_PORTS | POP3S_PORTS

    # Standard plaintext ports
    SMTP_PLAIN_PORTS = {25, 587}
    IMAP_PLAIN_PORTS = {143}
    POP3_PLAIN_PORTS = {110}

    def __init__(self):
        """Initialize the email security analyzer."""
        self._sessions: list[EmailSecuritySession] = []

    def reset(self):
        """Reset analyzer state for new analysis."""
        self._sessions = []

    def analyze_streams(self, streams: list[TcpStreamData]) -> None:
        """
        Analyze TCP streams for email security.

        Args:
            streams: List of reconstructed TCP streams from Phase 3
        """
        for stream in streams:
            if stream.protocol:
                session = self._analyze_stream(stream)
                if session:
                    self._sessions.append(session)

    def _analyze_stream(self, stream: TcpStreamData) -> Optional[EmailSecuritySession]:
        """
        Analyze a single stream for email security.

        Args:
            stream: TCP stream data

        Returns:
            EmailSecuritySession or None if not analyzable
        """
        if not stream.protocol:
            return None

        session_id = f"sess_{uuid.uuid4().hex[:12]}"

        # Determine transport security
        transport_security, starttls_obs, confidence = self._analyze_security(stream)

        # Determine analysis coverage
        coverage = self._assess_coverage(stream)

        session = EmailSecuritySession(
            session_id=session_id,
            stream_id=stream.stream_id,
            protocol=stream.protocol,
            client_ip=stream.client_ip,
            client_port=stream.client_port,
            server_ip=stream.server_ip,
            server_port=stream.server_port,
            transport_security=transport_security,
            starttls=starttls_obs,
            implicit_tls=transport_security == TransportSecurity.IMPLICIT_TLS,
            tls_detected=stream.has_tls,
            plaintext_commands_observed=self._has_plaintext_commands(stream),
            stream_integrity=stream.integrity,
            confidence=confidence,
            coverage=coverage,
            first_packet=stream.first_packet,
            last_packet=stream.last_packet,
            start_time=stream.start_time,
            end_time=stream.end_time,
        )

        return session

    def _analyze_security(
        self,
        stream: TcpStreamData
    ) -> tuple[TransportSecurity, StarttlsObservation, AnalysisConfidence]:
        """
        Analyze transport security for a stream.

        Returns:
            Tuple of (TransportSecurity, StarttlsObservation, AnalysisConfidence)
        """
        # Check for implicit TLS
        if self._is_implicit_tls(stream):
            return (
                TransportSecurity.IMPLICIT_TLS,
                StarttlsObservation(state=StarttlsState.NOT_OBSERVED),
                AnalysisConfidence.HIGH if stream.has_tls else AnalysisConfidence.MEDIUM
            )

        # Check for STARTTLS transition
        if stream.tls_transition_detected:
            starttls_obs = StarttlsObservation(
                state=StarttlsState.TLS_STARTED,
                advertised=True,  # Inferred from successful transition
                requested=True,
                accepted=True,
                tls_transition_observed=True,
            )
            return (
                TransportSecurity.STARTTLS,
                starttls_obs,
                AnalysisConfidence.HIGH
            )

        # Check for TLS without transition detection
        if stream.has_tls:
            # TLS detected but no clear transition - could be STARTTLS or implicit
            server_port = stream.server_port
            if server_port in self.IMPLICIT_TLS_PORTS:
                return (
                    TransportSecurity.IMPLICIT_TLS,
                    StarttlsObservation(state=StarttlsState.NOT_OBSERVED),
                    AnalysisConfidence.MEDIUM
                )
            else:
                # Likely STARTTLS but transition wasn't clearly observed
                starttls_obs = StarttlsObservation(
                    state=StarttlsState.PARTIAL,
                    tls_transition_observed=True,
                )
                return (
                    TransportSecurity.STARTTLS,
                    starttls_obs,
                    AnalysisConfidence.MEDIUM
                )

        # No TLS detected
        if stream.server_port in self.IMPLICIT_TLS_PORTS:
            # Implicit TLS port but no TLS detected - unusual
            return (
                TransportSecurity.UNKNOWN,
                StarttlsObservation(state=StarttlsState.NOT_OBSERVED),
                AnalysisConfidence.LOW
            )

        # Plaintext session
        return (
            TransportSecurity.PLAINTEXT,
            StarttlsObservation(state=StarttlsState.NOT_OBSERVED),
            AnalysisConfidence.HIGH
        )

    def _is_implicit_tls(self, stream: TcpStreamData) -> bool:
        """
        Check if stream uses implicit TLS.

        Implicit TLS is detected when:
        - Server port is a known implicit TLS port (465, 993, 995)
        - TLS is detected in the stream
        - No STARTTLS transition is observed (TLS from start)
        """
        server_port = stream.server_port

        if server_port not in self.IMPLICIT_TLS_PORTS:
            return False

        # Must have TLS traffic
        if not stream.has_tls:
            return False

        # Should NOT have a STARTTLS transition
        # (implicit TLS starts encrypted)
        if stream.tls_transition_detected:
            return False

        return True

    def _has_plaintext_commands(self, stream: TcpStreamData) -> bool:
        """
        Check if plaintext email commands were observed.

        Without payload analysis, we infer from:
        - Email protocol detected without TLS
        - Or mixed protocol/TLS detection
        """
        # If email protocol detected but no TLS, plaintext was used
        if stream.protocol and not stream.has_tls:
            return True

        # If TLS transition detected, plaintext was used before transition
        if stream.tls_transition_detected:
            return True

        return False

    def _assess_coverage(self, stream: TcpStreamData) -> AnalysisCoverage:
        """Assess analysis coverage based on stream integrity."""
        if stream.integrity == StreamIntegrity.COMPLETE:
            return AnalysisCoverage.COMPLETE
        elif stream.integrity == StreamIntegrity.PARTIAL:
            return AnalysisCoverage.PARTIAL
        else:
            return AnalysisCoverage.UNKNOWN

    def get_sessions(self) -> list[EmailSecuritySession]:
        """Get all analyzed sessions."""
        return self._sessions

    def get_result(self, evidence_id: str, job_id: str) -> EmailSecurityResult:
        """
        Get complete email security analysis result.

        Args:
            evidence_id: Evidence identifier
            job_id: Analysis job identifier

        Returns:
            EmailSecurityResult with all session data
        """
        sessions = self._sessions

        # Count by protocol
        smtp_count = sum(1 for s in sessions if s.protocol == "SMTP")
        imap_count = sum(1 for s in sessions if s.protocol == "IMAP")
        pop3_count = sum(1 for s in sessions if s.protocol == "POP3")

        # Count by security
        plaintext = sum(
            1 for s in sessions
            if s.transport_security == TransportSecurity.PLAINTEXT
        )
        starttls = sum(
            1 for s in sessions
            if s.transport_security == TransportSecurity.STARTTLS
        )
        implicit = sum(
            1 for s in sessions
            if s.transport_security == TransportSecurity.IMPLICIT_TLS
        )
        unknown = sum(
            1 for s in sessions
            if s.transport_security == TransportSecurity.UNKNOWN
        )

        # STARTTLS observations
        advertised = sum(1 for s in sessions if s.starttls.advertised)
        requested = sum(1 for s in sessions if s.starttls.requested)
        success = sum(
            1 for s in sessions
            if s.starttls.state == StarttlsState.TLS_STARTED
        )
        failure = sum(
            1 for s in sessions
            if s.starttls.state in (StarttlsState.REJECTED, StarttlsState.FAILED)
        )

        return EmailSecurityResult(
            evidence_id=evidence_id,
            job_id=job_id,
            sessions=sessions,
            total_sessions=len(sessions),
            smtp_sessions=smtp_count,
            imap_sessions=imap_count,
            pop3_sessions=pop3_count,
            plaintext_sessions=plaintext,
            starttls_sessions=starttls,
            implicit_tls_sessions=implicit,
            unknown_security_sessions=unknown,
            starttls_advertised_count=advertised,
            starttls_requested_count=requested,
            starttls_success_count=success,
            starttls_failure_count=failure,
        )
