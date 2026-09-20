"""TLS handshake analyzer service.

Phase 3: Analyzes TLS metadata from email sessions.

IMPORTANT: This service works with Phase 2/3 data.
Full TLS handshake parsing requires TShark SSL fields which
may not be available. Analysis confidence is adjusted accordingly.

Without full TLS field extraction:
- TLS version may be detected from protocol name (TLSv1.2)
- Cipher suite requires explicit extraction (often unavailable)
- Certificate details require dedicated analysis
"""

import logging
import re
import uuid
from typing import Optional

from app.services.tcp.models import TcpStreamData, StreamIntegrity
from app.services.email.models import (
    EmailSecuritySession,
    TransportSecurity,
    AnalysisConfidence,
    AnalysisCoverage,
)
from app.services.tls.models import (
    TlsVersion,
    TlsVersionSecurity,
    CipherStrength,
    KeyExchangeType,
    HandshakeStatus,
    TlsObservation,
    TlsAnalysisResult,
)
from app.services.packet.models import PacketRecord

logger = logging.getLogger(__name__)


class TlsAnalyzer:
    """
    TLS handshake analyzer.

    Extracts TLS metadata from email sessions. Works with
    available Phase 2/3 data.

    Capabilities:
    - TLS version detection from protocol name
    - Version security classification
    - Key exchange inference (from cipher suite if available)
    - Forward secrecy detection

    Limitations:
    - Full cipher suite requires TShark ssl.handshake.ciphersuite
    - Certificate extraction requires separate analysis
    - SNI/ALPN require specific TShark fields
    """

    # TLS version patterns from TShark protocol column
    VERSION_PATTERNS = {
        r"TLSv1\.3": TlsVersion.TLS_1_3,
        r"TLSv1\.2": TlsVersion.TLS_1_2,
        r"TLSv1\.1": TlsVersion.TLS_1_1,
        r"TLSv1\.0": TlsVersion.TLS_1_0,
        r"TLSv1": TlsVersion.TLS_1_0,  # Sometimes reported without minor
        r"TLS": TlsVersion.UNKNOWN,  # Generic TLS
        r"SSLv3": TlsVersion.SSL_3_0,
        r"SSLv2": TlsVersion.SSL_2_0,
        r"SSL": TlsVersion.SSL_3_0,  # Generic SSL
    }

    # Version security mapping
    VERSION_SECURITY = {
        TlsVersion.TLS_1_3: TlsVersionSecurity.MODERN,
        TlsVersion.TLS_1_2: TlsVersionSecurity.ACCEPTABLE,
        TlsVersion.TLS_1_1: TlsVersionSecurity.DEPRECATED,
        TlsVersion.TLS_1_0: TlsVersionSecurity.DEPRECATED,
        TlsVersion.SSL_3_0: TlsVersionSecurity.OBSOLETE,
        TlsVersion.SSL_2_0: TlsVersionSecurity.OBSOLETE,
        TlsVersion.UNKNOWN: TlsVersionSecurity.UNKNOWN,
    }

    # Cipher patterns for key exchange detection
    ECDHE_PATTERN = re.compile(r"ECDHE|ECDH_", re.IGNORECASE)
    DHE_PATTERN = re.compile(r"DHE_|DH_", re.IGNORECASE)
    RSA_KX_PATTERN = re.compile(r"^RSA_|_RSA_AES|_RSA_WITH", re.IGNORECASE)

    # Weak cipher patterns
    WEAK_CIPHERS = re.compile(
        r"RC4|3DES|DES_|NULL|EXPORT|MD5|anon",
        re.IGNORECASE
    )
    STRONG_CIPHERS = re.compile(
        r"AES.*GCM|CHACHA20|AES_256_CBC_SHA256|AES_128_CBC_SHA256",
        re.IGNORECASE
    )

    def __init__(self):
        """Initialize TLS analyzer."""
        self._observations: list[TlsObservation] = []

    def reset(self):
        """Reset analyzer state."""
        self._observations = []

    def analyze_sessions(
        self,
        sessions: list[EmailSecuritySession],
        streams: list[TcpStreamData],
        packets: Optional[list[PacketRecord]] = None
    ) -> None:
        """
        Analyze TLS for email security sessions.

        Args:
            sessions: Email security sessions to analyze
            streams: TCP stream data
            packets: Optional packet records for deeper analysis
        """
        # Create stream lookup
        stream_map = {s.stream_id: s for s in streams}

        for session in sessions:
            if session.tls_detected:
                stream = stream_map.get(session.stream_id)
                observation = self._analyze_session(session, stream, packets)
                if observation:
                    self._observations.append(observation)

    def _analyze_session(
        self,
        session: EmailSecuritySession,
        stream: Optional[TcpStreamData],
        packets: Optional[list[PacketRecord]]
    ) -> Optional[TlsObservation]:
        """
        Analyze TLS for a single session.

        Args:
            session: Email security session
            stream: Associated TCP stream
            packets: Optional packets for this stream

        Returns:
            TlsObservation or None
        """
        obs_id = f"tls_{uuid.uuid4().hex[:12]}"

        # Detect TLS version from packets if available
        tls_version = TlsVersion.UNKNOWN
        if packets:
            stream_packets = [
                p for p in packets
                if p.tcp_stream == session.stream_id
            ]
            tls_version = self._detect_version(stream_packets)
        elif stream and stream.has_tls:
            # Without packets, we know TLS exists but not version
            tls_version = TlsVersion.UNKNOWN

        # Classify version security
        version_security = self.VERSION_SECURITY.get(
            tls_version,
            TlsVersionSecurity.UNKNOWN
        )

        # Determine handshake status
        handshake_status = self._determine_handshake_status(session, stream)

        # Key exchange (requires cipher suite)
        # Without explicit cipher data, mark as unknown
        key_exchange = KeyExchangeType.UNKNOWN
        forward_secrecy = None
        cipher_strength = CipherStrength.UNKNOWN

        # Determine confidence
        confidence = self._determine_confidence(
            session, stream, tls_version, packets
        )

        # Determine coverage
        coverage = self._determine_coverage(session, stream)

        return TlsObservation(
            observation_id=obs_id,
            session_id=session.session_id,
            stream_id=session.stream_id,
            tls_version=tls_version,
            tls_version_security=version_security,
            cipher_suite=None,  # Would require TShark ssl fields
            cipher_strength=cipher_strength,
            key_exchange=key_exchange,
            forward_secrecy=forward_secrecy,
            handshake_status=handshake_status,
            certificate_observed=False,  # Certificate analysis is separate
            confidence=confidence,
            coverage=coverage,
            first_packet=session.first_packet,
            last_packet=session.last_packet,
            handshake_timestamp=session.start_time,
        )

    def _detect_version(
        self,
        packets: list[PacketRecord]
    ) -> TlsVersion:
        """
        Detect TLS version from packet protocols.

        Args:
            packets: Packets to analyze

        Returns:
            Detected TLS version
        """
        for packet in packets:
            if not packet.detected_protocol:
                continue

            proto = packet.detected_protocol.upper()
            for pattern, version in self.VERSION_PATTERNS.items():
                if re.search(pattern, proto, re.IGNORECASE):
                    if version != TlsVersion.UNKNOWN:
                        return version

        return TlsVersion.UNKNOWN

    def _determine_handshake_status(
        self,
        session: EmailSecuritySession,
        stream: Optional[TcpStreamData]
    ) -> HandshakeStatus:
        """Determine TLS handshake status."""
        if not stream:
            return HandshakeStatus.UNKNOWN

        if stream.integrity == StreamIntegrity.COMPLETE:
            # Complete stream with TLS suggests successful handshake
            return HandshakeStatus.SUCCESS
        elif stream.integrity == StreamIntegrity.PARTIAL:
            return HandshakeStatus.PARTIAL
        else:
            return HandshakeStatus.UNKNOWN

    def _determine_confidence(
        self,
        session: EmailSecuritySession,
        stream: Optional[TcpStreamData],
        tls_version: TlsVersion,
        packets: Optional[list[PacketRecord]]
    ) -> AnalysisConfidence:
        """Determine analysis confidence."""
        if tls_version != TlsVersion.UNKNOWN:
            # Version detected from protocol name
            return AnalysisConfidence.HIGH if packets else AnalysisConfidence.MEDIUM
        elif session.tls_detected:
            # TLS present but version unknown
            return AnalysisConfidence.MEDIUM
        else:
            return AnalysisConfidence.LOW

    def _determine_coverage(
        self,
        session: EmailSecuritySession,
        stream: Optional[TcpStreamData]
    ) -> AnalysisCoverage:
        """Determine evidence coverage."""
        if stream and stream.integrity == StreamIntegrity.COMPLETE:
            return AnalysisCoverage.COMPLETE
        elif stream and stream.integrity == StreamIntegrity.PARTIAL:
            return AnalysisCoverage.PARTIAL
        else:
            return AnalysisCoverage.UNKNOWN

    def _classify_cipher(self, cipher_suite: str) -> CipherStrength:
        """Classify cipher suite strength."""
        if not cipher_suite:
            return CipherStrength.UNKNOWN

        if self.WEAK_CIPHERS.search(cipher_suite):
            return CipherStrength.INSECURE
        if self.STRONG_CIPHERS.search(cipher_suite):
            return CipherStrength.STRONG

        # Default to acceptable for unknown modern ciphers
        return CipherStrength.ACCEPTABLE

    def _detect_key_exchange(
        self,
        cipher_suite: str
    ) -> tuple[KeyExchangeType, Optional[bool]]:
        """
        Detect key exchange mechanism from cipher suite.

        Returns:
            Tuple of (KeyExchangeType, forward_secrecy)
        """
        if not cipher_suite:
            return KeyExchangeType.UNKNOWN, None

        if self.ECDHE_PATTERN.search(cipher_suite):
            return KeyExchangeType.ECDHE, True
        if self.DHE_PATTERN.search(cipher_suite):
            return KeyExchangeType.DHE, True
        if self.RSA_KX_PATTERN.search(cipher_suite):
            return KeyExchangeType.RSA, False

        return KeyExchangeType.UNKNOWN, None

    def get_observations(self) -> list[TlsObservation]:
        """Get all TLS observations."""
        return self._observations

    def get_result(self, evidence_id: str, job_id: str) -> TlsAnalysisResult:
        """
        Get complete TLS analysis result.

        Args:
            evidence_id: Evidence identifier
            job_id: Analysis job identifier

        Returns:
            TlsAnalysisResult with all observations
        """
        obs = self._observations

        # Count versions
        tls_1_3 = sum(1 for o in obs if o.tls_version == TlsVersion.TLS_1_3)
        tls_1_2 = sum(1 for o in obs if o.tls_version == TlsVersion.TLS_1_2)
        tls_1_1 = sum(1 for o in obs if o.tls_version == TlsVersion.TLS_1_1)
        tls_1_0 = sum(1 for o in obs if o.tls_version == TlsVersion.TLS_1_0)
        ssl = sum(
            1 for o in obs
            if o.tls_version in (TlsVersion.SSL_2_0, TlsVersion.SSL_3_0)
        )
        unknown = sum(1 for o in obs if o.tls_version == TlsVersion.UNKNOWN)

        # Count deprecated
        deprecated = sum(
            1 for o in obs
            if o.tls_version_security in (
                TlsVersionSecurity.DEPRECATED,
                TlsVersionSecurity.OBSOLETE
            )
        )

        # Count forward secrecy
        fs_yes = sum(1 for o in obs if o.forward_secrecy is True)
        fs_no = sum(1 for o in obs if o.forward_secrecy is False)

        # Handshake status
        success = sum(
            1 for o in obs
            if o.handshake_status == HandshakeStatus.SUCCESS
        )
        failed = sum(
            1 for o in obs
            if o.handshake_status == HandshakeStatus.FAILED
        )
        partial = sum(
            1 for o in obs
            if o.handshake_status == HandshakeStatus.PARTIAL
        )

        return TlsAnalysisResult(
            evidence_id=evidence_id,
            job_id=job_id,
            observations=obs,
            total_observations=len(obs),
            tls_1_3_count=tls_1_3,
            tls_1_2_count=tls_1_2,
            tls_1_1_count=tls_1_1,
            tls_1_0_count=tls_1_0,
            ssl_count=ssl,
            unknown_version_count=unknown,
            deprecated_count=deprecated,
            forward_secrecy_count=fs_yes,
            no_forward_secrecy_count=fs_no,
            successful_handshakes=success,
            failed_handshakes=failed,
            partial_handshakes=partial,
        )
