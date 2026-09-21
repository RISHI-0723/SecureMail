"""Feature Engineering - Phase 4.

Extracts ML features from Phase 3 security analysis data.
Features are designed for:
1. Risk classification (supervised)
2. Anomaly detection (unsupervised)

IMPORTANT: Features are derived from deterministic Phase 3 data.
ML enhances but does not replace deterministic analysis.
"""
import logging
from typing import Optional
from datetime import datetime, timezone

from app.services.findings.models import SecurityFinding
from app.services.tls.models import TlsObservation, TlsVersion, TlsVersionSecurity
from app.services.certificates.models import (
    CertificateObservation,
    CertificateValidity,
    KeyType,
    KeyStrength,
)
from app.services.email.models import (
    EmailSecuritySession,
    TransportSecurity,
    StarttlsState,
)
from app.services.crypto.rules import Severity
from app.services.ml.models import FeatureVector

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Extracts ML features from security analysis data.

    Feature categories:
    1. TLS Features: version, cipher, key exchange
    2. Certificate Features: validity, strength, chain
    3. Protocol Features: STARTTLS, implicit TLS
    4. Finding Features: counts, severities
    5. Risk Features: scores, patterns
    """

    # TLS version scores (0 = bad, 1 = good)
    TLS_VERSION_SCORES = {
        TlsVersion.TLS_1_3: 1.0,
        TlsVersion.TLS_1_2: 0.8,
        TlsVersion.TLS_1_1: 0.3,
        TlsVersion.TLS_1_0: 0.2,
        TlsVersion.SSL_3_0: 0.0,
        TlsVersion.SSL_2_0: 0.0,
    }

    # Severity scores for max severity calculation
    SEVERITY_SCORES = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.2,
        Severity.INFO: 0.0,
    }

    # Key strength scores
    KEY_STRENGTH_SCORES = {
        KeyStrength.STRONG: 1.0,
        KeyStrength.ACCEPTABLE: 0.7,
        KeyStrength.WEAK: 0.3,
        KeyStrength.INSECURE: 0.0,
        KeyStrength.UNKNOWN: 0.5,
    }

    def __init__(self):
        """Initialize the feature engineer."""
        self._feature_vectors: list[FeatureVector] = []

    def extract_session_features(
        self,
        session: EmailSecuritySession,
        tls_obs: Optional[TlsObservation] = None,
        cert_obs: Optional[CertificateObservation] = None,
        findings: Optional[list[SecurityFinding]] = None,
    ) -> FeatureVector:
        """
        Extract features for a single email session.

        Args:
            session: Email security session
            tls_obs: TLS observation for this session
            cert_obs: Certificate observation for this session
            findings: Security findings for this session

        Returns:
            Feature vector for the session
        """
        findings = findings or []

        # Initialize feature vector
        fv = FeatureVector(
            target_type="session",
            target_id=session.session_id,
        )

        # Protocol features
        fv.uses_starttls = session.starttls.state in [
            StarttlsState.REQUESTED,
            StarttlsState.TLS_STARTED,
        ]
        fv.starttls_success = session.starttls.state == StarttlsState.TLS_STARTED
        fv.uses_implicit_tls = session.transport_security == TransportSecurity.IMPLICIT_TLS
        fv.is_plaintext = session.transport_security == TransportSecurity.PLAINTEXT

        # TLS features
        if tls_obs:
            fv.tls_version_score = self._get_tls_version_score(tls_obs.tls_version)
            fv.cipher_strength_score = self._get_cipher_score(tls_obs.cipher_suite)
            fv.key_exchange_score = self._get_key_exchange_score(tls_obs.key_exchange)
            fv.forward_secrecy = tls_obs.forward_secrecy or False

        # Certificate features
        if cert_obs:
            fv.cert_validity_days = self._get_cert_validity_days(cert_obs)
            fv.cert_key_strength = self._get_key_strength_score(cert_obs.key_strength)
            fv.cert_is_self_signed = cert_obs.is_self_signed or False
            fv.cert_chain_length = cert_obs.chain_position or 0

        # Finding features
        fv.finding_count = len(findings)
        fv.critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        fv.high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        fv.medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        fv.low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        # Risk features
        fv.max_severity_score = self._get_max_severity_score(findings)
        fv.risk_score = self._calculate_risk_score(findings)

        # Composite security score
        fv.security_score = self._calculate_security_score(fv)

        self._feature_vectors.append(fv)
        return fv

    def extract_all_features(
        self,
        sessions: list[EmailSecuritySession],
        tls_observations: list[TlsObservation],
        certificates: list[CertificateObservation],
        findings: list[SecurityFinding],
    ) -> list[FeatureVector]:
        """
        Extract features for all sessions.

        Args:
            sessions: All email security sessions
            tls_observations: All TLS observations
            certificates: All certificate observations
            findings: All security findings

        Returns:
            List of feature vectors
        """
        self._feature_vectors = []

        # Create lookup maps
        tls_by_session = {obs.session_id: obs for obs in tls_observations if obs.session_id}
        cert_by_session = {cert.session_id: cert for cert in certificates if cert.session_id}

        # Group findings by session
        findings_by_session: dict[str, list[SecurityFinding]] = {}
        for f in findings:
            if f.session_id:
                if f.session_id not in findings_by_session:
                    findings_by_session[f.session_id] = []
                findings_by_session[f.session_id].append(f)

        # Extract features for each session
        for session in sessions:
            tls_obs = tls_by_session.get(session.session_id)
            cert_obs = cert_by_session.get(session.session_id)
            session_findings = findings_by_session.get(session.session_id, [])

            self.extract_session_features(
                session=session,
                tls_obs=tls_obs,
                cert_obs=cert_obs,
                findings=session_findings,
            )

        logger.info(f"Extracted {len(self._feature_vectors)} feature vectors")
        return self._feature_vectors

    def _get_tls_version_score(
        self,
        version: Optional[TlsVersion]
    ) -> float:
        """Get TLS version score."""
        if version is None:
            return 0.0
        return self.TLS_VERSION_SCORES.get(version, 0.5)

    def _get_cipher_score(
        self,
        cipher_suite: Optional[str]
    ) -> float:
        """Get cipher suite score based on strength indicators."""
        if not cipher_suite:
            return 0.0

        cipher_upper = cipher_suite.upper()

        # Strong ciphers
        if "CHACHA20" in cipher_upper or "GCM" in cipher_upper:
            return 1.0

        # Good ciphers
        if "AES256" in cipher_upper or "AES_256" in cipher_upper:
            return 0.9

        if "AES128" in cipher_upper or "AES_128" in cipher_upper:
            return 0.8

        # Weak ciphers
        if "CBC" in cipher_upper:
            return 0.5

        if "3DES" in cipher_upper or "DES" in cipher_upper:
            return 0.2

        if "RC4" in cipher_upper or "NULL" in cipher_upper:
            return 0.0

        return 0.5  # Unknown

    def _get_key_exchange_score(
        self,
        key_exchange: Optional[str]
    ) -> float:
        """Get key exchange score."""
        if not key_exchange:
            return 0.0

        kex_upper = key_exchange.upper()

        # Strong key exchange
        if "ECDHE" in kex_upper or "X25519" in kex_upper:
            return 1.0

        if "DHE" in kex_upper:
            return 0.8

        # Static key exchange (no forward secrecy)
        if "ECDH" in kex_upper and "ECDHE" not in kex_upper:
            return 0.5

        if "RSA" in kex_upper:
            return 0.3

        return 0.5

    def _get_cert_validity_days(
        self,
        cert: CertificateObservation
    ) -> float:
        """Get certificate validity in days."""
        if cert.validity == CertificateValidity.EXPIRED:
            return -30.0  # Expired

        if cert.validity == CertificateValidity.NOT_YET_VALID:
            return -1.0

        if cert.not_after:
            try:
                # Parse the date
                if isinstance(cert.not_after, datetime):
                    not_after = cert.not_after
                else:
                    not_after = datetime.fromisoformat(str(cert.not_after).replace('Z', '+00:00'))

                now = datetime.now(timezone.utc)
                delta = not_after - now
                return float(delta.days)
            except (ValueError, TypeError):
                pass

        return 365.0  # Default to 1 year if unknown

    def _get_key_strength_score(
        self,
        strength: Optional[KeyStrength]
    ) -> float:
        """Get key strength score."""
        if strength is None:
            return 0.5
        return self.KEY_STRENGTH_SCORES.get(strength, 0.5)

    def _get_max_severity_score(
        self,
        findings: list[SecurityFinding]
    ) -> float:
        """Get the maximum severity score from findings."""
        if not findings:
            return 0.0

        max_score = 0.0
        for f in findings:
            score = self.SEVERITY_SCORES.get(f.severity, 0.0)
            if score > max_score:
                max_score = score

        return max_score

    def _calculate_risk_score(
        self,
        findings: list[SecurityFinding]
    ) -> float:
        """Calculate risk score from findings."""
        if not findings:
            return 0.0

        # Weighted sum
        score = 0.0
        for f in findings:
            severity_weight = self.SEVERITY_SCORES.get(f.severity, 0.0)
            score += severity_weight * 25 * f.occurrence_count

        return min(100.0, score)

    def _calculate_security_score(
        self,
        fv: FeatureVector
    ) -> float:
        """Calculate composite security score (0-100)."""
        score = 100.0

        # TLS penalty
        tls_penalty = (1.0 - fv.tls_version_score) * 20
        cipher_penalty = (1.0 - fv.cipher_strength_score) * 15
        kex_penalty = (1.0 - fv.key_exchange_score) * 10

        if not fv.forward_secrecy:
            kex_penalty += 10

        # Certificate penalty
        cert_penalty = 0.0
        if fv.cert_is_self_signed:
            cert_penalty += 15
        if fv.cert_validity_days < 0:
            cert_penalty += 20
        elif fv.cert_validity_days < 30:
            cert_penalty += 10
        cert_penalty += (1.0 - fv.cert_key_strength) * 10

        # Protocol penalty
        protocol_penalty = 0.0
        if fv.is_plaintext:
            protocol_penalty = 30

        # Finding penalty
        finding_penalty = (
            fv.critical_count * 15 +
            fv.high_count * 10 +
            fv.medium_count * 5 +
            fv.low_count * 2
        )

        total_penalty = (
            tls_penalty +
            cipher_penalty +
            kex_penalty +
            cert_penalty +
            protocol_penalty +
            finding_penalty
        )

        return max(0.0, score - total_penalty)

    def get_feature_vectors(self) -> list[FeatureVector]:
        """Get all extracted feature vectors."""
        return self._feature_vectors

    def get_feature_matrix(self) -> list[list[float]]:
        """Get feature matrix as 2D array for ML models."""
        return [fv.to_array() for fv in self._feature_vectors]

    def get_feature_names(self) -> list[str]:
        """Get feature names."""
        return FeatureVector.feature_names()
