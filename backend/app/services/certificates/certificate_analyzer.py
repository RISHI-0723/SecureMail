"""X.509 certificate analyzer service.

Phase 3: Analyzes X.509 certificates from TLS sessions.

IMPORTANT: Full certificate parsing requires TShark to extract
certificate data (ssl.handshake.certificate). Without this,
certificate analysis is limited to presence detection.

This analyzer is designed to work when certificate data becomes
available through enhanced Phase 2 extraction or explicit
certificate file provision.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.services.tls.models import TlsObservation
from app.services.email.models import AnalysisConfidence, AnalysisCoverage
from app.services.certificates.models import (
    CertificateValidity,
    KeyType,
    KeyStrength,
    SignatureAlgorithmSecurity,
    CertificateObservation,
    CertificateAnalysisResult,
)

logger = logging.getLogger(__name__)


class CertificateAnalyzer:
    """
    X.509 certificate analyzer.

    Capabilities when certificate data is available:
    - Certificate parsing using Python cryptography
    - Validity analysis relative to handshake time
    - Key type and size analysis
    - Signature algorithm analysis
    - Self-signed detection
    - Chain analysis

    Limitations without certificate data:
    - Can only detect certificate presence
    - Marks analysis as PARTIAL/UNKNOWN
    """

    # RSA key size thresholds
    RSA_STRONG_MIN = 3072
    RSA_ACCEPTABLE_MIN = 2048
    RSA_WEAK_MIN = 1024

    # EC key size thresholds
    EC_STRONG_MIN = 384
    EC_ACCEPTABLE_MIN = 256

    # Weak signature algorithms
    WEAK_SIGNATURES = {"md5", "sha1", "md2", "md4"}
    STRONG_SIGNATURES = {"sha256", "sha384", "sha512", "sha3"}

    def __init__(self):
        """Initialize certificate analyzer."""
        self._certificates: list[CertificateObservation] = []

    def reset(self):
        """Reset analyzer state."""
        self._certificates = []

    def analyze_tls_observations(
        self,
        observations: list[TlsObservation],
        certificate_data: Optional[dict] = None
    ) -> None:
        """
        Analyze certificates from TLS observations.

        Args:
            observations: TLS observations from TlsAnalyzer
            certificate_data: Optional certificate data (for future use)
        """
        for obs in observations:
            cert = self._analyze_observation(obs, certificate_data)
            if cert:
                self._certificates.append(cert)

    def _analyze_observation(
        self,
        observation: TlsObservation,
        certificate_data: Optional[dict]
    ) -> Optional[CertificateObservation]:
        """
        Create certificate observation from TLS observation.

        Without actual certificate data, this creates a placeholder
        indicating certificate presence but limited analysis.
        """
        cert_id = f"cert_{uuid.uuid4().hex[:12]}"

        # Without certificate data, we can only note presence
        # Mark analysis as limited
        cert = CertificateObservation(
            certificate_id=cert_id,
            tls_observation_id=observation.observation_id,
            session_id=observation.session_id,
            stream_id=observation.stream_id,
            validity=CertificateValidity.UNKNOWN,
            validity_reference_time=observation.handshake_timestamp,
            key_type=KeyType.UNKNOWN,
            key_strength=KeyStrength.UNKNOWN,
            signature_algorithm_security=SignatureAlgorithmSecurity.UNKNOWN,
            confidence=AnalysisConfidence.LOW,
            coverage=observation.coverage,
            parse_status="NOT_AVAILABLE",
            parse_error="Certificate data not extracted by Phase 2"
        )

        # Mark that certificate was observed in TLS handshake
        # (We know TLS happened, so certificate was likely exchanged)
        if observation.handshake_status.value in ["SUCCESS", "PARTIAL"]:
            cert.parse_status = "CERTIFICATE_EXPECTED"

        return cert

    def analyze_certificate_bytes(
        self,
        cert_bytes: bytes,
        tls_observation: TlsObservation,
        reference_time: Optional[datetime] = None
    ) -> Optional[CertificateObservation]:
        """
        Analyze certificate from raw bytes.

        This method is for when certificate data is available
        (e.g., from enhanced TShark extraction).

        Args:
            cert_bytes: DER or PEM encoded certificate
            tls_observation: Associated TLS observation
            reference_time: Time for validity comparison

        Returns:
            CertificateObservation with parsed data
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

            cert_id = f"cert_{uuid.uuid4().hex[:12]}"

            # Try DER first, then PEM
            try:
                cert = x509.load_der_x509_certificate(cert_bytes)
            except Exception:
                cert = x509.load_pem_x509_certificate(cert_bytes)

            # Use handshake time or provided reference time
            ref_time = reference_time or tls_observation.handshake_timestamp or datetime.now(timezone.utc)

            # Determine validity
            validity = self._assess_validity(cert, ref_time)

            # Analyze key
            key_type, key_size, key_strength = self._analyze_key(cert)

            # Analyze signature
            sig_algo, sig_security = self._analyze_signature(cert)

            # Check self-signed
            is_self_signed = cert.subject == cert.issuer

            # Extract SANs
            sans = self._extract_sans(cert)

            # Extract key usage
            key_usage, ext_key_usage = self._extract_key_usage(cert)

            return CertificateObservation(
                certificate_id=cert_id,
                tls_observation_id=tls_observation.observation_id,
                session_id=tls_observation.session_id,
                stream_id=tls_observation.stream_id,
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial_number=str(cert.serial_number),
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
                validity=validity,
                validity_reference_time=ref_time,
                key_type=key_type,
                key_size_bits=key_size,
                key_strength=key_strength,
                signature_algorithm=sig_algo,
                signature_algorithm_security=sig_security,
                subject_alt_names=sans,
                key_usage=key_usage,
                extended_key_usage=ext_key_usage,
                is_self_signed=is_self_signed,
                confidence=AnalysisConfidence.HIGH,
                coverage=AnalysisCoverage.COMPLETE,
                parse_status="PARSED",
            )

        except ImportError:
            logger.warning("cryptography library not available for certificate parsing")
            return None
        except Exception as e:
            logger.warning(f"Failed to parse certificate: {e}")
            return CertificateObservation(
                certificate_id=f"cert_{uuid.uuid4().hex[:12]}",
                tls_observation_id=tls_observation.observation_id,
                session_id=tls_observation.session_id,
                stream_id=tls_observation.stream_id,
                confidence=AnalysisConfidence.LOW,
                coverage=AnalysisCoverage.PARTIAL,
                parse_status="PARSE_FAILED",
                parse_error=str(e)[:200]
            )

    def _assess_validity(self, cert, reference_time: datetime) -> CertificateValidity:
        """Assess certificate validity at reference time."""
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            # Ensure reference_time is timezone-aware
            if reference_time.tzinfo is None:
                reference_time = reference_time.replace(tzinfo=timezone.utc)

            if reference_time < not_before:
                return CertificateValidity.NOT_YET_VALID
            elif reference_time > not_after:
                return CertificateValidity.EXPIRED
            else:
                return CertificateValidity.VALID

        except Exception:
            return CertificateValidity.UNKNOWN

    def _analyze_key(self, cert) -> tuple[KeyType, Optional[int], KeyStrength]:
        """Analyze certificate public key."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

            public_key = cert.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size >= self.RSA_STRONG_MIN:
                    strength = KeyStrength.STRONG
                elif key_size >= self.RSA_ACCEPTABLE_MIN:
                    strength = KeyStrength.ACCEPTABLE
                elif key_size >= self.RSA_WEAK_MIN:
                    strength = KeyStrength.WEAK
                else:
                    strength = KeyStrength.INSECURE
                return KeyType.RSA, key_size, strength

            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_size = public_key.curve.key_size
                if key_size >= self.EC_STRONG_MIN:
                    strength = KeyStrength.STRONG
                elif key_size >= self.EC_ACCEPTABLE_MIN:
                    strength = KeyStrength.ACCEPTABLE
                else:
                    strength = KeyStrength.WEAK
                return KeyType.ECDSA, key_size, strength

            elif isinstance(public_key, dsa.DSAPublicKey):
                key_size = public_key.key_size
                strength = KeyStrength.WEAK  # DSA is generally deprecated
                return KeyType.DSA, key_size, strength

            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                return KeyType.ED25519, 256, KeyStrength.STRONG

            elif isinstance(public_key, ed448.Ed448PublicKey):
                return KeyType.ED448, 448, KeyStrength.STRONG

        except Exception:
            pass

        return KeyType.UNKNOWN, None, KeyStrength.UNKNOWN

    def _analyze_signature(
        self,
        cert
    ) -> tuple[Optional[str], SignatureAlgorithmSecurity]:
        """Analyze certificate signature algorithm."""
        try:
            sig_algo = cert.signature_algorithm_oid._name
            sig_algo_lower = sig_algo.lower()

            if any(weak in sig_algo_lower for weak in self.WEAK_SIGNATURES):
                if "md5" in sig_algo_lower or "md2" in sig_algo_lower:
                    return sig_algo, SignatureAlgorithmSecurity.INSECURE
                return sig_algo, SignatureAlgorithmSecurity.WEAK

            if any(strong in sig_algo_lower for strong in self.STRONG_SIGNATURES):
                return sig_algo, SignatureAlgorithmSecurity.STRONG

            return sig_algo, SignatureAlgorithmSecurity.ACCEPTABLE

        except Exception:
            return None, SignatureAlgorithmSecurity.UNKNOWN

    def _extract_sans(self, cert) -> list[str]:
        """Extract Subject Alternative Names."""
        try:
            from cryptography import x509
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return [str(name) for name in ext.value]
        except Exception:
            return []

    def _extract_key_usage(self, cert) -> tuple[list[str], list[str]]:
        """Extract key usage extensions."""
        key_usage = []
        ext_key_usage = []

        try:
            from cryptography import x509

            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
                if ku.value.digital_signature:
                    key_usage.append("digitalSignature")
                if ku.value.key_encipherment:
                    key_usage.append("keyEncipherment")
                if ku.value.key_cert_sign:
                    key_usage.append("keyCertSign")
            except Exception:
                pass

            try:
                eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
                for usage in eku.value:
                    ext_key_usage.append(usage._name)
            except Exception:
                pass

        except Exception:
            pass

        return key_usage, ext_key_usage

    def get_certificates(self) -> list[CertificateObservation]:
        """Get all certificate observations."""
        return self._certificates

    def get_result(self, evidence_id: str, job_id: str) -> CertificateAnalysisResult:
        """
        Get complete certificate analysis result.

        Args:
            evidence_id: Evidence identifier
            job_id: Analysis job identifier

        Returns:
            CertificateAnalysisResult with all observations
        """
        certs = self._certificates

        # Count validity
        valid = sum(1 for c in certs if c.validity == CertificateValidity.VALID)
        expired = sum(1 for c in certs if c.validity == CertificateValidity.EXPIRED)
        not_yet = sum(1 for c in certs if c.validity == CertificateValidity.NOT_YET_VALID)
        unknown_validity = sum(1 for c in certs if c.validity == CertificateValidity.UNKNOWN)

        # Count key strength
        strong_key = sum(1 for c in certs if c.key_strength == KeyStrength.STRONG)
        weak_key = sum(
            1 for c in certs
            if c.key_strength in (KeyStrength.WEAK, KeyStrength.INSECURE)
        )

        # Count signature strength
        strong_sig = sum(
            1 for c in certs
            if c.signature_algorithm_security == SignatureAlgorithmSecurity.STRONG
        )
        weak_sig = sum(
            1 for c in certs
            if c.signature_algorithm_security in (
                SignatureAlgorithmSecurity.WEAK,
                SignatureAlgorithmSecurity.INSECURE
            )
        )

        # Count self-signed
        self_signed = sum(1 for c in certs if c.is_self_signed is True)

        # Parse status
        parsed = sum(1 for c in certs if c.parse_status == "PARSED")
        failed = sum(1 for c in certs if c.parse_status == "PARSE_FAILED")

        return CertificateAnalysisResult(
            evidence_id=evidence_id,
            job_id=job_id,
            certificates=certs,
            total_certificates=len(certs),
            valid_certificates=valid,
            expired_certificates=expired,
            not_yet_valid_certificates=not_yet,
            unknown_validity_certificates=unknown_validity,
            strong_key_certificates=strong_key,
            weak_key_certificates=weak_key,
            strong_signature_certificates=strong_sig,
            weak_signature_certificates=weak_sig,
            self_signed_count=self_signed,
            parsed_count=parsed,
            parse_failed_count=failed,
        )
