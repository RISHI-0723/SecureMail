"""X.509 certificate analysis models.

Phase 3: Data structures for certificate intelligence.

IMPORTANT: Certificate validity should be compared against
the handshake timestamp, not just current time.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from app.services.email.models import AnalysisConfidence, AnalysisCoverage


class CertificateValidity(str, Enum):
    """Certificate validity status."""
    VALID = "VALID"                 # Valid at observation time
    EXPIRED = "EXPIRED"             # Expired at observation time
    NOT_YET_VALID = "NOT_YET_VALID" # Not yet valid at observation time
    UNKNOWN = "UNKNOWN"             # Cannot determine


class KeyType(str, Enum):
    """Public key algorithm type."""
    RSA = "RSA"
    ECDSA = "ECDSA"
    DSA = "DSA"
    ED25519 = "ED25519"
    ED448 = "ED448"
    UNKNOWN = "UNKNOWN"


class KeyStrength(str, Enum):
    """Public key strength classification."""
    STRONG = "STRONG"       # RSA >= 2048, EC >= 256
    ACCEPTABLE = "ACCEPTABLE"  # RSA 2048, EC 256
    WEAK = "WEAK"           # RSA < 2048, EC < 256
    INSECURE = "INSECURE"   # RSA < 1024
    UNKNOWN = "UNKNOWN"


class SignatureAlgorithmSecurity(str, Enum):
    """Signature algorithm security classification."""
    STRONG = "STRONG"       # SHA-256+, ECDSA
    ACCEPTABLE = "ACCEPTABLE"  # SHA-256
    WEAK = "WEAK"           # SHA-1
    INSECURE = "INSECURE"   # MD5
    UNKNOWN = "UNKNOWN"


class CertificateObservation(BaseModel):
    """
    X.509 certificate observation.

    Contains parsed certificate metadata from TLS handshake.

    IMPORTANT: Certificate validity is assessed relative to
    the handshake observation time, not current time.
    """
    certificate_id: str = Field(description="Unique certificate identifier")
    tls_observation_id: str = Field(description="Associated TLS observation ID")
    session_id: str = Field(description="Associated email session ID")
    stream_id: int = Field(description="TCP stream ID")

    # Certificate subject/issuer
    subject: Optional[str] = Field(default=None, description="Certificate subject")
    issuer: Optional[str] = Field(default=None, description="Certificate issuer")
    serial_number: Optional[str] = Field(default=None, description="Serial number")

    # Validity
    not_before: Optional[datetime] = Field(
        default=None,
        description="Certificate not valid before"
    )
    not_after: Optional[datetime] = Field(
        default=None,
        description="Certificate not valid after"
    )
    validity: CertificateValidity = Field(
        default=CertificateValidity.UNKNOWN,
        description="Validity at observation time"
    )
    validity_reference_time: Optional[datetime] = Field(
        default=None,
        description="Time used for validity comparison"
    )

    # Public key
    key_type: KeyType = Field(
        default=KeyType.UNKNOWN,
        description="Public key algorithm"
    )
    key_size_bits: Optional[int] = Field(
        default=None,
        description="Public key size in bits"
    )
    key_strength: KeyStrength = Field(
        default=KeyStrength.UNKNOWN,
        description="Key strength classification"
    )

    # Signature
    signature_algorithm: Optional[str] = Field(
        default=None,
        description="Certificate signature algorithm"
    )
    signature_algorithm_security: SignatureAlgorithmSecurity = Field(
        default=SignatureAlgorithmSecurity.UNKNOWN,
        description="Signature algorithm security"
    )

    # Extensions
    subject_alt_names: list[str] = Field(
        default_factory=list,
        description="Subject Alternative Names"
    )
    key_usage: list[str] = Field(
        default_factory=list,
        description="Key usage extensions"
    )
    extended_key_usage: list[str] = Field(
        default_factory=list,
        description="Extended key usage"
    )

    # Chain information
    is_self_signed: Optional[bool] = Field(
        default=None,
        description="Is certificate self-signed"
    )
    chain_position: Optional[int] = Field(
        default=None,
        description="Position in certificate chain (0 = leaf)"
    )
    chain_complete: Optional[bool] = Field(
        default=None,
        description="Is certificate chain complete"
    )

    # Analysis metadata
    confidence: AnalysisConfidence = Field(
        default=AnalysisConfidence.UNKNOWN,
        description="Analysis confidence"
    )
    coverage: AnalysisCoverage = Field(
        default=AnalysisCoverage.UNKNOWN,
        description="Evidence coverage"
    )
    parse_status: str = Field(
        default="NOT_PARSED",
        description="Certificate parse status"
    )
    parse_error: Optional[str] = Field(
        default=None,
        description="Parse error if failed"
    )


class CertificateAnalysisResult(BaseModel):
    """Result of certificate analysis for an evidence file."""
    evidence_id: str = Field(description="Evidence identifier")
    job_id: str = Field(description="Analysis job identifier")

    # Certificate observations
    certificates: list[CertificateObservation] = Field(
        default_factory=list,
        description="Certificate observations"
    )
    total_certificates: int = Field(default=0)

    # Validity summary
    valid_certificates: int = Field(default=0)
    expired_certificates: int = Field(default=0)
    not_yet_valid_certificates: int = Field(default=0)
    unknown_validity_certificates: int = Field(default=0)

    # Key strength summary
    strong_key_certificates: int = Field(default=0)
    weak_key_certificates: int = Field(default=0)

    # Signature summary
    strong_signature_certificates: int = Field(default=0)
    weak_signature_certificates: int = Field(default=0)

    # Self-signed
    self_signed_count: int = Field(default=0)

    # Parse status
    parsed_count: int = Field(default=0)
    parse_failed_count: int = Field(default=0)

    # Error information
    error_code: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
