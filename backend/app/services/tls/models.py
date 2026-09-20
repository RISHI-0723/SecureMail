"""TLS analysis models.

Phase 3: Data structures for TLS handshake intelligence.

Supports TLS 1.0, 1.1, 1.2, 1.3 and legacy SSL versions.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from app.services.email.models import AnalysisConfidence, AnalysisCoverage


class TlsVersion(str, Enum):
    """TLS/SSL protocol versions."""
    SSL_2_0 = "SSLv2"
    SSL_3_0 = "SSLv3"
    TLS_1_0 = "TLS1.0"
    TLS_1_1 = "TLS1.1"
    TLS_1_2 = "TLS1.2"
    TLS_1_3 = "TLS1.3"
    UNKNOWN = "UNKNOWN"


class TlsVersionSecurity(str, Enum):
    """Security classification for TLS versions."""
    OBSOLETE = "OBSOLETE"       # SSLv2, SSLv3
    DEPRECATED = "DEPRECATED"    # TLS 1.0, TLS 1.1
    ACCEPTABLE = "ACCEPTABLE"   # TLS 1.2 (with good ciphers)
    MODERN = "MODERN"           # TLS 1.3
    UNKNOWN = "UNKNOWN"


class CipherStrength(str, Enum):
    """Cipher suite strength classification."""
    STRONG = "STRONG"           # Modern AEAD ciphers
    ACCEPTABLE = "ACCEPTABLE"   # AES-CBC with SHA-256+
    WEAK = "WEAK"               # AES-CBC with SHA-1, 3DES
    INSECURE = "INSECURE"       # RC4, NULL, EXPORT
    UNKNOWN = "UNKNOWN"


class KeyExchangeType(str, Enum):
    """Key exchange mechanism type."""
    ECDHE = "ECDHE"             # Forward secrecy
    DHE = "DHE"                 # Forward secrecy
    RSA = "RSA"                 # Static RSA (no FS)
    PSK = "PSK"                 # Pre-shared key
    UNKNOWN = "UNKNOWN"


class HandshakeStatus(str, Enum):
    """TLS handshake completion status."""
    SUCCESS = "SUCCESS"         # Completed successfully
    FAILED = "FAILED"           # Failed (alert observed)
    PARTIAL = "PARTIAL"         # Incomplete (capture issue)
    UNKNOWN = "UNKNOWN"


class TlsObservation(BaseModel):
    """
    TLS handshake observation for a session.

    Contains extracted TLS metadata where observable.
    Fields may be None if not captured or extractable.
    """
    observation_id: str = Field(description="Unique observation identifier")
    session_id: str = Field(description="Associated email security session ID")
    stream_id: int = Field(description="TCP stream ID")

    # TLS version
    tls_version: TlsVersion = Field(
        default=TlsVersion.UNKNOWN,
        description="Observed TLS version"
    )
    tls_version_security: TlsVersionSecurity = Field(
        default=TlsVersionSecurity.UNKNOWN,
        description="TLS version security classification"
    )

    # Cipher suite
    cipher_suite: Optional[str] = Field(
        default=None,
        description="Negotiated cipher suite"
    )
    cipher_strength: CipherStrength = Field(
        default=CipherStrength.UNKNOWN,
        description="Cipher strength classification"
    )

    # Key exchange
    key_exchange: KeyExchangeType = Field(
        default=KeyExchangeType.UNKNOWN,
        description="Key exchange mechanism"
    )
    forward_secrecy: Optional[bool] = Field(
        default=None,
        description="Forward secrecy supported (None if unknown)"
    )

    # Handshake details
    handshake_status: HandshakeStatus = Field(
        default=HandshakeStatus.UNKNOWN,
        description="Handshake completion status"
    )
    sni: Optional[str] = Field(
        default=None,
        description="Server Name Indication (SNI)"
    )
    alpn: Optional[list[str]] = Field(
        default=None,
        description="Application Layer Protocol Negotiation"
    )

    # Certificate reference (linked to CertificateObservation)
    certificate_observed: bool = Field(
        default=False,
        description="Certificate was observed in handshake"
    )
    certificate_id: Optional[str] = Field(
        default=None,
        description="Associated certificate observation ID"
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

    # Evidence
    first_packet: Optional[int] = Field(
        default=None,
        description="First TLS handshake packet"
    )
    last_packet: Optional[int] = Field(
        default=None,
        description="Last TLS handshake packet"
    )
    handshake_timestamp: Optional[datetime] = Field(
        default=None,
        description="Timestamp of handshake"
    )


class TlsAnalysisResult(BaseModel):
    """Result of TLS analysis for an evidence file."""
    evidence_id: str = Field(description="Evidence identifier")
    job_id: str = Field(description="Analysis job identifier")

    # TLS observations
    observations: list[TlsObservation] = Field(
        default_factory=list,
        description="TLS observations"
    )
    total_observations: int = Field(default=0, description="Total TLS sessions")

    # Version distribution
    tls_1_3_count: int = Field(default=0, description="TLS 1.3 sessions")
    tls_1_2_count: int = Field(default=0, description="TLS 1.2 sessions")
    tls_1_1_count: int = Field(default=0, description="TLS 1.1 sessions")
    tls_1_0_count: int = Field(default=0, description="TLS 1.0 sessions")
    ssl_count: int = Field(default=0, description="SSL sessions")
    unknown_version_count: int = Field(default=0, description="Unknown version")

    # Security summary
    deprecated_count: int = Field(
        default=0,
        description="Sessions with deprecated TLS"
    )
    forward_secrecy_count: int = Field(
        default=0,
        description="Sessions with forward secrecy"
    )
    no_forward_secrecy_count: int = Field(
        default=0,
        description="Sessions without forward secrecy"
    )

    # Handshake status
    successful_handshakes: int = Field(default=0)
    failed_handshakes: int = Field(default=0)
    partial_handshakes: int = Field(default=0)

    # Error information
    error_code: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
