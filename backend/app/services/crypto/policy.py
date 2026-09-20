"""Cryptographic security policy configuration.

Phase 3: Centralized policy for security assessments.

This policy defines what is considered secure/insecure.
All security rules reference this policy for consistency.

The policy is versioned for reproducibility.
"""

from typing import Optional
from pydantic import BaseModel, Field


class TlsVersionPolicy(BaseModel):
    """TLS version security policy."""
    deprecated_versions: list[str] = Field(
        default_factory=lambda: ["TLS1.0", "TLS1.1"],
        description="Deprecated TLS versions"
    )
    obsolete_versions: list[str] = Field(
        default_factory=lambda: ["SSLv2", "SSLv3"],
        description="Obsolete/critical TLS versions"
    )
    acceptable_versions: list[str] = Field(
        default_factory=lambda: ["TLS1.2", "TLS1.3"],
        description="Acceptable TLS versions"
    )


class CipherPolicy(BaseModel):
    """Cipher suite security policy."""
    weak_ciphers: list[str] = Field(
        default_factory=lambda: [
            "RC4", "3DES", "DES", "NULL", "EXPORT", "anon"
        ],
        description="Weak cipher patterns"
    )
    weak_modes: list[str] = Field(
        default_factory=lambda: ["CBC"],
        description="Weak cipher modes (context-dependent)"
    )
    strong_ciphers: list[str] = Field(
        default_factory=lambda: [
            "AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305"
        ],
        description="Strong cipher patterns"
    )


class KeyExchangePolicy(BaseModel):
    """Key exchange security policy."""
    require_forward_secrecy: bool = Field(
        default=True,
        description="Require forward secrecy"
    )
    deprecated_exchanges: list[str] = Field(
        default_factory=lambda: ["RSA"],
        description="Deprecated key exchanges (no FS)"
    )
    preferred_exchanges: list[str] = Field(
        default_factory=lambda: ["ECDHE", "X25519", "X448"],
        description="Preferred key exchanges"
    )


class CertificatePolicy(BaseModel):
    """Certificate security policy."""
    min_rsa_key_size: int = Field(
        default=2048,
        description="Minimum RSA key size (bits)"
    )
    min_ec_key_size: int = Field(
        default=256,
        description="Minimum EC key size (bits)"
    )
    weak_signature_algorithms: list[str] = Field(
        default_factory=lambda: ["md5", "sha1", "md2", "md4"],
        description="Weak signature algorithms"
    )
    max_validity_days: Optional[int] = Field(
        default=398,
        description="Maximum certificate validity (TLS BR)"
    )
    allow_self_signed: bool = Field(
        default=False,
        description="Allow self-signed certificates"
    )


class ProtocolPolicy(BaseModel):
    """Email protocol security policy."""
    require_starttls: bool = Field(
        default=True,
        description="Flag plaintext email sessions"
    )
    flag_starttls_not_used: bool = Field(
        default=True,
        description="Flag when STARTTLS advertised but not used"
    )
    flag_starttls_failure: bool = Field(
        default=True,
        description="Flag STARTTLS failures"
    )


class CryptoPolicy(BaseModel):
    """
    Complete cryptographic security policy.

    This policy is the single source of truth for security rules.
    Version the policy for reproducibility.
    """
    version: str = Field(
        default="1.0.0",
        description="Policy version"
    )
    name: str = Field(
        default="SecureMailScope Default Policy",
        description="Policy name"
    )
    description: str = Field(
        default="Default security policy for email TLS assessment",
        description="Policy description"
    )

    # Sub-policies
    tls_version: TlsVersionPolicy = Field(
        default_factory=TlsVersionPolicy,
        description="TLS version policy"
    )
    cipher: CipherPolicy = Field(
        default_factory=CipherPolicy,
        description="Cipher policy"
    )
    key_exchange: KeyExchangePolicy = Field(
        default_factory=KeyExchangePolicy,
        description="Key exchange policy"
    )
    certificate: CertificatePolicy = Field(
        default_factory=CertificatePolicy,
        description="Certificate policy"
    )
    protocol: ProtocolPolicy = Field(
        default_factory=ProtocolPolicy,
        description="Protocol policy"
    )

    def is_tls_version_deprecated(self, version: str) -> bool:
        """Check if TLS version is deprecated."""
        return version in self.tls_version.deprecated_versions

    def is_tls_version_obsolete(self, version: str) -> bool:
        """Check if TLS version is obsolete."""
        return version in self.tls_version.obsolete_versions

    def is_tls_version_acceptable(self, version: str) -> bool:
        """Check if TLS version is acceptable."""
        return version in self.tls_version.acceptable_versions

    def is_cipher_weak(self, cipher: str) -> bool:
        """Check if cipher suite is weak."""
        cipher_upper = cipher.upper()
        return any(
            weak.upper() in cipher_upper
            for weak in self.cipher.weak_ciphers
        )

    def is_key_size_acceptable(self, key_type: str, key_size: int) -> bool:
        """Check if key size meets policy."""
        if key_type.upper() in ("RSA", "DSA"):
            return key_size >= self.certificate.min_rsa_key_size
        elif key_type.upper() in ("ECDSA", "EC"):
            return key_size >= self.certificate.min_ec_key_size
        return True  # Unknown key types pass by default

    def is_signature_algorithm_weak(self, algorithm: str) -> bool:
        """Check if signature algorithm is weak."""
        algo_lower = algorithm.lower()
        return any(
            weak in algo_lower
            for weak in self.certificate.weak_signature_algorithms
        )


# Default policy instance
_default_policy: Optional[CryptoPolicy] = None


def get_default_policy() -> CryptoPolicy:
    """
    Get the default cryptographic policy.

    Returns:
        Default CryptoPolicy instance
    """
    global _default_policy
    if _default_policy is None:
        _default_policy = CryptoPolicy()
    return _default_policy
