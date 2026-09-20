"""Security rules engine.

Phase 3: Deterministic security rule evaluation.

This module defines security rules that generate findings.
Each rule has clear conditions and severity.

IMPORTANT: Rules are deterministic.
Same evidence + same policy = same findings.
"""

import logging
from enum import Enum
from typing import Optional, Callable, Any
from pydantic import BaseModel, Field

from app.services.crypto.policy import CryptoPolicy, get_default_policy

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"   # Immediate security risk
    HIGH = "HIGH"           # Significant security weakness
    MEDIUM = "MEDIUM"       # Moderate security concern
    LOW = "LOW"             # Minor security issue
    INFO = "INFO"           # Informational finding


class RuleCategory(str, Enum):
    """Security rule categories."""
    TLS_VERSION = "TLS_VERSION"
    TLS_CIPHER = "TLS_CIPHER"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    FORWARD_SECRECY = "FORWARD_SECRECY"
    CERTIFICATE_VALIDITY = "CERTIFICATE_VALIDITY"
    CERTIFICATE_KEY = "CERTIFICATE_KEY"
    CERTIFICATE_SIGNATURE = "CERTIFICATE_SIGNATURE"
    CERTIFICATE_CHAIN = "CERTIFICATE_CHAIN"
    PROTOCOL_SECURITY = "PROTOCOL_SECURITY"
    STARTTLS_SECURITY = "STARTTLS_SECURITY"
    HANDSHAKE = "HANDSHAKE"
    STREAM_INTEGRITY = "STREAM_INTEGRITY"


class SecurityRule(BaseModel):
    """
    Security rule definition.

    Each rule defines a condition that generates a finding
    when matched against evidence.
    """
    rule_id: str = Field(description="Unique rule identifier")
    title: str = Field(description="Human-readable rule title")
    description: str = Field(description="Detailed rule description")
    category: RuleCategory = Field(description="Rule category")
    severity: Severity = Field(description="Finding severity when triggered")
    enabled: bool = Field(default=True, description="Is rule enabled")
    remediation: str = Field(
        default="",
        description="Remediation guidance"
    )

    class Config:
        arbitrary_types_allowed = True


class RuleMatch(BaseModel):
    """Result of a rule evaluation."""
    rule_id: str = Field(description="Rule that matched")
    matched: bool = Field(description="Whether rule condition was met")
    observed_value: Optional[Any] = Field(default=None, description="Observed value")
    expected_value: Optional[Any] = Field(default=None, description="Expected/policy value")
    evidence: dict = Field(default_factory=dict, description="Evidence details")


class RulesEngine:
    """
    Deterministic security rules engine.

    Evaluates security rules against analyzed data.
    Generates findings when rules match.

    All rules are defined here for centralized management.
    """

    def __init__(self, policy: Optional[CryptoPolicy] = None):
        """
        Initialize rules engine.

        Args:
            policy: Crypto policy to use. Defaults to default policy.
        """
        self.policy = policy or get_default_policy()
        self._rules = self._define_rules()

    def _define_rules(self) -> dict[str, SecurityRule]:
        """Define all security rules."""
        rules = {}

        # TLS Version Rules
        rules["TLS-001"] = SecurityRule(
            rule_id="TLS-001",
            title="Deprecated TLS Version",
            description="TLS 1.0 or TLS 1.1 was observed. These versions have known vulnerabilities.",
            category=RuleCategory.TLS_VERSION,
            severity=Severity.HIGH,
            remediation="Upgrade to TLS 1.2 or TLS 1.3. Disable TLS 1.0 and TLS 1.1."
        )

        rules["TLS-002"] = SecurityRule(
            rule_id="TLS-002",
            title="Obsolete SSL Version",
            description="SSLv2 or SSLv3 was observed. These protocols are severely compromised.",
            category=RuleCategory.TLS_VERSION,
            severity=Severity.CRITICAL,
            remediation="Immediately disable SSLv2 and SSLv3. Use TLS 1.2 or higher."
        )

        # Cipher Rules
        rules["CIPHER-001"] = SecurityRule(
            rule_id="CIPHER-001",
            title="Weak Cipher Suite",
            description="A weak or insecure cipher suite was negotiated.",
            category=RuleCategory.TLS_CIPHER,
            severity=Severity.HIGH,
            remediation="Configure server to use strong cipher suites (AES-GCM, ChaCha20)."
        )

        # Key Exchange Rules
        rules["KEX-001"] = SecurityRule(
            rule_id="KEX-001",
            title="No Forward Secrecy",
            description="Key exchange without forward secrecy (e.g., static RSA).",
            category=RuleCategory.FORWARD_SECRECY,
            severity=Severity.MEDIUM,
            remediation="Enable ECDHE or DHE key exchange for forward secrecy."
        )

        # Certificate Rules
        rules["CERT-001"] = SecurityRule(
            rule_id="CERT-001",
            title="Expired Certificate",
            description="Certificate was expired at the time of observation.",
            category=RuleCategory.CERTIFICATE_VALIDITY,
            severity=Severity.HIGH,
            remediation="Renew the expired certificate immediately."
        )

        rules["CERT-002"] = SecurityRule(
            rule_id="CERT-002",
            title="Certificate Not Yet Valid",
            description="Certificate was not yet valid at the time of observation.",
            category=RuleCategory.CERTIFICATE_VALIDITY,
            severity=Severity.HIGH,
            remediation="Check certificate deployment timing and system clocks."
        )

        rules["CERT-003"] = SecurityRule(
            rule_id="CERT-003",
            title="Self-Signed Certificate",
            description="A self-signed certificate was observed.",
            category=RuleCategory.CERTIFICATE_CHAIN,
            severity=Severity.MEDIUM,
            remediation="Use certificates from a trusted Certificate Authority."
        )

        rules["CERT-004"] = SecurityRule(
            rule_id="CERT-004",
            title="Weak Certificate Key",
            description="Certificate public key size is below recommended minimum.",
            category=RuleCategory.CERTIFICATE_KEY,
            severity=Severity.HIGH,
            remediation="Use RSA keys >= 2048 bits or EC keys >= 256 bits."
        )

        rules["CERT-005"] = SecurityRule(
            rule_id="CERT-005",
            title="Weak Signature Algorithm",
            description="Certificate uses a weak signature algorithm (MD5, SHA-1).",
            category=RuleCategory.CERTIFICATE_SIGNATURE,
            severity=Severity.MEDIUM,
            remediation="Reissue certificate with SHA-256 or stronger signature."
        )

        # Protocol Security Rules
        rules["PROTO-001"] = SecurityRule(
            rule_id="PROTO-001",
            title="Plaintext Email Session",
            description="Email session transmitted without TLS encryption.",
            category=RuleCategory.PROTOCOL_SECURITY,
            severity=Severity.HIGH,
            remediation="Enable and require TLS for email communications."
        )

        rules["PROTO-002"] = SecurityRule(
            rule_id="PROTO-002",
            title="STARTTLS Available But Not Used",
            description="Server advertised STARTTLS but client did not use it.",
            category=RuleCategory.STARTTLS_SECURITY,
            severity=Severity.MEDIUM,
            remediation="Configure email client to require STARTTLS."
        )

        rules["PROTO-003"] = SecurityRule(
            rule_id="PROTO-003",
            title="STARTTLS Failure",
            description="STARTTLS negotiation failed.",
            category=RuleCategory.STARTTLS_SECURITY,
            severity=Severity.HIGH,
            remediation="Investigate STARTTLS configuration and certificate issues."
        )

        # Handshake Rules
        rules["HAND-001"] = SecurityRule(
            rule_id="HAND-001",
            title="TLS Handshake Failure",
            description="TLS handshake failed to complete.",
            category=RuleCategory.HANDSHAKE,
            severity=Severity.MEDIUM,
            remediation="Review TLS configuration and certificate validity."
        )

        return rules

    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_rules_by_category(self, category: RuleCategory) -> list[SecurityRule]:
        """Get all rules in a category."""
        return [
            r for r in self._rules.values()
            if r.category == category and r.enabled
        ]

    def get_all_rules(self) -> list[SecurityRule]:
        """Get all enabled rules."""
        return [r for r in self._rules.values() if r.enabled]

    def evaluate_tls_version(
        self,
        version: str,
        stream_id: int,
        packet_numbers: Optional[list[int]] = None
    ) -> list[RuleMatch]:
        """
        Evaluate TLS version against rules.

        Args:
            version: TLS version string (e.g., "TLS1.0")
            stream_id: TCP stream ID
            packet_numbers: Evidence packet numbers

        Returns:
            List of rule matches
        """
        matches = []
        evidence = {
            "stream_id": stream_id,
            "packet_numbers": packet_numbers or []
        }

        # Check deprecated versions
        if self.policy.is_tls_version_deprecated(version):
            matches.append(RuleMatch(
                rule_id="TLS-001",
                matched=True,
                observed_value=version,
                expected_value=self.policy.tls_version.acceptable_versions,
                evidence=evidence
            ))

        # Check obsolete versions
        if self.policy.is_tls_version_obsolete(version):
            matches.append(RuleMatch(
                rule_id="TLS-002",
                matched=True,
                observed_value=version,
                expected_value=self.policy.tls_version.acceptable_versions,
                evidence=evidence
            ))

        return matches

    def evaluate_cipher(
        self,
        cipher: str,
        stream_id: int,
        packet_numbers: Optional[list[int]] = None
    ) -> list[RuleMatch]:
        """Evaluate cipher suite against rules."""
        matches = []
        evidence = {
            "stream_id": stream_id,
            "packet_numbers": packet_numbers or []
        }

        if self.policy.is_cipher_weak(cipher):
            matches.append(RuleMatch(
                rule_id="CIPHER-001",
                matched=True,
                observed_value=cipher,
                expected_value=self.policy.cipher.strong_ciphers,
                evidence=evidence
            ))

        return matches

    def evaluate_forward_secrecy(
        self,
        has_fs: bool,
        key_exchange: str,
        stream_id: int
    ) -> list[RuleMatch]:
        """Evaluate forward secrecy."""
        matches = []

        if not has_fs and self.policy.key_exchange.require_forward_secrecy:
            matches.append(RuleMatch(
                rule_id="KEX-001",
                matched=True,
                observed_value={"forward_secrecy": False, "key_exchange": key_exchange},
                expected_value={"forward_secrecy": True},
                evidence={"stream_id": stream_id}
            ))

        return matches

    def evaluate_certificate(
        self,
        cert_data: dict,
        stream_id: int
    ) -> list[RuleMatch]:
        """
        Evaluate certificate against rules.

        Args:
            cert_data: Dictionary with certificate properties:
                - validity: CertificateValidity
                - key_type: str
                - key_size: int
                - signature_algorithm: str
                - is_self_signed: bool
            stream_id: TCP stream ID

        Returns:
            List of rule matches
        """
        matches = []
        evidence = {"stream_id": stream_id}

        # Check validity
        validity = cert_data.get("validity")
        if validity == "EXPIRED":
            matches.append(RuleMatch(
                rule_id="CERT-001",
                matched=True,
                observed_value="EXPIRED",
                expected_value="VALID",
                evidence=evidence
            ))
        elif validity == "NOT_YET_VALID":
            matches.append(RuleMatch(
                rule_id="CERT-002",
                matched=True,
                observed_value="NOT_YET_VALID",
                expected_value="VALID",
                evidence=evidence
            ))

        # Check self-signed
        if cert_data.get("is_self_signed") and not self.policy.certificate.allow_self_signed:
            matches.append(RuleMatch(
                rule_id="CERT-003",
                matched=True,
                observed_value=True,
                expected_value=False,
                evidence=evidence
            ))

        # Check key size
        key_type = cert_data.get("key_type", "")
        key_size = cert_data.get("key_size", 0)
        if key_size and not self.policy.is_key_size_acceptable(key_type, key_size):
            matches.append(RuleMatch(
                rule_id="CERT-004",
                matched=True,
                observed_value={"key_type": key_type, "key_size": key_size},
                expected_value={
                    "min_rsa": self.policy.certificate.min_rsa_key_size,
                    "min_ec": self.policy.certificate.min_ec_key_size
                },
                evidence=evidence
            ))

        # Check signature algorithm
        sig_algo = cert_data.get("signature_algorithm", "")
        if sig_algo and self.policy.is_signature_algorithm_weak(sig_algo):
            matches.append(RuleMatch(
                rule_id="CERT-005",
                matched=True,
                observed_value=sig_algo,
                expected_value="SHA-256 or stronger",
                evidence=evidence
            ))

        return matches

    def evaluate_protocol_security(
        self,
        session_data: dict,
        stream_id: int
    ) -> list[RuleMatch]:
        """
        Evaluate protocol security against rules.

        Args:
            session_data: Dictionary with session properties:
                - transport_security: str
                - starttls_advertised: bool
                - starttls_requested: bool
                - starttls_failed: bool
            stream_id: TCP stream ID

        Returns:
            List of rule matches
        """
        matches = []
        evidence = {"stream_id": stream_id}

        transport = session_data.get("transport_security")

        # Plaintext session
        if transport == "PLAINTEXT" and self.policy.protocol.require_starttls:
            matches.append(RuleMatch(
                rule_id="PROTO-001",
                matched=True,
                observed_value="PLAINTEXT",
                expected_value="TLS",
                evidence=evidence
            ))

        # STARTTLS advertised but not used
        if (session_data.get("starttls_advertised")
            and not session_data.get("starttls_requested")
            and self.policy.protocol.flag_starttls_not_used):
            matches.append(RuleMatch(
                rule_id="PROTO-002",
                matched=True,
                observed_value={"advertised": True, "used": False},
                expected_value={"used": True},
                evidence=evidence
            ))

        # STARTTLS failure
        if (session_data.get("starttls_failed")
            and self.policy.protocol.flag_starttls_failure):
            matches.append(RuleMatch(
                rule_id="PROTO-003",
                matched=True,
                observed_value="FAILED",
                expected_value="SUCCESS",
                evidence=evidence
            ))

        return matches

    def evaluate_handshake(
        self,
        handshake_status: str,
        stream_id: int
    ) -> list[RuleMatch]:
        """Evaluate TLS handshake status."""
        matches = []

        if handshake_status == "FAILED":
            matches.append(RuleMatch(
                rule_id="HAND-001",
                matched=True,
                observed_value="FAILED",
                expected_value="SUCCESS",
                evidence={"stream_id": stream_id}
            ))

        return matches
