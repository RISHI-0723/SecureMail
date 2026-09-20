"""Email security session models.

Phase 3: Data structures for email protocol security analysis.

Supports SMTP, IMAP, POP3 with STARTTLS/STLS and implicit TLS detection.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from app.services.tcp.models import StreamIntegrity


class TransportSecurity(str, Enum):
    """Transport security mode for email session."""
    PLAINTEXT = "PLAINTEXT"           # No TLS, plaintext only
    STARTTLS = "STARTTLS"            # Upgraded via STARTTLS/STLS
    IMPLICIT_TLS = "IMPLICIT_TLS"     # Started as TLS (SMTPS/IMAPS/POP3S)
    UNKNOWN = "UNKNOWN"               # Cannot determine


class StarttlsState(str, Enum):
    """STARTTLS/STLS negotiation state."""
    NOT_OBSERVED = "NOT_OBSERVED"     # No STARTTLS seen
    ADVERTISED = "ADVERTISED"         # Server advertised STARTTLS
    REQUESTED = "REQUESTED"           # Client requested STARTTLS
    ACCEPTED = "ACCEPTED"             # Server accepted (220/OK)
    REJECTED = "REJECTED"             # Server rejected
    TLS_STARTED = "TLS_STARTED"       # TLS handshake observed after acceptance
    FAILED = "FAILED"                 # STARTTLS failed (various reasons)
    PARTIAL = "PARTIAL"               # Incomplete observation


class AnalysisConfidence(str, Enum):
    """Confidence level for analysis results."""
    HIGH = "HIGH"       # Direct evidence observed
    MEDIUM = "MEDIUM"   # Multiple indicators
    LOW = "LOW"         # Indirect evidence only
    UNKNOWN = "UNKNOWN" # Insufficient evidence


class AnalysisCoverage(str, Enum):
    """Evidence coverage for analysis."""
    COMPLETE = "COMPLETE"   # Full session captured
    PARTIAL = "PARTIAL"     # Incomplete capture
    UNKNOWN = "UNKNOWN"     # Cannot determine


class StarttlsObservation(BaseModel):
    """STARTTLS/STLS observation details."""
    state: StarttlsState = Field(description="Current STARTTLS state")
    advertised: bool = Field(default=False, description="STARTTLS was advertised")
    requested: bool = Field(default=False, description="Client requested STARTTLS")
    accepted: bool = Field(default=False, description="Server accepted STARTTLS")
    rejected: bool = Field(default=False, description="Server rejected STARTTLS")
    tls_transition_observed: bool = Field(
        default=False,
        description="TLS handshake observed after STARTTLS"
    )
    evidence_packet: Optional[int] = Field(
        default=None,
        description="Packet number where evidence was found"
    )


class EmailSecuritySession(BaseModel):
    """
    Email protocol security session analysis.

    Represents the security state of a single email protocol session
    (SMTP, IMAP, or POP3 conversation).
    """
    session_id: str = Field(description="Unique session identifier")
    stream_id: int = Field(description="Associated TCP stream ID")
    protocol: str = Field(description="Email protocol (SMTP, IMAP, POP3)")

    # Network endpoints
    client_ip: Optional[str] = Field(default=None, description="Client IP")
    client_port: Optional[int] = Field(default=None, description="Client port")
    server_ip: Optional[str] = Field(default=None, description="Server IP")
    server_port: Optional[int] = Field(default=None, description="Server port")

    # Security classification
    transport_security: TransportSecurity = Field(
        default=TransportSecurity.UNKNOWN,
        description="Transport security mode"
    )

    # STARTTLS/STLS analysis
    starttls: StarttlsObservation = Field(
        default_factory=lambda: StarttlsObservation(state=StarttlsState.NOT_OBSERVED),
        description="STARTTLS/STLS observation"
    )

    # Implicit TLS
    implicit_tls: bool = Field(
        default=False,
        description="Session started with implicit TLS"
    )

    # TLS detection
    tls_detected: bool = Field(
        default=False,
        description="TLS traffic detected in session"
    )

    # Plaintext exposure
    plaintext_commands_observed: bool = Field(
        default=False,
        description="Plaintext email commands observed"
    )
    plaintext_after_starttls_failure: bool = Field(
        default=False,
        description="Plaintext commands after failed STARTTLS"
    )

    # Stream integrity (from TCP analysis)
    stream_integrity: StreamIntegrity = Field(
        default=StreamIntegrity.UNKNOWN,
        description="TCP stream integrity"
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

    # Timestamps
    first_packet: Optional[int] = Field(default=None, description="First packet number")
    last_packet: Optional[int] = Field(default=None, description="Last packet number")
    start_time: Optional[datetime] = Field(default=None, description="Session start time")
    end_time: Optional[datetime] = Field(default=None, description="Session end time")


class EmailSecurityResult(BaseModel):
    """Result of email security analysis for an evidence file."""
    evidence_id: str = Field(description="Evidence identifier")
    job_id: str = Field(description="Analysis job identifier")

    # Session analysis
    sessions: list[EmailSecuritySession] = Field(
        default_factory=list,
        description="Analyzed email sessions"
    )
    total_sessions: int = Field(default=0, description="Total sessions analyzed")

    # Protocol breakdown
    smtp_sessions: int = Field(default=0, description="SMTP sessions")
    imap_sessions: int = Field(default=0, description="IMAP sessions")
    pop3_sessions: int = Field(default=0, description="POP3 sessions")

    # Security summary
    plaintext_sessions: int = Field(default=0, description="Plaintext-only sessions")
    starttls_sessions: int = Field(default=0, description="STARTTLS-upgraded sessions")
    implicit_tls_sessions: int = Field(default=0, description="Implicit TLS sessions")
    unknown_security_sessions: int = Field(
        default=0,
        description="Sessions with unknown security"
    )

    # STARTTLS observations
    starttls_advertised_count: int = Field(
        default=0,
        description="Sessions where STARTTLS was advertised"
    )
    starttls_requested_count: int = Field(
        default=0,
        description="Sessions where STARTTLS was requested"
    )
    starttls_success_count: int = Field(
        default=0,
        description="Sessions where STARTTLS succeeded"
    )
    starttls_failure_count: int = Field(
        default=0,
        description="Sessions where STARTTLS failed"
    )

    # Error information
    error_code: Optional[str] = Field(default=None, description="Error code if failed")
    error_message: Optional[str] = Field(default=None, description="Error message")
