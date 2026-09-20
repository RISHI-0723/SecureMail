"""Email security state machine service.

Phase 3: Email Protocol Security Analysis
- SMTP STARTTLS detection and analysis
- IMAP STARTTLS detection and analysis
- POP3 STLS detection and analysis
- Implicit TLS detection (SMTPS, IMAPS, POP3S)
- Plaintext/encrypted transition analysis
"""

from app.services.email.models import (
    TransportSecurity,
    StarttlsState,
    AnalysisConfidence,
    EmailSecuritySession,
    EmailSecurityResult,
)
from app.services.email.security_analyzer import EmailSecurityAnalyzer

__all__ = [
    "TransportSecurity",
    "StarttlsState",
    "AnalysisConfidence",
    "EmailSecuritySession",
    "EmailSecurityResult",
    "EmailSecurityAnalyzer",
]
