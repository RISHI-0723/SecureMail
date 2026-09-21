"""Phase 4 Evidence Integrity Services.

This package provides evidence integrity verification:
- Cryptographic hashing (SHA-256, SHA-512)
- Merkle tree generation for batch verification
- Optional blockchain anchoring

IMPORTANT: Integrity verification is independent of core forensics.
If blockchain anchoring fails, hash-based verification continues.
"""
from app.services.integrity.integrity_service import (
    IntegrityService,
    IntegrityRecord,
    VerificationResult,
    IntegrityStatus,
    LocalHashProvider,
    NoOpBlockchainProvider,
)

__all__ = [
    "IntegrityService",
    "IntegrityRecord",
    "VerificationResult",
    "IntegrityStatus",
    "LocalHashProvider",
    "NoOpBlockchainProvider",
]
