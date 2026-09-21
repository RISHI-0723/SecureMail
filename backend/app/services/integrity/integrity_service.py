"""Evidence Integrity Service - Phase 4.

Provides cryptographic verification and integrity tracking for forensic evidence.
Supports local hash-based verification and optional blockchain anchoring.

IMPORTANT: Integrity verification is independent of core forensics.
If blockchain anchoring fails, hash-based verification continues unaffected.

RULE: No raw PCAP, email content, or credentials go on-chain.
Only hashes and non-sensitive integrity metadata are anchored.
"""
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field
import uuid

logger = logging.getLogger(__name__)


class IntegrityStatus(str):
    """Integrity verification status."""
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ANCHORED = "ANCHORED"
    UNAVAILABLE = "UNAVAILABLE"


class VerificationResult(BaseModel):
    """Result of integrity verification."""
    status: str
    evidence_id: str
    evidence_hash_match: bool = False
    analysis_hash_match: bool = False
    report_hash_match: bool = False

    # Stored vs computed hashes
    stored_evidence_hash: Optional[str] = None
    computed_evidence_hash: Optional[str] = None
    stored_analysis_hash: Optional[str] = None
    computed_analysis_hash: Optional[str] = None

    # Blockchain info (if applicable)
    blockchain_verified: bool = False
    transaction_hash: Optional[str] = None

    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = ""


class IntegrityRecord(BaseModel):
    """Complete integrity record for evidence and analysis."""
    integrity_id: str = Field(default_factory=lambda: f"integ_{uuid.uuid4().hex[:12]}")
    evidence_id: str
    job_id: Optional[str] = None
    intelligence_report_id: Optional[str] = None

    # Hashes
    evidence_sha256: str
    evidence_sha512: Optional[str] = None
    analysis_hash: Optional[str] = None
    report_hash: Optional[str] = None
    merkle_root: Optional[str] = None

    # Status
    status: str = IntegrityStatus.PENDING

    # Blockchain (optional)
    blockchain_enabled: bool = False
    blockchain_network: Optional[str] = None
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    anchor_timestamp: Optional[datetime] = None

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: Optional[datetime] = None

    # Metadata
    integrity_metadata: Optional[dict] = None


class HashProvider(ABC):
    """Abstract base for hash providers."""

    @abstractmethod
    def compute_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Compute hash of a file."""
        pass

    @abstractmethod
    def compute_data_hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """Compute hash of data."""
        pass

    @abstractmethod
    def verify_hash(self, expected: str, computed: str) -> bool:
        """Verify hash match."""
        pass


class LocalHashProvider(HashProvider):
    """Local cryptographic hash provider using Python hashlib."""

    SUPPORTED_ALGORITHMS = ["sha256", "sha512", "sha384", "sha3_256", "md5"]

    def compute_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """
        Compute hash of a file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (default: sha256)

        Returns:
            Hexadecimal hash string
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        hasher = hashlib.new(algorithm)

        with open(file_path, "rb") as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)

        return hasher.hexdigest()

    def compute_data_hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """
        Compute hash of data.

        Args:
            data: Bytes to hash
            algorithm: Hash algorithm (default: sha256)

        Returns:
            Hexadecimal hash string
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()

    def verify_hash(self, expected: str, computed: str) -> bool:
        """
        Verify hash match (constant-time comparison).

        Args:
            expected: Expected hash
            computed: Computed hash

        Returns:
            True if hashes match
        """
        import hmac
        return hmac.compare_digest(expected.lower(), computed.lower())


class BlockchainAnchorProvider(ABC):
    """Abstract base for blockchain anchoring."""

    @abstractmethod
    def anchor_hash(self, hash_value: str, metadata: dict) -> Optional[str]:
        """Anchor a hash to blockchain. Returns transaction hash."""
        pass

    @abstractmethod
    def verify_anchor(self, transaction_hash: str, expected_hash: str) -> bool:
        """Verify an anchored hash."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if blockchain is available."""
        pass


class NoOpBlockchainProvider(BlockchainAnchorProvider):
    """No-op blockchain provider when blockchain is disabled."""

    def anchor_hash(self, hash_value: str, metadata: dict) -> Optional[str]:
        """No-op anchor - returns None."""
        logger.debug("Blockchain anchoring disabled, skipping")
        return None

    def verify_anchor(self, transaction_hash: str, expected_hash: str) -> bool:
        """No-op verify - always returns False (not anchored)."""
        return False

    def is_available(self) -> bool:
        """Blockchain not available."""
        return False


class IntegrityService:
    """
    Evidence integrity service for Phase 4.

    Provides:
    1. SHA-256/SHA-512 hashing for evidence
    2. Analysis result hashing
    3. Report hashing
    4. Hash verification
    5. Optional blockchain anchoring

    IMPORTANT: If blockchain fails, local hash verification continues.
    """

    def __init__(
        self,
        hash_provider: Optional[HashProvider] = None,
        blockchain_provider: Optional[BlockchainAnchorProvider] = None,
        blockchain_enabled: bool = False,
    ):
        """
        Initialize the integrity service.

        Args:
            hash_provider: Hash computation provider (default: LocalHashProvider)
            blockchain_provider: Blockchain anchor provider (default: NoOpBlockchainProvider)
            blockchain_enabled: Whether blockchain anchoring is enabled
        """
        self.hash_provider = hash_provider or LocalHashProvider()
        self.blockchain_provider = blockchain_provider or NoOpBlockchainProvider()
        self.blockchain_enabled = blockchain_enabled

        logger.info(f"IntegrityService initialized (blockchain_enabled={blockchain_enabled})")

    def compute_evidence_integrity(
        self,
        evidence_path: Path,
        evidence_id: str,
    ) -> IntegrityRecord:
        """
        Compute integrity hashes for evidence file.

        Args:
            evidence_path: Path to evidence file
            evidence_id: Evidence identifier

        Returns:
            IntegrityRecord with computed hashes
        """
        try:
            sha256 = self.hash_provider.compute_file_hash(evidence_path, "sha256")
            sha512 = self.hash_provider.compute_file_hash(evidence_path, "sha512")

            record = IntegrityRecord(
                evidence_id=evidence_id,
                evidence_sha256=sha256,
                evidence_sha512=sha512,
                status=IntegrityStatus.VERIFIED,
                verified_at=datetime.now(timezone.utc),
            )

            logger.info(
                f"Computed evidence integrity for {evidence_id}",
                extra={"evidence_id": evidence_id, "sha256": sha256[:16] + "..."}
            )

            return record

        except Exception as e:
            logger.error(f"Failed to compute evidence integrity: {e}")
            return IntegrityRecord(
                evidence_id=evidence_id,
                evidence_sha256="",
                status=IntegrityStatus.FAILED,
                integrity_metadata={"error": str(e)},
            )

    def compute_analysis_hash(
        self,
        analysis_data: dict,
        normalize: bool = True,
    ) -> str:
        """
        Compute deterministic hash of analysis results.

        Args:
            analysis_data: Analysis result data
            normalize: Whether to normalize data for determinism

        Returns:
            SHA-256 hash of analysis
        """
        if normalize:
            # Remove non-deterministic fields
            data = self._normalize_for_hashing(analysis_data)
        else:
            data = analysis_data

        # Serialize deterministically
        json_data = json.dumps(data, sort_keys=True, default=str)

        return self.hash_provider.compute_data_hash(json_data.encode(), "sha256")

    def compute_report_hash(
        self,
        report_content: bytes,
    ) -> str:
        """
        Compute hash of generated report.

        Args:
            report_content: Report content bytes

        Returns:
            SHA-256 hash of report
        """
        return self.hash_provider.compute_data_hash(report_content, "sha256")

    def verify_evidence_integrity(
        self,
        evidence_path: Path,
        stored_record: IntegrityRecord,
    ) -> VerificationResult:
        """
        Verify evidence file integrity against stored record.

        Args:
            evidence_path: Path to evidence file
            stored_record: Stored integrity record

        Returns:
            VerificationResult with verification status
        """
        try:
            computed_sha256 = self.hash_provider.compute_file_hash(evidence_path, "sha256")

            hash_match = self.hash_provider.verify_hash(
                stored_record.evidence_sha256,
                computed_sha256
            )

            status = IntegrityStatus.VERIFIED if hash_match else IntegrityStatus.FAILED

            result = VerificationResult(
                status=status,
                evidence_id=stored_record.evidence_id,
                evidence_hash_match=hash_match,
                stored_evidence_hash=stored_record.evidence_sha256,
                computed_evidence_hash=computed_sha256,
                message="Evidence integrity verified" if hash_match else "Evidence hash mismatch detected",
            )

            # Check blockchain if anchored
            if stored_record.blockchain_enabled and stored_record.transaction_hash:
                result.blockchain_verified = self.blockchain_provider.verify_anchor(
                    stored_record.transaction_hash,
                    stored_record.evidence_sha256
                )
                result.transaction_hash = stored_record.transaction_hash

            logger.info(
                f"Evidence verification: {status}",
                extra={
                    "evidence_id": stored_record.evidence_id,
                    "hash_match": hash_match
                }
            )

            return result

        except FileNotFoundError:
            return VerificationResult(
                status=IntegrityStatus.FAILED,
                evidence_id=stored_record.evidence_id,
                message="Evidence file not found",
            )
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return VerificationResult(
                status=IntegrityStatus.FAILED,
                evidence_id=stored_record.evidence_id,
                message=f"Verification error: {str(e)}",
            )

    def anchor_to_blockchain(
        self,
        record: IntegrityRecord,
    ) -> IntegrityRecord:
        """
        Anchor integrity record to blockchain (optional).

        IMPORTANT: Only hashes and metadata are anchored.
        No raw PCAP, email content, or sensitive data goes on-chain.

        Args:
            record: Integrity record to anchor

        Returns:
            Updated integrity record with blockchain info
        """
        if not self.blockchain_enabled:
            logger.debug("Blockchain anchoring disabled")
            return record

        if not self.blockchain_provider.is_available():
            logger.warning("Blockchain provider not available")
            return record

        try:
            # Prepare anchor metadata (no sensitive data)
            metadata = {
                "evidence_id": record.evidence_id,
                "evidence_sha256": record.evidence_sha256,
                "analysis_hash": record.analysis_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "0.4.0-phase4",
            }

            # Anchor the evidence hash
            tx_hash = self.blockchain_provider.anchor_hash(
                record.evidence_sha256,
                metadata
            )

            if tx_hash:
                record.blockchain_enabled = True
                record.transaction_hash = tx_hash
                record.anchor_timestamp = datetime.now(timezone.utc)
                record.status = IntegrityStatus.ANCHORED

                logger.info(
                    f"Evidence anchored to blockchain",
                    extra={
                        "evidence_id": record.evidence_id,
                        "transaction_hash": tx_hash
                    }
                )

            return record

        except Exception as e:
            logger.error(f"Blockchain anchoring failed: {e}")
            # Anchoring failure does not affect local integrity
            return record

    def create_complete_integrity_record(
        self,
        evidence_path: Path,
        evidence_id: str,
        job_id: Optional[str] = None,
        analysis_data: Optional[dict] = None,
        report_content: Optional[bytes] = None,
        intelligence_report_id: Optional[str] = None,
    ) -> IntegrityRecord:
        """
        Create a complete integrity record with all hashes.

        Args:
            evidence_path: Path to evidence file
            evidence_id: Evidence identifier
            job_id: Analysis job ID
            analysis_data: Analysis result data
            report_content: Generated report content
            intelligence_report_id: Phase 4 intelligence report ID

        Returns:
            Complete integrity record
        """
        # Start with evidence integrity
        record = self.compute_evidence_integrity(evidence_path, evidence_id)
        record.job_id = job_id
        record.intelligence_report_id = intelligence_report_id

        # Add analysis hash if provided
        if analysis_data:
            record.analysis_hash = self.compute_analysis_hash(analysis_data)

        # Add report hash if provided
        if report_content:
            record.report_hash = self.compute_report_hash(report_content)

        # Optionally anchor to blockchain
        if self.blockchain_enabled and record.status == IntegrityStatus.VERIFIED:
            record = self.anchor_to_blockchain(record)

        return record

    def _normalize_for_hashing(self, data: dict) -> dict:
        """
        Normalize data for deterministic hashing.

        Removes or normalizes:
        - Timestamps (converted to ISO format)
        - Runtime-generated IDs (if dynamic)
        - Floating point precision issues

        Args:
            data: Data to normalize

        Returns:
            Normalized data
        """
        normalized = {}

        for key, value in data.items():
            # Skip known non-deterministic fields
            if key in ["created_at", "updated_at", "generated_at"]:
                continue

            if isinstance(value, datetime):
                normalized[key] = value.isoformat()
            elif isinstance(value, float):
                # Round to 6 decimal places for consistency
                normalized[key] = round(value, 6)
            elif isinstance(value, dict):
                normalized[key] = self._normalize_for_hashing(value)
            elif isinstance(value, list):
                normalized[key] = [
                    self._normalize_for_hashing(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                normalized[key] = value

        return normalized

    def get_merkle_root(
        self,
        hashes: list[str],
    ) -> str:
        """
        Compute Merkle tree root from a list of hashes.

        Args:
            hashes: List of hash strings

        Returns:
            Merkle root hash
        """
        if not hashes:
            return ""

        if len(hashes) == 1:
            return hashes[0]

        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])

        # Compute next level
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            parent_hash = self.hash_provider.compute_data_hash(
                combined.encode(), "sha256"
            )
            next_level.append(parent_hash)

        return self.get_merkle_root(next_level)
