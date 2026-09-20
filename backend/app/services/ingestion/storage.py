"""Evidence storage service abstraction."""
import os
import uuid
import logging
from pathlib import Path
from typing import BinaryIO
from dataclasses import dataclass

from app.core.config import settings

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for storage errors."""
    def __init__(self, message: str, code: str = "STORAGE_FAILED"):
        self.message = message
        self.code = code
        super().__init__(message)


@dataclass
class StorageMetadata:
    """Metadata about stored evidence."""
    stored_filename: str
    storage_location: str
    file_size_bytes: int


class EvidenceStorage:
    """
    Local file system storage for evidence files.

    This abstraction allows for future migration to S3-compatible
    object storage without changing the ingestion API.
    """

    def __init__(self, base_path: str | None = None):
        """
        Initialize evidence storage.

        Args:
            base_path: Base directory for evidence storage.
                      Defaults to settings.evidence_storage_path.
        """
        self.base_path = Path(base_path or settings.evidence_storage_path)
        self._ensure_storage_directory()

    def _ensure_storage_directory(self) -> None:
        """Create storage directory if it doesn't exist."""
        try:
            self.base_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Evidence storage directory ready: {self.base_path}")
        except OSError as e:
            logger.error(f"Failed to create storage directory: {e}")
            raise StorageError(
                f"Cannot create storage directory: {self.base_path}",
                code="STORAGE_INIT_FAILED"
            )

    def _generate_storage_key(self, extension: str = "") -> str:
        """
        Generate a unique storage key for a file.

        Args:
            extension: Original file extension (e.g., ".pcap")

        Returns:
            Unique storage filename
        """
        unique_id = uuid.uuid4().hex
        # Keep extension for easier debugging, but storage key is authoritative
        return f"{unique_id}{extension}"

    def _get_file_path(self, storage_key: str) -> Path:
        """Get the full file path for a storage key."""
        # Prevent path traversal by using only the filename
        safe_key = Path(storage_key).name
        return self.base_path / safe_key

    def save(
        self,
        file_data: BinaryIO,
        original_filename: str,
        file_size: int | None = None
    ) -> StorageMetadata:
        """
        Save evidence file to storage.

        Args:
            file_data: File-like object containing evidence data
            original_filename: Original filename (used for extension only)
            file_size: Expected file size (for verification)

        Returns:
            StorageMetadata with storage details

        Raises:
            StorageError: If storage operation fails
        """
        # Extract extension safely
        original_ext = Path(original_filename).suffix.lower()
        storage_key = self._generate_storage_key(original_ext)
        file_path = self._get_file_path(storage_key)

        try:
            bytes_written = 0
            with open(file_path, "wb") as f:
                while True:
                    chunk = file_data.read(8192)  # 8KB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_written += len(chunk)

            # Verify size if provided
            if file_size is not None and bytes_written != file_size:
                # Clean up partial file
                file_path.unlink(missing_ok=True)
                raise StorageError(
                    f"File size mismatch: expected {file_size}, got {bytes_written}",
                    code="STORAGE_SIZE_MISMATCH"
                )

            logger.info(
                f"Evidence stored: {storage_key}, size: {bytes_written} bytes",
                extra={"storage_key": storage_key, "size": bytes_written}
            )

            return StorageMetadata(
                stored_filename=storage_key,
                storage_location=str(file_path),
                file_size_bytes=bytes_written
            )

        except StorageError:
            raise
        except OSError as e:
            logger.error(f"Failed to store evidence: {e}")
            # Clean up partial file
            file_path.unlink(missing_ok=True)
            raise StorageError(
                f"Failed to write evidence file: {e}",
                code="STORAGE_WRITE_FAILED"
            )

    def exists(self, storage_key: str) -> bool:
        """
        Check if evidence file exists in storage.

        Args:
            storage_key: Storage key of the file

        Returns:
            True if file exists
        """
        file_path = self._get_file_path(storage_key)
        return file_path.exists() and file_path.is_file()

    def delete(self, storage_key: str) -> bool:
        """
        Delete evidence file from storage.

        Args:
            storage_key: Storage key of the file

        Returns:
            True if file was deleted, False if not found
        """
        file_path = self._get_file_path(storage_key)
        try:
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Evidence deleted: {storage_key}")
                return True
            return False
        except OSError as e:
            logger.error(f"Failed to delete evidence: {e}")
            raise StorageError(
                f"Failed to delete evidence file: {e}",
                code="STORAGE_DELETE_FAILED"
            )

    def get_metadata(self, storage_key: str) -> StorageMetadata | None:
        """
        Get metadata for stored evidence.

        Args:
            storage_key: Storage key of the file

        Returns:
            StorageMetadata if file exists, None otherwise
        """
        file_path = self._get_file_path(storage_key)
        if not file_path.exists():
            return None

        stat = file_path.stat()
        return StorageMetadata(
            stored_filename=storage_key,
            storage_location=str(file_path),
            file_size_bytes=stat.st_size
        )

    def open(self, storage_key: str) -> BinaryIO:
        """
        Open evidence file for reading.

        Args:
            storage_key: Storage key of the file

        Returns:
            File-like object for reading

        Raises:
            StorageError: If file not found or cannot be opened
        """
        file_path = self._get_file_path(storage_key)
        if not file_path.exists():
            raise StorageError(
                f"Evidence file not found: {storage_key}",
                code="STORAGE_NOT_FOUND"
            )
        try:
            return open(file_path, "rb")
        except OSError as e:
            raise StorageError(
                f"Cannot open evidence file: {e}",
                code="STORAGE_READ_FAILED"
            )

    def get_path(self, storage_key: str) -> Path:
        """
        Get the full path for a storage key.

        Args:
            storage_key: Storage key of the file

        Returns:
            Full path to the file
        """
        return self._get_file_path(storage_key)


# Global storage instance
evidence_storage = EvidenceStorage()
