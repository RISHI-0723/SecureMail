"""Evidence storage service abstraction."""
import os
import uuid
import logging
import tempfile
from pathlib import Path
from typing import BinaryIO, Protocol
from dataclasses import dataclass
from io import BytesIO

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


class S3EvidenceStorage:
    """
    S3-compatible object storage for evidence files.

    Supports AWS S3, Cloudflare R2, Backblaze B2, and other S3-compatible services.
    Both backend and worker can access the same bucket, solving the shared storage problem.
    """

    def __init__(
        self,
        bucket_name: str | None = None,
        endpoint_url: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        region: str | None = None
    ):
        """
        Initialize S3 storage.

        Args:
            bucket_name: S3 bucket name
            endpoint_url: S3 endpoint URL (for non-AWS S3)
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            region: AWS region
        """
        try:
            import boto3
            from botocore.exceptions import ClientError
            self.ClientError = ClientError
        except ImportError:
            raise StorageError(
                "boto3 is required for S3 storage. Install with: pip install boto3",
                code="STORAGE_DEPENDENCY_MISSING"
            )

        self.bucket_name = bucket_name or settings.s3_bucket_name
        if not self.bucket_name:
            raise StorageError(
                "S3_BUCKET_NAME must be configured for S3 storage",
                code="STORAGE_CONFIG_MISSING"
            )

        # Initialize S3 client
        s3_config = {
            "aws_access_key_id": access_key_id or settings.s3_access_key_id,
            "aws_secret_access_key": secret_access_key or settings.s3_secret_access_key,
            "region_name": region or settings.s3_region,
        }

        if endpoint_url or settings.s3_endpoint_url:
            s3_config["endpoint_url"] = endpoint_url or settings.s3_endpoint_url

        try:
            self.s3_client = boto3.client("s3", **s3_config)
            logger.info(
                f"S3 storage initialized: bucket={self.bucket_name}, region={s3_config['region_name']}"
            )
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {e}")
            raise StorageError(
                f"Failed to initialize S3 storage: {e}",
                code="STORAGE_INIT_FAILED"
            )

    def _generate_storage_key(self, extension: str = "") -> str:
        """Generate a unique storage key for S3 object."""
        unique_id = uuid.uuid4().hex
        # Use evidence/ prefix for organization
        return f"evidence/{unique_id}{extension}"

    def save(
        self,
        file_data: BinaryIO,
        original_filename: str,
        file_size: int | None = None
    ) -> StorageMetadata:
        """
        Save evidence file to S3.

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

        try:
            # Upload to S3
            bytes_written = 0
            chunks = []

            # Read file in chunks to avoid memory issues with large files
            while True:
                chunk = file_data.read(8192)  # 8KB chunks
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_written += len(chunk)

            # Combine chunks
            file_content = b"".join(chunks)

            # Verify size if provided
            if file_size is not None and bytes_written != file_size:
                raise StorageError(
                    f"File size mismatch: expected {file_size}, got {bytes_written}",
                    code="STORAGE_SIZE_MISMATCH"
                )

            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=storage_key,
                Body=file_content,
                ContentType="application/vnd.tcpdump.pcap",
                Metadata={
                    "original_filename": original_filename,
                    "file_size": str(bytes_written)
                }
            )

            logger.info(
                f"Evidence stored in S3: {storage_key}, size: {bytes_written} bytes",
                extra={"storage_key": storage_key, "size": bytes_written, "bucket": self.bucket_name}
            )

            return StorageMetadata(
                stored_filename=storage_key,
                storage_location=f"s3://{self.bucket_name}/{storage_key}",
                file_size_bytes=bytes_written
            )

        except self.ClientError as e:
            logger.error(f"S3 storage failed: {e}")
            raise StorageError(
                f"Failed to store evidence in S3: {e}",
                code="STORAGE_WRITE_FAILED"
            )
        except StorageError:
            raise
        except Exception as e:
            logger.error(f"Unexpected S3 error: {e}")
            raise StorageError(
                f"Failed to store evidence: {e}",
                code="STORAGE_FAILED"
            )

    def exists(self, storage_key: str) -> bool:
        """
        Check if evidence file exists in S3.

        Args:
            storage_key: Storage key of the file

        Returns:
            True if file exists
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=storage_key)
            return True
        except self.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            logger.error(f"S3 exists check failed: {e}")
            raise StorageError(
                f"Failed to check S3 object existence: {e}",
                code="STORAGE_CHECK_FAILED"
            )

    def delete(self, storage_key: str) -> bool:
        """
        Delete evidence file from S3.

        Args:
            storage_key: Storage key of the file

        Returns:
            True if file was deleted, False if not found
        """
        try:
            if not self.exists(storage_key):
                return False

            self.s3_client.delete_object(Bucket=self.bucket_name, Key=storage_key)
            logger.info(f"Evidence deleted from S3: {storage_key}")
            return True
        except self.ClientError as e:
            logger.error(f"S3 delete failed: {e}")
            raise StorageError(
                f"Failed to delete S3 object: {e}",
                code="STORAGE_DELETE_FAILED"
            )

    def get_metadata(self, storage_key: str) -> StorageMetadata | None:
        """
        Get metadata for stored evidence in S3.

        Args:
            storage_key: Storage key of the file

        Returns:
            StorageMetadata if file exists, None otherwise
        """
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=storage_key)
            return StorageMetadata(
                stored_filename=storage_key,
                storage_location=f"s3://{self.bucket_name}/{storage_key}",
                file_size_bytes=response["ContentLength"]
            )
        except self.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return None
            logger.error(f"S3 metadata retrieval failed: {e}")
            raise StorageError(
                f"Failed to get S3 object metadata: {e}",
                code="STORAGE_METADATA_FAILED"
            )

    def open(self, storage_key: str) -> BinaryIO:
        """
        Open evidence file from S3 for reading.

        Args:
            storage_key: Storage key of the file

        Returns:
            File-like object for reading

        Raises:
            StorageError: If file not found or cannot be opened
        """
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=storage_key)
            # Return the Body stream (file-like object)
            return response["Body"]
        except self.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise StorageError(
                    f"Evidence file not found in S3: {storage_key}",
                    code="STORAGE_NOT_FOUND"
                )
            logger.error(f"S3 open failed: {e}")
            raise StorageError(
                f"Failed to open S3 object: {e}",
                code="STORAGE_READ_FAILED"
            )

    def get_path(self, storage_key: str) -> Path:
        """
        Get a temporary local path for S3 object.

        Downloads the S3 object to a temporary file and returns the path.
        This is needed for TShark which requires a file path.

        Args:
            storage_key: Storage key of the file

        Returns:
            Path to temporary file containing the object

        Raises:
            StorageError: If download fails
        """
        try:
            # Create temporary file
            suffix = Path(storage_key).suffix or ".pcap"
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            temp_path = Path(temp_file.name)
            temp_file.close()

            # Download from S3
            self.s3_client.download_file(self.bucket_name, storage_key, str(temp_path))

            logger.info(
                f"Downloaded S3 object to temp file: {storage_key} -> {temp_path}",
                extra={"storage_key": storage_key, "temp_path": str(temp_path)}
            )

            return temp_path
        except self.ClientError as e:
            logger.error(f"S3 download failed: {e}")
            raise StorageError(
                f"Failed to download S3 object: {e}",
                code="STORAGE_DOWNLOAD_FAILED"
            )


def create_storage() -> EvidenceStorage | S3EvidenceStorage:
    """
    Create storage instance based on configuration.

    Returns:
        EvidenceStorage for local storage or S3EvidenceStorage for S3
    """
    backend = settings.storage_backend.lower()

    if backend == "s3":
        logger.info("Initializing S3 storage backend")
        return S3EvidenceStorage()
    elif backend == "local":
        logger.info("Initializing local filesystem storage backend")
        return EvidenceStorage()
    else:
        logger.warning(f"Unknown storage backend '{backend}', defaulting to local")
        return EvidenceStorage()


# Global storage instance
evidence_storage = create_storage()
