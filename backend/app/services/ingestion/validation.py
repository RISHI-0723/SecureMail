"""File validation service for PCAP/PCAPNG evidence.

IMPORTANT: Phase 1 validation uses ONLY magic-byte checking.
TShark, Scapy, and PyShark are NOT used for validation in Phase 1.
"""
import hashlib
import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from app.core.config import settings
from app.models.evidence import FileFormat

logger = logging.getLogger(__name__)


# PCAP magic bytes (both byte orders)
PCAP_MAGIC_LE = b'\xd4\xc3\xb2\xa1'  # Little-endian
PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'  # Big-endian
PCAP_MAGIC_NANO_LE = b'\x4d\x3c\xb2\xa1'  # Little-endian nanosecond
PCAP_MAGIC_NANO_BE = b'\xa1\xb2\x3c\x4d'  # Big-endian nanosecond

# PCAPNG magic bytes (Section Header Block)
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


class ValidationErrorCode(str, Enum):
    """Error codes for validation failures."""
    EMPTY_FILE = "EMPTY_FILE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
    INVALID_PCAP = "INVALID_PCAP"
    INVALID_PCAPNG = "INVALID_PCAPNG"
    HASHING_FAILED = "HASHING_FAILED"
    READ_ERROR = "READ_ERROR"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"


class ValidationError(Exception):
    """Exception raised when file validation fails."""
    def __init__(self, code: ValidationErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass
class ValidationResult:
    """Result of file validation."""
    valid: bool
    file_format: FileFormat
    file_size_bytes: int
    sha256: str
    error_code: str | None = None
    error_message: str | None = None

    @classmethod
    def success(
        cls,
        file_format: FileFormat,
        file_size_bytes: int,
        sha256: str
    ) -> "ValidationResult":
        """Create a successful validation result."""
        return cls(
            valid=True,
            file_format=file_format,
            file_size_bytes=file_size_bytes,
            sha256=sha256
        )

    @classmethod
    def failure(
        cls,
        code: ValidationErrorCode,
        message: str,
        file_size_bytes: int = 0
    ) -> "ValidationResult":
        """Create a failed validation result."""
        return cls(
            valid=False,
            file_format=FileFormat.UNKNOWN,
            file_size_bytes=file_size_bytes,
            sha256="",
            error_code=code.value,
            error_message=message
        )


class FileValidator:
    """
    Validator for PCAP/PCAPNG evidence files.

    This validator uses ONLY magic-byte checking and does NOT
    invoke TShark, Scapy, or PyShark. Full packet parsing
    is performed in Phase 2.
    """

    # Dangerous filename patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.',           # Parent directory
        r'^/',             # Absolute path (Unix)
        r'^[A-Za-z]:',     # Absolute path (Windows)
        r'\\',             # Backslash
        r'\x00',           # Null byte
    ]

    def __init__(self, max_size_mb: int | None = None):
        """
        Initialize the file validator.

        Args:
            max_size_mb: Maximum file size in MB. Defaults to settings.
        """
        # Use 'is not None' to allow max_size_mb=0 for testing
        if max_size_mb is not None:
            self.max_size_bytes = max_size_mb * 1024 * 1024
        else:
            self.max_size_bytes = settings.max_pcap_size_mb * 1024 * 1024

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal attacks.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename (basename only)

        Raises:
            ValidationError: If filename contains dangerous patterns
        """
        if not filename:
            return "unknown"

        # Check for dangerous patterns
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, filename):
                logger.warning(
                    f"Path traversal attempt detected: {filename[:100]}"
                )
                raise ValidationError(
                    ValidationErrorCode.PATH_TRAVERSAL,
                    "Filename contains invalid characters or path components"
                )

        # Extract basename safely
        safe_name = Path(filename).name

        # Remove any remaining problematic characters
        safe_name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', safe_name)

        # Limit length
        if len(safe_name) > 255:
            name, ext = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
            safe_name = name[:250] + ('.' + ext if ext else '')

        return safe_name or "unknown"

    def validate_size(self, file_size: int) -> None:
        """
        Validate file size.

        Args:
            file_size: File size in bytes

        Raises:
            ValidationError: If file is empty or too large
        """
        if file_size == 0:
            raise ValidationError(
                ValidationErrorCode.EMPTY_FILE,
                "File is empty. PCAP/PCAPNG files must contain data."
            )

        if file_size > self.max_size_bytes:
            max_mb = self.max_size_bytes / (1024 * 1024)
            actual_mb = file_size / (1024 * 1024)
            raise ValidationError(
                ValidationErrorCode.FILE_TOO_LARGE,
                f"File size ({actual_mb:.2f} MB) exceeds maximum allowed size ({max_mb:.0f} MB)."
            )

    def detect_format(self, header_bytes: bytes, filename: str) -> FileFormat:
        """
        Detect file format from magic bytes.

        Args:
            header_bytes: First bytes of the file (at least 4 bytes)
            filename: Original filename (for extension hint)

        Returns:
            Detected FileFormat

        Raises:
            ValidationError: If format is not supported
        """
        if len(header_bytes) < 4:
            raise ValidationError(
                ValidationErrorCode.UNSUPPORTED_FILE_TYPE,
                "File is too small to identify format."
            )

        magic = header_bytes[:4]

        # Check for PCAPNG first (more specific check)
        if magic == PCAPNG_MAGIC:
            return FileFormat.PCAPNG

        # Check for PCAP (both byte orders)
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NANO_LE, PCAP_MAGIC_NANO_BE):
            return FileFormat.PCAP

        # Format not recognized
        ext = Path(filename).suffix.lower()
        if ext == '.pcap':
            raise ValidationError(
                ValidationErrorCode.INVALID_PCAP,
                "File has .pcap extension but does not contain valid PCAP magic bytes."
            )
        elif ext == '.pcapng':
            raise ValidationError(
                ValidationErrorCode.INVALID_PCAPNG,
                "File has .pcapng extension but does not contain valid PCAPNG magic bytes."
            )
        else:
            raise ValidationError(
                ValidationErrorCode.UNSUPPORTED_FILE_TYPE,
                f"Unsupported file type. Only PCAP and PCAPNG files are supported. "
                f"Detected extension: {ext or 'none'}"
            )

    def calculate_sha256_streaming(self, file_data: BinaryIO) -> str:
        """
        Calculate SHA-256 hash using streaming to handle large files.

        Args:
            file_data: File-like object to hash

        Returns:
            Hexadecimal SHA-256 digest

        Raises:
            ValidationError: If hashing fails
        """
        try:
            sha256 = hashlib.sha256()
            # Reset to beginning
            file_data.seek(0)

            while True:
                chunk = file_data.read(65536)  # 64KB chunks
                if not chunk:
                    break
                sha256.update(chunk)

            # Reset for subsequent reads
            file_data.seek(0)
            return sha256.hexdigest()

        except Exception as e:
            logger.error(f"SHA-256 calculation failed: {e}")
            raise ValidationError(
                ValidationErrorCode.HASHING_FAILED,
                f"Failed to calculate file hash: {e}"
            )

    def validate(
        self,
        file_data: BinaryIO,
        filename: str,
        file_size: int
    ) -> ValidationResult:
        """
        Validate an uploaded evidence file.

        This method performs:
        1. Filename sanitization
        2. Size validation
        3. Magic byte detection
        4. SHA-256 calculation

        Args:
            file_data: File-like object containing evidence
            filename: Original filename
            file_size: File size in bytes

        Returns:
            ValidationResult with validation outcome

        Note:
            This method does NOT use TShark, Scapy, or PyShark.
            It performs only lightweight magic-byte validation.
        """
        try:
            # 1. Sanitize filename (raises ValidationError if dangerous)
            safe_filename = self.sanitize_filename(filename)

            # 2. Validate size
            self.validate_size(file_size)

            # 3. Read header for magic byte detection
            file_data.seek(0)
            header = file_data.read(32)  # Read first 32 bytes
            if len(header) < 4:
                raise ValidationError(
                    ValidationErrorCode.EMPTY_FILE,
                    "File is too small to be a valid capture file."
                )

            # 4. Detect format from magic bytes
            file_format = self.detect_format(header, filename)

            # 5. Calculate SHA-256 (streaming)
            sha256 = self.calculate_sha256_streaming(file_data)

            logger.info(
                f"File validated: {safe_filename}, format: {file_format.value}, "
                f"size: {file_size}, sha256: {sha256[:16]}...",
                extra={
                    "file_name": safe_filename,
                    "file_format": file_format.value,
                    "file_size": file_size,
                    "sha256_prefix": sha256[:16]
                }
            )

            return ValidationResult.success(
                file_format=file_format,
                file_size_bytes=file_size,
                sha256=sha256
            )

        except ValidationError as e:
            logger.warning(
                f"File validation failed: {e.code.value} - {e.message}",
                extra={"error_code": e.code.value}
            )
            return ValidationResult.failure(
                code=e.code,
                message=e.message,
                file_size_bytes=file_size
            )

        except Exception as e:
            logger.error(f"Unexpected validation error: {e}")
            return ValidationResult.failure(
                code=ValidationErrorCode.READ_ERROR,
                message=f"Failed to read file: {e}",
                file_size_bytes=file_size
            )


# Global validator instance
file_validator = FileValidator()
