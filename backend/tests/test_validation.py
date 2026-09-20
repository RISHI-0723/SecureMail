"""Tests for file validation service."""
import io
import hashlib
import pytest

from app.services.ingestion.validation import (
    FileValidator,
    ValidationResult,
    ValidationError,
    ValidationErrorCode,
)
from app.models.evidence import FileFormat


class TestFileValidator:
    """Tests for FileValidator class."""

    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization."""
        validator = FileValidator()
        assert validator.sanitize_filename("test.pcap") == "test.pcap"
        assert validator.sanitize_filename("my file.pcap") == "my file.pcap"

    def test_sanitize_filename_path_traversal(self):
        """Test path traversal prevention."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.sanitize_filename("../secret.pcap")
        assert exc_info.value.code == ValidationErrorCode.PATH_TRAVERSAL

        with pytest.raises(ValidationError) as exc_info:
            validator.sanitize_filename("..\\secret.pcap")
        assert exc_info.value.code == ValidationErrorCode.PATH_TRAVERSAL

    def test_sanitize_filename_absolute_path_unix(self):
        """Test absolute path rejection (Unix)."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.sanitize_filename("/etc/passwd")
        assert exc_info.value.code == ValidationErrorCode.PATH_TRAVERSAL

    def test_sanitize_filename_absolute_path_windows(self):
        """Test absolute path rejection (Windows)."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.sanitize_filename("C:\\Windows\\System32\\test.pcap")
        assert exc_info.value.code == ValidationErrorCode.PATH_TRAVERSAL

    def test_sanitize_filename_empty(self):
        """Test empty filename handling."""
        validator = FileValidator()
        assert validator.sanitize_filename("") == "unknown"
        assert validator.sanitize_filename(None) == "unknown"

    def test_validate_size_empty_file(self):
        """Test empty file rejection."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_size(0)
        assert exc_info.value.code == ValidationErrorCode.EMPTY_FILE

    def test_validate_size_too_large(self):
        """Test file size limit enforcement."""
        validator = FileValidator(max_size_mb=1)  # 1 MB limit

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_size(2 * 1024 * 1024)  # 2 MB
        assert exc_info.value.code == ValidationErrorCode.FILE_TOO_LARGE

    def test_validate_size_valid(self):
        """Test valid file size acceptance."""
        validator = FileValidator(max_size_mb=10)
        # Should not raise
        validator.validate_size(1 * 1024 * 1024)  # 1 MB

    def test_detect_format_pcap_little_endian(self, valid_pcap_bytes):
        """Test PCAP detection (little-endian)."""
        validator = FileValidator()
        file_format = validator.detect_format(valid_pcap_bytes, "test.pcap")
        assert file_format == FileFormat.PCAP

    def test_detect_format_pcap_big_endian(self, valid_pcap_be_bytes):
        """Test PCAP detection (big-endian)."""
        validator = FileValidator()
        file_format = validator.detect_format(valid_pcap_be_bytes, "test.pcap")
        assert file_format == FileFormat.PCAP

    def test_detect_format_pcapng(self, valid_pcapng_bytes):
        """Test PCAPNG detection."""
        validator = FileValidator()
        file_format = validator.detect_format(valid_pcapng_bytes, "test.pcapng")
        assert file_format == FileFormat.PCAPNG

    def test_detect_format_invalid_pcap_extension(self, invalid_file_bytes):
        """Test invalid file with .pcap extension."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.detect_format(invalid_file_bytes, "test.pcap")
        assert exc_info.value.code == ValidationErrorCode.INVALID_PCAP

    def test_detect_format_invalid_pcapng_extension(self, invalid_file_bytes):
        """Test invalid file with .pcapng extension."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.detect_format(invalid_file_bytes, "test.pcapng")
        assert exc_info.value.code == ValidationErrorCode.INVALID_PCAPNG

    def test_detect_format_unsupported(self, jpg_file_bytes):
        """Test unsupported file type rejection."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.detect_format(jpg_file_bytes, "image.jpg")
        assert exc_info.value.code == ValidationErrorCode.UNSUPPORTED_FILE_TYPE

    def test_detect_format_too_small(self):
        """Test file too small to identify."""
        validator = FileValidator()

        with pytest.raises(ValidationError) as exc_info:
            validator.detect_format(b"AB", "test.pcap")
        assert exc_info.value.code == ValidationErrorCode.UNSUPPORTED_FILE_TYPE

    def test_calculate_sha256_streaming(self, valid_pcap_bytes):
        """Test streaming SHA-256 calculation."""
        validator = FileValidator()
        file_data = io.BytesIO(valid_pcap_bytes)

        sha256 = validator.calculate_sha256_streaming(file_data)

        # Calculate expected hash
        expected = hashlib.sha256(valid_pcap_bytes).hexdigest()
        assert sha256 == expected

    def test_calculate_sha256_streaming_large_file(self):
        """Test SHA-256 with larger data."""
        validator = FileValidator()
        # Create 1 MB of data
        large_data = b"x" * (1024 * 1024)
        file_data = io.BytesIO(large_data)

        sha256 = validator.calculate_sha256_streaming(file_data)

        expected = hashlib.sha256(large_data).hexdigest()
        assert sha256 == expected

    def test_validate_complete_pcap(self, valid_pcap_bytes):
        """Test complete validation of valid PCAP."""
        validator = FileValidator(max_size_mb=10)
        file_data = io.BytesIO(valid_pcap_bytes)

        result = validator.validate(file_data, "test.pcap", len(valid_pcap_bytes))

        assert result.valid is True
        assert result.file_format == FileFormat.PCAP
        assert result.file_size_bytes == len(valid_pcap_bytes)
        assert len(result.sha256) == 64  # SHA-256 hex digest length
        assert result.error_code is None

    def test_validate_complete_pcapng(self, valid_pcapng_bytes):
        """Test complete validation of valid PCAPNG."""
        validator = FileValidator(max_size_mb=10)
        file_data = io.BytesIO(valid_pcapng_bytes)

        result = validator.validate(file_data, "test.pcapng", len(valid_pcapng_bytes))

        assert result.valid is True
        assert result.file_format == FileFormat.PCAPNG
        assert result.file_size_bytes == len(valid_pcapng_bytes)

    def test_validate_empty_file(self):
        """Test validation of empty file."""
        validator = FileValidator()
        file_data = io.BytesIO(b"")

        result = validator.validate(file_data, "empty.pcap", 0)

        assert result.valid is False
        assert result.error_code == ValidationErrorCode.EMPTY_FILE.value

    def test_validate_oversized_file(self, valid_pcap_bytes):
        """Test validation of oversized file."""
        validator = FileValidator(max_size_mb=0)  # 0 MB limit
        file_data = io.BytesIO(valid_pcap_bytes)

        result = validator.validate(file_data, "test.pcap", len(valid_pcap_bytes))

        assert result.valid is False
        assert result.error_code == ValidationErrorCode.FILE_TOO_LARGE.value

    def test_validate_invalid_format(self, text_file_bytes):
        """Test validation of invalid file format."""
        validator = FileValidator(max_size_mb=10)
        file_data = io.BytesIO(text_file_bytes)

        result = validator.validate(file_data, "readme.txt", len(text_file_bytes))

        assert result.valid is False
        assert result.error_code == ValidationErrorCode.UNSUPPORTED_FILE_TYPE.value

    def test_validate_path_traversal(self, valid_pcap_bytes):
        """Test validation rejects path traversal."""
        validator = FileValidator(max_size_mb=10)
        file_data = io.BytesIO(valid_pcap_bytes)

        result = validator.validate(file_data, "../../../etc/passwd", len(valid_pcap_bytes))

        assert result.valid is False
        assert result.error_code == ValidationErrorCode.PATH_TRAVERSAL.value


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_success_factory(self):
        """Test success factory method."""
        result = ValidationResult.success(
            file_format=FileFormat.PCAP,
            file_size_bytes=1024,
            sha256="abc123"
        )

        assert result.valid is True
        assert result.file_format == FileFormat.PCAP
        assert result.file_size_bytes == 1024
        assert result.sha256 == "abc123"
        assert result.error_code is None

    def test_failure_factory(self):
        """Test failure factory method."""
        result = ValidationResult.failure(
            code=ValidationErrorCode.EMPTY_FILE,
            message="File is empty"
        )

        assert result.valid is False
        assert result.file_format == FileFormat.UNKNOWN
        assert result.error_code == "EMPTY_FILE"
        assert result.error_message == "File is empty"
