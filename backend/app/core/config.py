"""Application configuration using Pydantic settings.

Phase 5: Production hardening with security configuration.
"""
import os
import secrets
from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "SecureMailScope"
    environment: str = "development"
    debug: bool = True

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000

    # Database
    postgres_user: str = "securemailscope"
    postgres_password: str = "changeme"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "securemailscope"

    @property
    def database_url(self) -> str:
        """Construct PostgreSQL database URL."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    @property
    def redis_url(self) -> str:
        """Construct Redis URL."""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Celery
    celery_broker_url: Optional[str] = None
    celery_result_backend: Optional[str] = None

    @property
    def celery_broker(self) -> str:
        """Celery broker URL (defaults to Redis)."""
        return self.celery_broker_url or self.redis_url

    @property
    def celery_backend(self) -> str:
        """Celery result backend URL (defaults to Redis)."""
        return self.celery_result_backend or self.redis_url

    # PCAP Processing
    max_pcap_size_mb: int = 500

    # Evidence Storage
    evidence_storage_path: str = "/app/data/evidence"
    reports_storage_path: str = "/app/data/reports"
    allowed_pcap_extensions: str = ".pcap,.pcapng"

    # Storage Backend (local or s3)
    storage_backend: str = "local"  # "local" or "s3"

    # S3-Compatible Object Storage (when storage_backend=s3)
    s3_endpoint_url: str | None = None  # e.g., https://s3.amazonaws.com or R2 endpoint
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None
    s3_bucket_name: str | None = None
    s3_region: str = "us-east-1"

    @property
    def max_pcap_size_bytes(self) -> int:
        """Maximum PCAP size in bytes."""
        return self.max_pcap_size_mb * 1024 * 1024

    # TShark Configuration (Phase 2)
    tshark_binary: str = "tshark"
    tshark_timeout_seconds: int = 300

    # Logging
    log_level: str = "INFO"

    # =================================================================
    # Phase 5: Security Configuration
    # =================================================================

    # JWT Authentication
    secret_key: str = "CHANGE_ME_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Password Hashing
    password_hash_rounds: int = 12

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    rate_limit_login_requests: int = 5
    rate_limit_login_window_seconds: int = 300
    rate_limit_upload_requests: int = 10
    rate_limit_upload_window_seconds: int = 60

    # CORS - Production should use explicit origins
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins as list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    # Security Headers
    enable_security_headers: bool = True

    # Request Limits
    max_request_size_mb: int = 100
    max_json_size_kb: int = 1024

    @property
    def max_request_size_bytes(self) -> int:
        """Maximum request body size in bytes."""
        return self.max_request_size_mb * 1024 * 1024

    # Admin User (initial setup)
    admin_username: str = "admin"
    admin_email: str = "admin@securemailscope.local"
    admin_password: Optional[str] = None  # Must be set in production

    # Blockchain (optional)
    blockchain_enabled: bool = False
    blockchain_rpc_url: Optional[str] = None

    # ML Configuration
    ml_enabled: bool = True
    ml_model_path: str = "/app/data/models"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    def validate_production_config(self) -> List[str]:
        """
        Validate configuration for production deployment.
        Returns list of validation errors.
        """
        errors = []

        if self.environment == "production":
            # Secret key validation
            if self.secret_key == "CHANGE_ME_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32":
                errors.append("SECRET_KEY must be changed in production")
            if len(self.secret_key) < 32:
                errors.append("SECRET_KEY must be at least 32 characters")

            # Debug must be disabled
            if self.debug:
                errors.append("DEBUG must be False in production")

            # Database password
            if self.postgres_password in ("changeme", "password", ""):
                errors.append("POSTGRES_PASSWORD must be changed in production")

            # Admin password
            if not self.admin_password:
                errors.append("ADMIN_PASSWORD must be set in production")

            # CORS validation
            if "*" in self.cors_origins:
                errors.append("CORS_ORIGINS must not contain wildcard in production")

        return errors

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment.lower() in ("production", "prod")


# Global settings instance
settings = Settings()
