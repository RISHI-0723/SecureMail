"""Application configuration using Pydantic settings."""
import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @property
    def redis_url(self) -> str:
        """Construct Redis URL."""
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

    # Logging
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Global settings instance
settings = Settings()
