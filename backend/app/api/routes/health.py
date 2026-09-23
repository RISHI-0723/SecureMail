"""Health check endpoints."""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
import redis

from app.core.database import get_db
from app.core.config import settings
from app.schemas.health import HealthResponse, DependenciesHealthResponse, DependencyStatus

logger = logging.getLogger(__name__)
router = APIRouter()

APP_VERSION = "0.5.0"


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Basic liveness health check.

    Returns:
        Health status indicating the API is running
    """
    return HealthResponse(
        status="healthy",
        service="SecureMailScope API",
        version=APP_VERSION
    )


@router.get("/health/dependencies", response_model=DependenciesHealthResponse, tags=["Health"])
async def dependencies_health_check(db: Session = Depends(get_db)) -> DependenciesHealthResponse:
    """Detailed health check including all system dependencies.

    Args:
        db: Database session

    Returns:
        Detailed health status of all system components
    """
    dependencies = []

    # Check PostgreSQL
    postgres_status = _check_postgres(db)
    dependencies.append(postgres_status)

    # Check Redis
    redis_status = _check_redis()
    dependencies.append(redis_status)

    # Determine overall status
    statuses = [dep.status for dep in dependencies]
    if all(s == "healthy" for s in statuses):
        overall_status = "healthy"
    elif any(s == "unhealthy" for s in statuses):
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return DependenciesHealthResponse(
        status=overall_status,
        service="SecureMailScope API",
        version=APP_VERSION,
        dependencies=dependencies
    )


def _check_postgres(db: Session) -> DependencyStatus:
    """Check PostgreSQL connection.

    Args:
        db: Database session

    Returns:
        PostgreSQL health status
    """
    try:
        db.execute(text("SELECT 1"))
        return DependencyStatus(
            name="PostgreSQL",
            status="healthy",
            message="Database connection successful"
        )
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {str(e)}")
        return DependencyStatus(
            name="PostgreSQL",
            status="unhealthy",
            message="Database connection failed"
        )


def _check_redis() -> DependencyStatus:
    """Check Redis connection.

    In demo mode (when analysis_execution_mode == "demo"), Redis is optional.
    In Celery mode, Redis is required.

    Returns:
        Redis health status
    """
    # Demo mode: Redis is optional
    if settings.analysis_execution_mode == "demo":
        return DependencyStatus(
            name="Redis",
            status="degraded",
            message="Redis not required in demo mode"
        )

    # Celery mode: Redis is required
    try:
        redis_client = redis.from_url(settings.redis_url, socket_connect_timeout=2)
        redis_client.ping()
        redis_client.close()
        return DependencyStatus(
            name="Redis",
            status="healthy",
            message="Redis connection successful"
        )
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        return DependencyStatus(
            name="Redis",
            status="unhealthy",
            message="Redis connection failed"
        )
