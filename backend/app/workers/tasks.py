"""Celery tasks for Phase 0 foundation testing."""
import logging
from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.health_check_task")
def health_check_task() -> dict[str, str]:
    """Simple health check task to verify Celery is working.

    Returns:
        Task execution status
    """
    logger.info("Health check task executed successfully")
    return {
        "status": "success",
        "message": "Celery worker is operational"
    }
