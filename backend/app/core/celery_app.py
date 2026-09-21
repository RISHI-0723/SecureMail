"""Celery application configuration."""
from celery import Celery

from app.core.config import settings

# Create Celery application
celery_app = Celery(
    "securemailscope",
    broker=settings.celery_broker,
    backend=settings.celery_backend,
    include=["app.workers.tasks", "app.workers.security_tasks"]
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    # Celery 6.0+ compatibility: explicitly enable broker connection retry on startup
    broker_connection_retry_on_startup=True,
)
