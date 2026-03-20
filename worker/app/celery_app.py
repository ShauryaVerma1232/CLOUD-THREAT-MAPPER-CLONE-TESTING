"""
Celery application instance and task router for the Threat Mapper worker.
"""
import os

from celery import Celery
import structlog

log = structlog.get_logger()

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "threat_mapper",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.graph_tasks",
        "app.tasks.ai_tasks",
        # Future: "app.tasks.sandbox_tasks",
        # Future: "app.tasks.test_tasks",
    ],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Task behavior
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,       # One task at a time per worker (important for long scans)

    # Result retention
    result_expires=86400,               # Keep results for 24 hours

    # Task routing
    task_routes={
        "scan_tasks.*":    {"queue": "scans"},
        "tasks.graph_tasks.*":   {"queue": "graph"},
        "tasks.sandbox_tasks.*": {"queue": "sandbox"},
        "tasks.test_tasks.*":    {"queue": "testing"},
    },

    # Default queue
    task_default_queue="default",
)
