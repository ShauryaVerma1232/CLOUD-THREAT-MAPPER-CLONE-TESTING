"""
Scan Service — database operations and Celery task dispatch for scans.
"""
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import ScanJob

log = structlog.get_logger()


async def create_scan_job(
    db: AsyncSession,
    aws_profile: str,
    region: str,
) -> ScanJob:
    """Create a new scan job record and return it."""
    job = ScanJob(
        id=uuid.uuid4(),
        aws_profile=aws_profile,
        aws_region=region,
        status="pending",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.flush()  # Get the ID without committing
    await db.refresh(job)
    return job


async def get_scan_job(db: AsyncSession, scan_job_id: uuid.UUID) -> ScanJob | None:
    """Fetch a scan job by ID."""
    result = await db.execute(
        select(ScanJob).where(ScanJob.id == scan_job_id)
    )
    return result.scalar_one_or_none()


async def list_scan_jobs(
    db: AsyncSession,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[ScanJob], int]:
    """Return paginated scan jobs ordered by most recent first."""
    from sqlalchemy import func

    count_result = await db.execute(
        select(func.count()).select_from(ScanJob)
    )
    total = count_result.scalar_one()

    result = await db.execute(
        select(ScanJob)
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
        .offset(offset)
    )
    jobs = list(result.scalars().all())
    return jobs, total


def dispatch_scan_task(scan_job_id: str, aws_profile: str, region: str) -> str:
    """
    Dispatch the Celery scan task.
    Returns the Celery task ID.

    Import is deferred to avoid circular imports and to keep the
    Celery app from being loaded in contexts where it isn't needed.
    """
    # Import here to avoid loading the worker's Celery app in the backend
    import httpx
    import os

    # We call Celery indirectly via the Redis broker
    # The worker container has the task registered
    try:
        from celery import Celery
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        app = Celery(broker=redis_url)
        result = app.send_task(
            "app.tasks.scan_tasks.run_infrastructure_scan",
            kwargs={
                "scan_job_id": scan_job_id,
                "aws_profile": aws_profile,
                "region": region,
            },
            queue="scans",
        )
        log.info(
            "scan.task_dispatched",
            scan_job_id=scan_job_id,
            celery_task_id=result.id,
        )
        return result.id
    except Exception as e:
        log.error("scan.task_dispatch_error", error=str(e))
        raise RuntimeError(f"Failed to dispatch scan task: {e}")
