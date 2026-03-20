"""
Scan API Routes

POST /scans          → create and dispatch a new scan job
GET  /scans          → list all scan jobs (paginated)
GET  /scans/{id}     → get a single scan job by ID
"""
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.scan_schemas import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanJobListResponse,
    ScanJobResponse,
)
from app.services.scan_service import (
    create_scan_job,
    dispatch_scan_task,
    get_scan_job,
    list_scan_jobs,
)

log = structlog.get_logger()
router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=201)
async def create_scan(
    body: ScanCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new infrastructure scan job and dispatch it to the worker.

    The scan runs asynchronously. Poll GET /scans/{id} for status updates.
    """
    log.info(
        "api.scan_create",
        profile=body.aws_profile,
        region=body.region,
    )

    # Create DB record
    job = await create_scan_job(
        db=db,
        aws_profile=body.aws_profile,
        region=body.region,
    )

    # Dispatch Celery task (fire and forget from API perspective)
    try:
        dispatch_scan_task(
            scan_job_id=str(job.id),
            aws_profile=body.aws_profile,
            region=body.region,
        )
    except RuntimeError as e:
        # Task dispatch failed — mark job as failed
        job.status = "failed"
        job.error_message = str(e)
        raise HTTPException(status_code=503, detail=str(e))

    return ScanCreateResponse(
        scan_job_id=job.id,
        status="pending",
        message=(
            f"Scan job created. Scanning AWS profile '{body.aws_profile}' "
            f"in region '{body.region}'. Poll GET /scans/{job.id} for status."
        ),
    )


@router.get("", response_model=ScanJobListResponse)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Return a paginated list of scan jobs, most recent first."""
    jobs, total = await list_scan_jobs(db=db, limit=limit, offset=offset)
    return ScanJobListResponse(
        items=[ScanJobResponse.model_validate(j) for j in jobs],
        total=total,
    )


@router.get("/{scan_job_id}", response_model=ScanJobResponse)
async def get_scan(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a single scan job by ID. Used for polling scan status."""
    job = await get_scan_job(db=db, scan_job_id=scan_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobResponse.model_validate(job)
