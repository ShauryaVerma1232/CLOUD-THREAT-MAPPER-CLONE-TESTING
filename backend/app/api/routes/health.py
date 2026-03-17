"""
Health check endpoints.
Used by Docker Compose, load balancers, and the frontend to verify service status.
"""
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, get_neo4j_driver
from app.core.config import get_settings

log = structlog.get_logger()
router = APIRouter(prefix="/health", tags=["health"])
settings = get_settings()


@router.get("")
async def health_check():
    """Basic liveness probe — returns 200 if the process is running."""
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """
    Readiness probe — checks all downstream dependencies.
    Returns 200 only when PostgreSQL and Neo4j are reachable.
    """
    checks = {
        "postgres": False,
        "neo4j": False,
    }
    errors = {}

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    try:
        await db.execute(text("SELECT 1"))
        checks["postgres"] = True
    except Exception as e:
        errors["postgres"] = str(e)
        log.warning("health.postgres_fail", error=str(e))

    # ── Neo4j ──────────────────────────────────────────────────────────────────
    try:
        driver = get_neo4j_driver()
        await driver.verify_connectivity()
        checks["neo4j"] = True
    except Exception as e:
        errors["neo4j"] = str(e)
        log.warning("health.neo4j_fail", error=str(e))

    all_ok = all(checks.values())

    return {
        "status": "ready" if all_ok else "degraded",
        "checks": checks,
        "errors": errors if errors else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
