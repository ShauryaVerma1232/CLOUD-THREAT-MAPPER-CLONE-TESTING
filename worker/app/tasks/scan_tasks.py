"""
Scan Celery Tasks — fixed DB update syntax.
"""
import os
from datetime import datetime, timezone

import structlog
from celery import Task

from app.celery_app import celery_app
from app.scanner.scanner import run_scan, ScannerError
from app.tasks.db_utils import update_scan_job

log = structlog.get_logger()


@celery_app.task(
    bind=True,
    name="app.tasks.scan_tasks.run_infrastructure_scan",
    max_retries=1,
    soft_time_limit=1800,
    time_limit=2100,
)
def run_infrastructure_scan(self: Task, scan_job_id: str, aws_profile: str, region: str) -> dict:
    """Execute a full AWS infrastructure scan."""
    log.info("scan_task.started", task_id=self.request.id,
             scan_job_id=scan_job_id, profile=aws_profile, region=region)

    update_scan_job(scan_job_id, {
        "status": "running",
        "updated_at": datetime.now(timezone.utc),
    })

    artifacts_dir = os.environ.get("ARTIFACTS_DIR", "/app/artifacts")

    try:
        summary = run_scan(
            profile=aws_profile,
            region=region,
            scan_id=scan_job_id,
            artifacts_dir=artifacts_dir,
        )
        update_scan_job(scan_job_id, {
            "status": "complete",
            "aws_account_id": summary["account_id"],
            "resource_count": summary["resource_count"],
            "artifact_path": summary["artifact_path"],
            "updated_at": datetime.now(timezone.utc),
            "completed_at": datetime.now(timezone.utc),
        })
        log.info("scan_task.complete", scan_job_id=scan_job_id,
                 resource_count=summary["resource_count"])
        return summary

    except ScannerError as e:
        log.warning("scan_task.scanner_error", scan_job_id=scan_job_id, error=str(e))
        update_scan_job(scan_job_id, {
            "status": "failed",
            "error_message": str(e),
            "updated_at": datetime.now(timezone.utc),
        })
        raise

    except Exception as e:
        log.error("scan_task.unexpected_error", scan_job_id=scan_job_id, error=str(e))
        update_scan_job(scan_job_id, {
            "status": "failed",
            "error_message": f"Unexpected error: {str(e)}",
            "updated_at": datetime.now(timezone.utc),
        })
        raise


@celery_app.task(name="app.tasks.scan_tasks.run_full_pipeline")
def run_full_pipeline(scan_job_id: str, aws_profile: str, region: str) -> dict:
    from celery import chain
    return chain(
        run_infrastructure_scan.si(scan_job_id, aws_profile, region),
        _chain_graph_build.s(scan_job_id),
    ).apply_async()


@celery_app.task(name="app.tasks.scan_tasks._chain_graph_build")
def _chain_graph_build(scan_result: dict, scan_job_id: str):
    from app.tasks.graph_tasks import build_attack_graph
    artifact_path = scan_result.get("artifact_path", "")
    if artifact_path:
        build_attack_graph.delay(scan_job_id=scan_job_id, artifact_path=artifact_path)
    return scan_result
