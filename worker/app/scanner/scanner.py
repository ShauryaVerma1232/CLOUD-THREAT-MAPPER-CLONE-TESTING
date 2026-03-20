"""
Infrastructure Scanner — Main Orchestrator

Runs all scanner modules in sequence, builds relationships,
and saves the resulting InfrastructureModel as a JSON artifact.
"""
from pathlib import Path

import structlog

from app.scanner.aws_session import AWSSession, AWSSessionError
from app.scanner.model import InfrastructureModel
from app.scanner.relationship_builder import build_relationships
from app.scanner.modules.ec2_scanner import (
    scan_ec2, scan_security_groups, scan_vpcs, scan_subnets,
)
from app.scanner.modules.iam_scanner import scan_iam_roles, scan_iam_users
from app.scanner.modules.s3_scanner import scan_s3
from app.scanner.modules.rds_scanner import scan_rds
from app.scanner.modules.lambda_scanner import scan_lambda

log = structlog.get_logger()


class ScannerError(Exception):
    pass


def run_scan(
    profile: str,
    region: str,
    scan_id: str,
    artifacts_dir: str = "/app/artifacts",
) -> dict:
    """
    Execute a full infrastructure scan.

    Args:
        profile:       AWS CLI profile name (read-only)
        region:        AWS region to scan
        scan_id:       UUID string for this scan job
        artifacts_dir: Path where the JSON model will be saved

    Returns:
        dict with scan summary (resource_count, artifact_path, errors)
    """
    log.info("scan.start", profile=profile, region=region, scan_id=scan_id)

    # ── Create session ────────────────────────────────────────────────────────
    try:
        session = AWSSession(profile=profile, region=region)
        account_id = session.get_account_id()
    except AWSSessionError as e:
        raise ScannerError(str(e))

    # ── Initialize model ──────────────────────────────────────────────────────
    model = InfrastructureModel(
        scan_id=scan_id,
        account_id=account_id,
        region=region,
        aws_profile=profile,
    )

    # ── Run scanner modules ───────────────────────────────────────────────────
    # Order matters: VPC/subnet/SG must run before EC2
    # IAM must run before relationship builder
    modules = [
        ("VPC",              lambda: scan_vpcs(session, model)),
        ("Subnets",          lambda: scan_subnets(session, model)),
        ("Security Groups",  lambda: scan_security_groups(session, model)),
        ("EC2 Instances",    lambda: scan_ec2(session, model)),
        ("IAM Roles",        lambda: scan_iam_roles(session, model)),
        ("IAM Users",        lambda: scan_iam_users(session, model)),
        ("S3 Buckets",       lambda: scan_s3(session, model)),
        ("RDS Instances",    lambda: scan_rds(session, model)),
        ("Lambda Functions", lambda: scan_lambda(session, model)),
    ]

    for name, fn in modules:
        try:
            log.info("scan.module_start", module=name)
            fn()
            log.info("scan.module_done", module=name)
        except Exception as e:
            # Non-fatal: record the error and continue
            log.warning("scan.module_error", module=name, error=str(e))
            model.add_error(name, "scan", str(e))

    # ── Build relationships ───────────────────────────────────────────────────
    build_relationships(model)

    # ── Save artifact ─────────────────────────────────────────────────────────
    artifact_dir = Path(artifacts_dir) / scan_id 
    artifact_dir.mkdir(parents=True, exist_ok=True)
    
    artifact_path = artifact_dir / "infrastructure_model.json"
    model.save(artifact_path)
    log.info("scan.artifact_saved", path=str(artifact_path))

    summary = {
        "scan_id": scan_id,
        "account_id": account_id,
        "region": region,
        "resource_count": model.resource_count,
        "relationship_count": len(model.relationships),
        "error_count": len(model.errors),
        "artifact_path": str(artifact_path),
        "resources": {
            "ec2_instances":    len(model.ec2_instances),
            "iam_roles":        len(model.iam_roles),
            "iam_users":        len(model.iam_users),
            "s3_buckets":       len(model.s3_buckets),
            "vpcs":             len(model.vpcs),
            "subnets":          len(model.subnets),
            "security_groups":  len(model.security_groups),
            "rds_instances":    len(model.rds_instances),
            "lambda_functions": len(model.lambda_functions),
        },
    }

    log.info("scan.complete", **summary)
    return summary
