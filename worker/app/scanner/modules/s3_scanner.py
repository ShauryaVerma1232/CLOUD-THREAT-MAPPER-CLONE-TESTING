"""
S3 Scanner Module

Collects:
- All buckets (global, not region-scoped)
- Public access block settings
- Bucket policies
- Bucket ACLs
- Versioning and encryption status
- Derives: is_public flag
"""
import json

import structlog
from botocore.exceptions import ClientError

from app.scanner.aws_session import AWSSession
from app.scanner.model import S3Bucket, InfrastructureModel

log = structlog.get_logger()

# Public ACL grants that indicate a bucket/object is world-readable
PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _is_policy_public(policy: dict | None) -> bool:
    """Check if a bucket policy contains any public Allow statements."""
    if not policy:
        return False
    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal", {})
        # Principal: "*" or {"AWS": "*"}
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS", "")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


def _is_acl_public(acl_grants: list) -> bool:
    for grant in acl_grants:
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") in PUBLIC_GRANTEE_URIS:
            return True
    return False


def scan_s3(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all S3 buckets accessible from the current account."""
    log.info("scanner.s3.start")
    s3 = session.client("s3")

    try:
        response = AWSSession.safe_call(s3.list_buckets)
        buckets = response.get("Buckets", [])
        log.info("scanner.s3.found_buckets", count=len(buckets))

        for bucket_data in buckets:
            name = bucket_data["Name"]
            bucket_region = session.region  # default

            # ── Get bucket region ──────────────────────────────────────────────
            try:
                loc = AWSSession.safe_call(
                    s3.get_bucket_location, Bucket=name
                )
                region_raw = loc.get("LocationConstraint")
                bucket_region = region_raw if region_raw else "us-east-1"
            except ClientError:
                pass

            # ── Public access block ────────────────────────────────────────────
            public_access_block = {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
            try:
                pab = AWSSession.safe_call(
                    s3.get_public_access_block, Bucket=name
                )
                public_access_block = pab["PublicAccessBlockConfiguration"]
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    # No block configured — all defaults are permissive
                    public_access_block = {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    }

            # ── Bucket policy ──────────────────────────────────────────────────
            bucket_policy = None
            try:
                pol = AWSSession.safe_call(s3.get_bucket_policy, Bucket=name)
                bucket_policy = json.loads(pol["Policy"])
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    log.warning("s3.policy_error", bucket=name, error=str(e))

            # ── ACL ────────────────────────────────────────────────────────────
            acl_summary = "private"
            acl_grants = []
            try:
                acl_resp = AWSSession.safe_call(s3.get_bucket_acl, Bucket=name)
                acl_grants = acl_resp.get("Grants", [])
                if _is_acl_public(acl_grants):
                    acl_summary = "public"
            except ClientError as e:
                log.warning("s3.acl_error", bucket=name, error=str(e))

            # ── Versioning ─────────────────────────────────────────────────────
            versioning_enabled = False
            try:
                ver = AWSSession.safe_call(s3.get_bucket_versioning, Bucket=name)
                versioning_enabled = ver.get("Status") == "Enabled"
            except ClientError:
                pass

            # ── Encryption ────────────────────────────────────────────────────
            encryption_enabled = False
            try:
                AWSSession.safe_call(
                    s3.get_bucket_encryption, Bucket=name
                )
                encryption_enabled = True
            except ClientError as e:
                if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                    log.warning("s3.encryption_error", bucket=name, error=str(e))

            # ── Tags ───────────────────────────────────────────────────────────
            tags = {}
            try:
                tag_resp = AWSSession.safe_call(s3.get_bucket_tagging, Bucket=name)
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
            except ClientError:
                pass

            # ── Derive is_public ───────────────────────────────────────────────
            block_all = all([
                public_access_block.get("BlockPublicAcls", False),
                public_access_block.get("IgnorePublicAcls", False),
                public_access_block.get("BlockPublicPolicy", False),
                public_access_block.get("RestrictPublicBuckets", False),
            ])
            policy_public = (not block_all) and _is_policy_public(bucket_policy)
            acl_public = (not block_all) and (acl_summary == "public")
            is_public = policy_public or acl_public

            bucket = S3Bucket(
                name=name,
                arn=f"arn:aws:s3:::{name}",
                region=bucket_region,
                public_access_block=public_access_block,
                bucket_policy=bucket_policy,
                bucket_acl=acl_summary,
                versioning_enabled=versioning_enabled,
                encryption_enabled=encryption_enabled,
                is_public=is_public,
                tags=tags,
            )
            model.s3_buckets.append(bucket)

    except ClientError as e:
        model.add_error("s3", "list_buckets", str(e))
        log.warning("scanner.s3.error", error=str(e))

    log.info("scanner.s3.done", count=len(model.s3_buckets))
