"""
Pydantic schemas for scan job API endpoints.
Request bodies, response models, and list responses.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ── Request schemas ────────────────────────────────────────────────────────────

class ScanCreateRequest(BaseModel):
    aws_profile: str = Field(
        ...,
        description="AWS CLI named profile to use for scanning (read-only profile)",
        examples=["threatmapper-readonly"],
    )
    region: str = Field(
        default="us-east-1",
        description="AWS region to scan",
        examples=["us-east-1", "eu-west-1"],
    )


# ── Response schemas ───────────────────────────────────────────────────────────

class ResourceBreakdown(BaseModel):
    ec2_instances: int = 0
    iam_roles: int = 0
    iam_users: int = 0
    s3_buckets: int = 0
    vpcs: int = 0
    subnets: int = 0
    security_groups: int = 0
    rds_instances: int = 0
    lambda_functions: int = 0


class ScanJobResponse(BaseModel):
    id: UUID
    aws_account_id: Optional[str]
    aws_region: str
    aws_profile: str
    status: str
    error_message: Optional[str]
    resource_count: Optional[int]
    attack_path_count: Optional[int]
    critical_path_count: Optional[int]
    overall_risk_score: Optional[float]
    artifact_path: Optional[str]
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ScanJobListResponse(BaseModel):
    items: list[ScanJobResponse]
    total: int


class ScanCreateResponse(BaseModel):
    scan_job_id: UUID
    status: str
    message: str
