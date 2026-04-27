"""
Infrastructure Model — the normalized JSON output of a scan.

This is the canonical intermediate representation that:
  - the Graph Builder reads to construct the attack graph
  - the Clone Generator reads to produce the sandbox spec
  - is persisted to disk as a scan artifact

All scanner modules append into an InfrastructureModel instance.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Resource types ─────────────────────────────────────────────────────────────

@dataclass
class EC2Instance:
    instance_id: str
    instance_type: str
    state: str                          # running | stopped | terminated
    vpc_id: str | None
    subnet_id: str | None
    private_ip: str | None
    public_ip: str | None
    iam_instance_profile_arn: str | None
    iam_role_name: str | None           # Extracted from profile ARN
    iam_role_arn: str | None            # Resolved role ARN from instance profile
    security_group_ids: list[str]
    tags: dict[str, str]
    platform: str | None                # "windows" or None (linux)
    metadata_options: dict[str, Any]    # IMDSv1/v2 config
    region: str


@dataclass
class IAMRole:
    role_id: str
    role_name: str
    arn: str
    trust_policy: dict[str, Any]        # Who can assume this role
    inline_policies: list[dict]         # List of {name, document}
    attached_policy_arns: list[str]
    managed_policies: list[dict]        # List of {arn, name, document}
    max_session_duration: int
    tags: dict[str, str]


@dataclass
class IAMUser:
    user_id: str
    user_name: str
    arn: str
    has_console_access: bool
    has_mfa: bool
    access_keys: list[dict]             # List of {key_id, status, last_used}
    attached_policy_arns: list[str]
    inline_policies: list[dict]
    managed_policies: list[dict]        # List of {arn, name, document}
    groups: list[str]
    tags: dict[str, str]


@dataclass
class S3Bucket:
    name: str
    arn: str
    region: str
    public_access_block: dict[str, bool]  # 4 block settings
    bucket_policy: dict | None
    bucket_acl: str                         # "private" | "public-read" | etc.
    versioning_enabled: bool
    encryption_enabled: bool
    is_public: bool                         # Derived: any public path exists
    tags: dict[str, str]


@dataclass
class VPC:
    vpc_id: str
    cidr_block: str
    is_default: bool
    state: str
    tags: dict[str, str]
    region: str


@dataclass
class Subnet:
    subnet_id: str
    vpc_id: str
    cidr_block: str
    availability_zone: str
    is_public: bool                     # Has route to IGW
    map_public_ip_on_launch: bool
    tags: dict[str, str]


@dataclass
class SecurityGroup:
    group_id: str
    group_name: str
    vpc_id: str | None
    description: str
    ingress_rules: list[dict]           # [{protocol, from_port, to_port, cidr_ranges, sg_refs}]
    egress_rules: list[dict]
    tags: dict[str, str]


@dataclass
class RDSInstance:
    db_instance_id: str
    db_instance_class: str
    engine: str
    engine_version: str
    endpoint_address: str | None
    endpoint_port: int | None
    vpc_id: str | None
    subnet_group: str | None
    security_group_ids: list[str]
    publicly_accessible: bool
    multi_az: bool
    encrypted: bool
    iam_auth_enabled: bool
    tags: dict[str, str]
    region: str


@dataclass
class LambdaFunction:
    function_name: str
    function_arn: str
    runtime: str | None
    role_arn: str
    role_name: str | None               # Extracted from role ARN
    vpc_config: dict | None             # vpc_id, subnet_ids, sg_ids if VPC-attached
    environment_variables: list[str]    # Just keys — never values
    tags: dict[str, str]
    region: str


@dataclass
class NATGateway:
    nat_gateway_id: str
    vpc_id: str
    subnet_id: str                      # NAT must be in a public subnet
    state: str                          # pending | available | failed | deleting | deleted
    connectivity_type: str              # public | private
    public_ip: str | None
    tags: dict[str, str]
    region: str


@dataclass
class InternetGateway:
    igw_id: str
    vpc_id: str | None                  # Can be unattached (detached)
    state: str
    tags: dict[str, str]
    region: str


@dataclass
class VPCEndpoint:
    endpoint_id: str
    vpc_id: str
    service_name: str                   # com.amazonaws.region.s3, etc.
    endpoint_type: str                  # Gateway | Interface
    subnet_ids: list[str]               # For Interface endpoints
    security_group_ids: list[str]       # For Interface endpoints
    policy_document: dict | None        # Endpoint policy
    private_dns_enabled: bool           # For Interface endpoints
    state: str                          # pending | available | failed | deleting | deleted
    tags: dict[str, str]
    region: str


@dataclass
class Relationship:
    """A directed relationship between two resources."""
    source_id: str
    target_id: str
    rel_type: str     # network_access | assumes_role | can_access | connected_to | exposes | trusts
    properties: dict[str, Any] = field(default_factory=dict)


# ── Top-level model ────────────────────────────────────────────────────────────

@dataclass
class InfrastructureModel:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str = ""
    region: str = ""
    aws_profile: str = ""
    scan_started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scan_completed_at: str | None = None

    # Resources
    ec2_instances: list[EC2Instance] = field(default_factory=list)
    iam_roles: list[IAMRole] = field(default_factory=list)
    iam_users: list[IAMUser] = field(default_factory=list)
    s3_buckets: list[S3Bucket] = field(default_factory=list)
    vpcs: list[VPC] = field(default_factory=list)
    subnets: list[Subnet] = field(default_factory=list)
    security_groups: list[SecurityGroup] = field(default_factory=list)
    rds_instances: list[RDSInstance] = field(default_factory=list)
    lambda_functions: list[LambdaFunction] = field(default_factory=list)
    nat_gateways: list[NATGateway] = field(default_factory=list)
    internet_gateways: list[InternetGateway] = field(default_factory=list)
    vpc_endpoints: list[VPCEndpoint] = field(default_factory=list)

    # Relationships (populated by the relationship builder)
    relationships: list[Relationship] = field(default_factory=list)

    # Scan metadata
    errors: list[dict] = field(default_factory=list)   # Non-fatal scan errors

    @property
    def resource_count(self) -> int:
        return (
            len(self.ec2_instances)
            + len(self.iam_roles)
            + len(self.iam_users)
            + len(self.s3_buckets)
            + len(self.vpcs)
            + len(self.subnets)
            + len(self.security_groups)
            + len(self.rds_instances)
            + len(self.lambda_functions)
            + len(self.nat_gateways)
            + len(self.internet_gateways)
            + len(self.vpc_endpoints)
        )

    def add_error(self, service: str, operation: str, error: str) -> None:
        self.errors.append({
            "service": service,
            "operation": operation,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def to_dict(self) -> dict:
        """Serialize the entire model to a JSON-compatible dict."""
        import dataclasses
        return dataclasses.asdict(self)

    def save(self, path: Path) -> None:
        """Write the model to disk as a JSON artifact."""
        path.parent.mkdir(parents=True, exist_ok=True)
        self.scan_completed_at = datetime.now(timezone.utc).isoformat()
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: Path) -> "InfrastructureModel":
        """Load a previously saved model from disk."""
        with open(path) as f:
            data = json.load(f)
        # Simple reconstruction — nested dataclasses stay as dicts for now
        # (Graph Builder handles the full typed reconstruction)
        model = cls.__new__(cls)
        for k, v in data.items():
            setattr(model, k, v)
        return model
