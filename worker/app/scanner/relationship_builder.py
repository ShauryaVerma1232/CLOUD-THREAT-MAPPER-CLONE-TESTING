"""
Relationship Builder

Takes a fully populated InfrastructureModel (all resource lists filled)
and derives all security relationships (edges) between resources.

These relationships feed directly into the graph builder in Day 3.
"""
import fnmatch
import structlog

from app.scanner.model import InfrastructureModel, Relationship

log = structlog.get_logger()


def build_relationships(model: InfrastructureModel) -> None:
    """
    Derive all relationships and append them to model.relationships.
    Called after all scanner modules have run.
    """
    log.info("relationships.building")
    before = len(model.relationships)

    # Core resource relationships
    _ec2_to_iam_role(model)
    _ec2_to_security_group(model)
    _security_group_references(model)
    _iam_user_assume_role_policies(model)
    _ec2_public_exposure(model)
    _lambda_to_iam_role(model)
    _lambda_to_vpc(model)
    _lambda_iam_invoke(model)
    _iam_role_trust_relationships(model)
    _rds_public_exposure(model)
    _iam_to_rds_access(model)
    _s3_public_exposure(model)
    _iam_to_s3_access(model)
    _subnet_to_vpc(model)
    _ec2_to_subnet(model)
    _ec2_to_vpc(model)
    _rds_to_security_group(model)

    # Network gateway relationships
    _nat_to_vpc_subnet(model)
    _igw_to_vpc(model)
    _internet_to_nat_gateway(model)
    _subnet_to_nat_gateway(model)

    # VPC Endpoint relationships
    _vpce_to_vpc_subnet_sg(model)
    _vpce_to_s3_rds(model)

    # IAM privilege escalation capabilities
    _iam_to_ec2_create(model)
    _iam_to_lambda_create(model)
    _iam_to_iam_modify(model)

    added = len(model.relationships) - before
    log.info("relationships.done", added=added, total=len(model.relationships))


# ── IAM User → Role (can_assume via sts:AssumeRole policy) ────────────────────
def _iam_user_assume_role_policies(model: InfrastructureModel) -> None:
    """
    Find IAM users who have policies granting sts:AssumeRole on specific roles.
    This creates potential privilege escalation paths.
    """
    role_arns = {r.arn for r in model.iam_roles}

    for user in model.iam_users:
        assume_role_targets = set()

        # Check inline policies
        for policy in user.inline_policies:
            doc = policy.get("document", {})
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "sts:AssumeRole" in actions or "sts:*" in actions:
                    resource = stmt.get("Resource", "*")
                    if isinstance(resource, str):
                        resource = [resource]
                    for r in resource:
                        if r != "*" and r in role_arns:
                            assume_role_targets.add(r)

        # Check attached policies (managed policies)
        for policy in user.attached_policy_arns:
            # For managed policies, we'd need to fetch the policy document
            # For now, we rely on inline policies and role trust relationships
            pass

        # Add relationships for each role the user can assume
        for role_arn in assume_role_targets:
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id=role_arn,
                rel_type="can_assume",
                properties={"via": "sts_assume_role_policy"},
            ))


# ── EC2 → IAM Role (assumes_role) ─────────────────────────────────────────────
def _ec2_to_iam_role(model: InfrastructureModel) -> None:
    role_by_name = {r.role_name: r for r in model.iam_roles}
    role_by_arn = {r.arn: r for r in model.iam_roles}
    for inst in model.ec2_instances:
        # First try to match by resolved role ARN
        if inst.iam_role_arn and inst.iam_role_arn in role_by_arn:
            role = role_by_arn[inst.iam_role_arn]
            model.relationships.append(Relationship(
                source_id=inst.instance_id,
                target_id=role.arn,
                rel_type="assumes_role",
                properties={"via": "instance_profile"},
            ))
        # Fallback to matching by role name
        elif inst.iam_role_name and inst.iam_role_name in role_by_name:
            role = role_by_name[inst.iam_role_name]
            model.relationships.append(Relationship(
                source_id=inst.instance_id,
                target_id=role.arn,
                rel_type="assumes_role",
                properties={"via": "instance_profile"},
            ))


# ── EC2 → Security Group (connected_to) ───────────────────────────────────────
def _ec2_to_security_group(model: InfrastructureModel) -> None:
    sg_ids = {sg.group_id for sg in model.security_groups}
    for inst in model.ec2_instances:
        for sg_id in inst.security_group_ids:
            if sg_id in sg_ids:
                model.relationships.append(Relationship(
                    source_id=sg_id,
                    target_id=inst.instance_id,
                    rel_type="connected_to",
                    properties={"attachment": "instance_sg"},
                ))


# ── Security Group → Security Group (references via ingress rules) ────────────
def _security_group_references(model: InfrastructureModel) -> None:
    """
    Security groups can reference other security groups in ingress rules.
    This creates potential lateral movement paths: if SG-A allows traffic from SG-B,
    and SG-B is attached to a compromised resource, traffic can flow through.
    """
    sg_by_id = {sg.group_id: sg for sg in model.security_groups}

    for sg in model.security_groups:
        for rule in sg.ingress_rules:
            for sg_ref in rule.get("sg_refs", []):
                ref_sg_id = sg_ref.get("group_id")
                if ref_sg_id and ref_sg_id in sg_by_id and ref_sg_id != sg.group_id:
                    # Traffic can flow from resources attached to ref_sg → this sg
                    model.relationships.append(Relationship(
                        source_id=ref_sg_id,
                        target_id=sg.group_id,
                        rel_type="references",
                        properties={
                            "via": "security_group_ingress",
                            "protocol": rule.get("protocol"),
                            "from_port": rule.get("from_port"),
                            "to_port": rule.get("to_port"),
                        },
                    ))


# ── Internet → EC2 (exposes) via public SG rules ──────────────────────────────
def _ec2_public_exposure(model: InfrastructureModel) -> None:
    """
    If a security group has an ingress rule allowing traffic from 0.0.0.0/0
    AND is attached to an EC2 instance, add Internet → EC2 exposes edge.
    """
    # Build: sg_id → list of exposed ports
    sg_exposed_ports: dict[str, list[dict]] = {}
    for sg in model.security_groups:
        for rule in sg.ingress_rules:
            for cidr in rule.get("cidr_ranges", []):
                if cidr in ("0.0.0.0/0", "::/0"):
                    if sg.group_id not in sg_exposed_ports:
                        sg_exposed_ports[sg.group_id] = []
                    sg_exposed_ports[sg.group_id].append({
                        "protocol": rule["protocol"],
                        "from_port": rule["from_port"],
                        "to_port": rule["to_port"],
                    })

    for inst in model.ec2_instances:
        if inst.state != "running":
            continue
        exposed_via = []
        for sg_id in inst.security_group_ids:
            if sg_id in sg_exposed_ports:
                exposed_via.extend(sg_exposed_ports[sg_id])

        if exposed_via:
            model.relationships.append(Relationship(
                source_id="INTERNET",
                target_id=inst.instance_id,
                rel_type="exposes",
                properties={
                    "public_ip": inst.public_ip,
                    "exposed_ports": exposed_via,
                    "has_public_ip": inst.public_ip is not None,
                },
            ))


# ── Lambda → IAM Role (assumes_role) ──────────────────────────────────────────
def _lambda_to_iam_role(model: InfrastructureModel) -> None:
    role_by_arn = {r.arn: r for r in model.iam_roles}
    for fn in model.lambda_functions:
        if fn.role_arn in role_by_arn:
            model.relationships.append(Relationship(
                source_id=fn.function_arn,
                target_id=fn.role_arn,
                rel_type="assumes_role",
                properties={"via": "lambda_execution_role"},
            ))


# ── Lambda → VPC (connected_to) ───────────────────────────────────────────────
def _lambda_vpc_attachment(model: InfrastructureModel) -> None:
    for fn in model.lambda_functions:
        if fn.vpc_config and fn.vpc_config.get("vpc_id"):
            model.relationships.append(Relationship(
                source_id=fn.function_arn,
                target_id=fn.vpc_config["vpc_id"],
                rel_type="connected_to",
                properties={"attachment": "lambda_vpc"},
            ))


# ── Lambda → Subnet/VPC (connected_to via VPC config) ─────────────────────────
def _lambda_to_vpc(model: InfrastructureModel) -> None:
    """Add edges from Lambda to subnets and VPC it's attached to."""
    for fn in model.lambda_functions:
        if fn.vpc_config:
            vpc_id = fn.vpc_config.get("vpc_id")
            if vpc_id:
                model.relationships.append(Relationship(
                    source_id=fn.function_arn,
                    target_id=vpc_id,
                    rel_type="connected_to",
                    properties={"attachment": "lambda_vpc_config"},
                ))
            for subnet_id in fn.vpc_config.get("subnet_ids", []):
                model.relationships.append(Relationship(
                    source_id=fn.function_arn,
                    target_id=subnet_id,
                    rel_type="connected_to",
                    properties={"attachment": "lambda_subnet"},
                ))


# ── IAM → Lambda Invoke (can_invoke via lambda:InvokeFunction) ────────────────
def _lambda_iam_invoke(model: InfrastructureModel) -> None:
    """
    Parse IAM policies to find Lambda invoke permissions.
    Creates can_invoke edges from IAM principals to Lambda functions they can invoke.
    """
    lambda_arns = {fn.function_arn: fn for fn in model.lambda_functions}

    LAMBDA_ACTIONS = {
        "lambda:*",
        "lambda:InvokeFunction",
        "lambda:InvokeAsync",
    }

    def matches_lambda_resource(resource: str, fn_arn: str) -> bool:
        if resource == "*":
            return True
        if fn_arn in resource or resource.endswith(fn_arn.split(":")[-1]):
            return True
        if "*" in resource:
            import fnmatch
            if fnmatch.fnmatch(fn_arn, resource):
                return True
        return False

    def has_lambda_actions(statement: dict) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        return bool(set(actions) & LAMBDA_ACTIONS)

    def process_policy(policy: dict) -> list:
        accessible_lambdas = []
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            if not has_lambda_actions(stmt):
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                for fn_arn in lambda_arns:
                    if matches_lambda_resource(resource, fn_arn):
                        accessible_lambdas.append(fn_arn)
        return accessible_lambdas

    # Process IAM Roles
    for role in model.iam_roles:
        accessible = []
        for policy in role.inline_policies:
            doc = policy.get("document", {})
            accessible.extend(process_policy(doc))
        for policy in role.managed_policies:
            doc = policy.get("document")
            policy_name = policy.get("name", "")
            if doc:
                accessible.extend(process_policy(doc))
            elif "Lambda" in policy_name or "lambda" in policy_name.lower():
                # AWS-managed Lambda policy
                for fn_arn in lambda_arns:
                    accessible.append(fn_arn)
            elif "AdministratorAccess" in policy_name:
                for fn_arn in lambda_arns:
                    accessible.append(fn_arn)
        for fn_arn in set(accessible):
            model.relationships.append(Relationship(
                source_id=role.arn,
                target_id=fn_arn,
                rel_type="can_invoke",
                properties={"via": "managed_policy", "access_type": "lambda"},
            ))

    # Process IAM Users
    for user in model.iam_users:
        accessible = []
        for policy in user.inline_policies:
            doc = policy.get("document", {})
            accessible.extend(process_policy(doc))
        for policy in user.managed_policies:
            doc = policy.get("document")
            policy_name = policy.get("name", "")
            if doc:
                accessible.extend(process_policy(doc))
            elif "Lambda" in policy_name or "lambda" in policy_name.lower():
                for fn_arn in lambda_arns:
                    accessible.append(fn_arn)
            elif "AdministratorAccess" in policy_name:
                for fn_arn in lambda_arns:
                    accessible.append(fn_arn)
        for fn_arn in set(accessible):
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id=fn_arn,
                rel_type="can_invoke",
                properties={"via": "managed_policy", "access_type": "lambda"},
            ))


# ── IAM Role trust relationships (trusts) ─────────────────────────────────────
def _iam_role_trust_relationships(model: InfrastructureModel) -> None:
    """
    Parse trust policies to find roles that can be assumed by other roles,
    IAM users, services, or external principals (cross-account, federated).
    """
    role_arns = {r.arn for r in model.iam_roles}
    user_arns = {u.arn for u in model.iam_users}

    for role in model.iam_roles:
        for stmt in role.trust_policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            principals = []
            if isinstance(principal, str):
                principals = [principal]
            elif isinstance(principal, dict):
                aws = principal.get("AWS", [])
                service = principal.get("Service", [])
                federated = principal.get("Federated", [])
                if isinstance(aws, str):
                    aws = [aws]
                if isinstance(service, str):
                    service = [service]
                if isinstance(federated, str):
                    federated = [federated]
                principals = aws + service + federated

            for p in principals:
                if p == "*":
                    model.relationships.append(Relationship(
                        source_id="INTERNET",
                        target_id=role.arn,
                        rel_type="trusts",
                        properties={"principal": "*", "risk": "critical"},
                    ))
                elif p in role_arns and p != role.arn:
                    # Role-to-role trust
                    model.relationships.append(Relationship(
                        source_id=p,
                        target_id=role.arn,
                        rel_type="trusts",
                        properties={"principal": p, "principal_type": "role"},
                    ))
                elif p in user_arns:
                    # User-to-role assumption (privilege escalation path!)
                    model.relationships.append(Relationship(
                        source_id=p,
                        target_id=role.arn,
                        rel_type="can_assume",
                        properties={"principal": p, "principal_type": "user"},
                    ))


# ── RDS public exposure ───────────────────────────────────────────────────────
def _rds_public_exposure(model: InfrastructureModel) -> None:
    for db in model.rds_instances:
        if db.publicly_accessible:
            model.relationships.append(Relationship(
                source_id="INTERNET",
                target_id=db.db_instance_id,
                rel_type="exposes",
                properties={
                    "endpoint": db.endpoint_address,
                    "port": db.endpoint_port,
                    "engine": db.engine,
                },
            ))


# ── IAM Role/User → RDS (can_access via IAM auth or rds:* permissions) ────────
def _iam_to_rds_access(model: InfrastructureModel) -> None:
    """
    Parse IAM role and user policies to find RDS access permissions.
    Creates can_access edges from IAM principals to RDS instances they can access.
    """
    rds_arns = {db.db_instance_id: db for db in model.rds_instances}

    # RDS actions that indicate access
    RDS_ACTIONS = {
        "rds:*",
        "rds:DescribeDBInstances",
        "rds:Connect",
        "rds-db:connect",
        "rds:ModifyDBInstance",
        "rds:DeleteDBInstance",
    }

    def matches_rds_resource(resource: str, rds_id: str) -> bool:
        """Check if a policy resource pattern matches an RDS instance."""
        if resource == "*":
            return True
        if rds_id in resource or resource.endswith(rds_id):
            return True
        if "*" in resource:
            import fnmatch
            if fnmatch.fnmatch(rds_id, resource):
                return True
        return False

    def has_rds_actions(statement: dict) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        return bool(set(actions) & RDS_ACTIONS)

    def process_policy(policy: dict) -> list:
        accessible_rds = []
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            if not has_rds_actions(stmt):
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                for rds_id in rds_arns:
                    if matches_rds_resource(resource, rds_id):
                        accessible_rds.append(rds_id)
        return accessible_rds

    # Process IAM Roles
    for role in model.iam_roles:
        accessible = []
        for policy in role.inline_policies:
            doc = policy.get("document", {})
            accessible.extend(process_policy(doc))
        for policy in role.managed_policies:
            doc = policy.get("document")
            policy_name = policy.get("name", "")
            if doc:
                accessible.extend(process_policy(doc))
            elif "RDS" in policy_name.upper() or "Database" in policy_name:
                # AWS-managed RDS policy
                for rds_id in rds_arns:
                    accessible.append(rds_id)
            elif "AdministratorAccess" in policy_name:
                for rds_id in rds_arns:
                    accessible.append(rds_id)
        for rds_id in set(accessible):
            model.relationships.append(Relationship(
                source_id=role.arn,
                target_id=rds_id,
                rel_type="can_access",
                properties={"via": "managed_policy", "access_type": "rds"},
            ))

    # Process IAM Users
    for user in model.iam_users:
        accessible = []
        for policy in user.inline_policies:
            doc = policy.get("document", {})
            accessible.extend(process_policy(doc))
        for policy in user.managed_policies:
            doc = policy.get("document")
            policy_name = policy.get("name", "")
            if doc:
                accessible.extend(process_policy(doc))
            elif "RDS" in policy_name.upper() or "Database" in policy_name:
                for rds_id in rds_arns:
                    accessible.append(rds_id)
            elif "AdministratorAccess" in policy_name:
                for rds_id in rds_arns:
                    accessible.append(rds_id)
        for rds_id in set(accessible):
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id=rds_id,
                rel_type="can_access",
                properties={"via": "managed_policy", "access_type": "rds"},
            ))


# ── RDS → Security Group (connected_to) ───────────────────────────────────────
def _rds_to_security_group(model: InfrastructureModel) -> None:
    """Add edges from RDS instances to their attached security groups."""
    sg_ids = {sg.group_id for sg in model.security_groups}
    for db in model.rds_instances:
        for sg_id in db.security_group_ids:
            if sg_id in sg_ids:
                model.relationships.append(Relationship(
                    source_id=sg_id,
                    target_id=db.db_instance_id,
                    rel_type="connected_to",
                    properties={"attachment": "rds_security_group"},
                ))


# ── S3 public access ──────────────────────────────────────────────────────────
def _s3_public_exposure(model: InfrastructureModel) -> None:
    for bucket in model.s3_buckets:
        if bucket.is_public:
            model.relationships.append(Relationship(
                source_id="INTERNET",
                target_id=bucket.arn,
                rel_type="exposes",
                properties={"bucket_name": bucket.name, "acl": bucket.bucket_acl},
            ))


# ── IAM Role/User → S3 (can_access via policy permissions) ────────────────────
def _iam_to_s3_access(model: InfrastructureModel) -> None:
    """
    Parse IAM role and user policies to find S3 access permissions.
    Creates can_access edges from IAM principals to S3 buckets they can access.
    """
    # Build a map of bucket ARNs to bucket objects for matching
    bucket_arns = {bucket.arn: bucket for bucket in model.s3_buckets}
    # Also create pattern-matching for ARN wildcards (e.g., arn:aws:s3:::cg-*)
    bucket_names = [bucket.name for bucket in model.s3_buckets]

    # S3 actions that indicate access
    S3_ACTIONS = {
        "s3:*",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
    }

    def matches_s3_resource(resource: str, bucket_arn: str) -> bool:
        """Check if a policy resource pattern matches a bucket ARN."""
        if resource == "*":
            return True  # Wildcard grants access to all buckets
        if resource == bucket_arn:
            return True
        # Handle wildcard patterns like arn:aws:s3:::cg-*
        if "*" in resource:
            # Match bucket ARN pattern
            if fnmatch.fnmatch(bucket_arn, resource):
                return True
            # Also match with just bucket name (for arn:aws:s3:::bucket-name patterns)
            bucket_name = bucket_arn.replace("arn:aws:s3:::", "")
            if fnmatch.fnmatch(bucket_name, resource.replace("arn:aws:s3:::", "")):
                return True
        return False

    def has_s3_actions(statement: dict) -> bool:
        """Check if a policy statement contains S3 access actions."""
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        return bool(set(actions) & S3_ACTIONS)

    def process_policy(principal_arn: str, policy: dict) -> list:
        """Extract S3 bucket ARNs that this policy grants access to."""
        accessible_buckets = []
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            if not has_s3_actions(stmt):
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources:
                # Match against known buckets
                for bucket_arn in bucket_arns:
                    if matches_s3_resource(resource, bucket_arn):
                        accessible_buckets.append(bucket_arn)
        return accessible_buckets

    # Process IAM Roles
    for role in model.iam_roles:
        accessible = []

        # Check inline policies
        for policy in role.inline_policies:
            doc = policy.get("document", {})
            accessible.extend(process_policy(role.arn, doc))

        # Check managed policies - handle AWS-managed policies by name
        for policy in role.managed_policies:
            doc = policy.get("document")
            policy_name = policy.get("name", "")
            policy_arn = policy.get("arn", "")

            if doc:
                # Customer-managed policy with document
                accessible.extend(process_policy(role.arn, doc))
            elif "AmazonS3FullAccess" in policy_name or "S3" in policy_name:
                # AWS-managed S3 policy - grant access to all buckets
                for bucket_arn in bucket_arns:
                    accessible.append(bucket_arn)
            elif "AdministratorAccess" in policy_name:
                # Admin policy grants access to everything
                for bucket_arn in bucket_arns:
                    accessible.append(bucket_arn)

        # Add relationships for each accessible bucket
        for bucket_arn in set(accessible):  # Deduplicate
            model.relationships.append(Relationship(
                source_id=role.arn,
                target_id=bucket_arn,
                rel_type="can_access",
                properties={"via": "managed_policy", "access_type": "s3"},
            ))

    # Process IAM Users
    for user in model.iam_users:
        accessible = []

        # Check inline policies
        for policy in user.inline_policies:
            doc = policy.get("document", {})
            accessible.extend(process_policy(user.arn, doc))

        # Check managed policies
        for policy in user.managed_policies:
            doc = policy.get("document")
            policy_name = policy.get("name", "")
            if doc:
                accessible.extend(process_policy(user.arn, doc))
            elif "AmazonS3FullAccess" in policy_name or "S3" in policy_name:
                for bucket_arn in bucket_arns:
                    accessible.append(bucket_arn)
            elif "AdministratorAccess" in policy_name:
                for bucket_arn in bucket_arns:
                    accessible.append(bucket_arn)

        # Add relationships for each accessible bucket
        for bucket_arn in set(accessible):
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id=bucket_arn,
                rel_type="can_access",
                properties={"via": "managed_policy" if user.managed_policies else "inline_policy", "access_type": "s3"},
            ))


# ── Subnet → VPC (connected_to) ───────────────────────────────────────────────
def _subnet_to_vpc(model: InfrastructureModel) -> None:
    for subnet in model.subnets:
        model.relationships.append(Relationship(
            source_id=subnet.subnet_id,
            target_id=subnet.vpc_id,
            rel_type="connected_to",
            properties={"is_public": subnet.is_public},
        ))


# ── EC2 → Subnet (connected_to) ───────────────────────────────────────────────
def _ec2_to_subnet(model: InfrastructureModel) -> None:
    subnet_ids = {s.subnet_id for s in model.subnets}
    for inst in model.ec2_instances:
        if inst.subnet_id and inst.subnet_id in subnet_ids:
            model.relationships.append(Relationship(
                source_id=inst.instance_id,
                target_id=inst.subnet_id,
                rel_type="connected_to",
                properties={"attachment": "ec2_subnet"},
            ))


# ── EC2 → VPC (connected_to via VPC attachment) ───────────────────────────────
def _ec2_to_vpc(model: InfrastructureModel) -> None:
    """Add edges from EC2 instances to their VPC."""
    vpc_ids = {v.vpc_id for v in model.vpcs}
    for inst in model.ec2_instances:
        if inst.vpc_id and inst.vpc_id in vpc_ids:
            model.relationships.append(Relationship(
                source_id=inst.instance_id,
                target_id=inst.vpc_id,
                rel_type="connected_to",
                properties={"attachment": "ec2_vpc"},
            ))


# ── NAT Gateway → VPC/Subnet (connected_to) ───────────────────────────────────
def _nat_to_vpc_subnet(model: InfrastructureModel) -> None:
    """Add edges from NAT Gateways to their VPC and subnet."""
    for nat in model.nat_gateways:
        model.relationships.append(Relationship(
            source_id=nat.nat_gateway_id,
            target_id=nat.vpc_id,
            rel_type="connected_to",
            properties={"attachment": "nat_vpc"},
        ))
        model.relationships.append(Relationship(
            source_id=nat.nat_gateway_id,
            target_id=nat.subnet_id,
            rel_type="connected_to",
            properties={"attachment": "nat_subnet"},
        ))


# ── Internet Gateway → VPC (attached_to) ──────────────────────────────────────
def _igw_to_vpc(model: InfrastructureModel) -> None:
    """Add edges from Internet Gateways to their attached VPCs."""
    for igw in model.internet_gateways:
        if igw.vpc_id:
            model.relationships.append(Relationship(
                source_id=igw.igw_id,
                target_id=igw.vpc_id,
                rel_type="connected_to",
                properties={"attachment": "igw_vpc", "state": igw.state},
            ))


# ── VPC Endpoint → VPC/Subnet/SG (connected_to) ───────────────────────────────
def _vpce_to_vpc_subnet_sg(model: InfrastructureModel) -> None:
    """Add edges from VPC Endpoints to their associated resources."""
    for vpce in model.vpc_endpoints:
        model.relationships.append(Relationship(
            source_id=vpce.endpoint_id,
            target_id=vpce.vpc_id,
            rel_type="connected_to",
            properties={"attachment": "vpce_vpc", "service": vpce.service_name},
        ))
        for subnet_id in vpce.subnet_ids:
            model.relationships.append(Relationship(
                source_id=vpce.endpoint_id,
                target_id=subnet_id,
                rel_type="connected_to",
                properties={"attachment": "vpce_subnet"},
            ))
        for sg_id in vpce.security_group_ids:
            model.relationships.append(Relationship(
                source_id=vpce.endpoint_id,
                target_id=sg_id,
                rel_type="connected_to",
                properties={"attachment": "vpce_security_group"},
            ))


# ── Internet → NAT Gateway (exposes via public IP) ────────────────────────────
def _internet_to_nat_gateway(model: InfrastructureModel) -> None:
    """Add edges from Internet to NAT Gateways with public IPs."""
    for nat in model.nat_gateways:
        if nat.public_ip and nat.state == "available":
            model.relationships.append(Relationship(
                source_id="INTERNET",
                target_id=nat.nat_gateway_id,
                rel_type="exposes",
                properties={"public_ip": nat.public_ip, "type": "nat_gateway"},
            ))


# ── Subnet → NAT Gateway (routes_via) for private subnets ─────────────────────
def _subnet_to_nat_gateway(model: InfrastructureModel) -> None:
    """
    Add edges from private subnets to NAT Gateways.
    Note: This is a simplification - in reality, route tables determine this.
    """
    nat_by_subnet = {nat.subnet_id: nat for nat in model.nat_gateways if nat.state == "available"}

    for subnet in model.subnets:
        # Private subnets typically route 0.0.0.0/0 to NAT
        # Here we assume subnets in same VPC as NAT might use it
        if not subnet.is_public and subnet.vpc_id:
            # Find NAT in same VPC (might be in different subnet)
            for nat in model.nat_gateways:
                if nat.vpc_id == subnet.vpc_id and nat.state == "available":
                    model.relationships.append(Relationship(
                        source_id=subnet.subnet_id,
                        target_id=nat.nat_gateway_id,
                        rel_type="routes_via",
                        properties={"purpose": "outbound_internet_access"},
                    ))


# ── VPC Endpoint → S3/RDS (can_access) ────────────────────────────────────────
def _vpce_to_s3_rds(model: InfrastructureModel) -> None:
    """Add edges from VPC Endpoints to the AWS services they provide access to."""
    s3_buckets_by_region = {b.name: b for b in model.s3_buckets}
    rds_instances_by_id = {db.db_instance_id: db for db in model.rds_instances}

    for vpce in model.vpc_endpoints:
        if vpce.state != "available":
            continue

        # Gateway endpoints for S3
        if "s3" in vpce.service_name.lower():
            for bucket_name, bucket in s3_buckets_by_region.items():
                # Check if bucket is in same region as VPC endpoint
                if bucket.region in vpce.region:
                    model.relationships.append(Relationship(
                        source_id=vpce.endpoint_id,
                        target_id=bucket.arn,
                        rel_type="can_access",
                        properties={"via": "vpc_endpoint", "service": "s3"},
                    ))

        # Interface endpoints for RDS
        if "rds" in vpce.service_name.lower():
            for rds_id, rds in rds_instances_by_id.items():
                if rds.region in vpce.region:
                    model.relationships.append(Relationship(
                        source_id=vpce.endpoint_id,
                        target_id=rds_id,
                        rel_type="can_access",
                        properties={"via": "vpc_endpoint", "service": "rds"},
                    ))


# ── IAM → EC2 Create (can_create via ec2:* permissions) ───────────────────────
def _iam_to_ec2_create(model: InfrastructureModel) -> None:
    """
    Add edges from IAM roles/users that can create EC2 instances.
    This represents privilege escalation via resource creation.
    """
    for role in model.iam_roles:
        metadata = getattr(role, "metadata", {})
        if metadata.get("can_create_ec2"):
            # Edge to a virtual "EC2_CREATE" target representing ability to create instances
            model.relationships.append(Relationship(
                source_id=role.arn,
                target_id="EC2_CREATE_CAPABILITY",
                rel_type="can_create",
                properties={"resource_type": "ec2", "via": "iam_policy"},
            ))

    for user in model.iam_users:
        metadata = getattr(user, "metadata", {})
        if metadata.get("can_create_ec2"):
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id="EC2_CREATE_CAPABILITY",
                rel_type="can_create",
                properties={"resource_type": "ec2", "via": "iam_policy"},
            ))


# ── IAM → Lambda Create (can_create via lambda:* permissions) ─────────────────
def _iam_to_lambda_create(model: InfrastructureModel) -> None:
    """
    Add edges from IAM roles/users that can create Lambda functions.
    This represents privilege escalation via resource creation.
    """
    for role in model.iam_roles:
        metadata = getattr(role, "metadata", {})
        if metadata.get("can_create_lambda"):
            model.relationships.append(Relationship(
                source_id=role.arn,
                target_id="LAMBDA_CREATE_CAPABILITY",
                rel_type="can_create",
                properties={"resource_type": "lambda", "via": "iam_policy"},
            ))

    for user in model.iam_users:
        metadata = getattr(user, "metadata", {})
        if metadata.get("can_create_lambda"):
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id="LAMBDA_CREATE_CAPABILITY",
                rel_type="can_create",
                properties={"resource_type": "lambda", "via": "iam_policy"},
            ))


# ── IAM → IAM Modify (can_modify via iam:* permissions) ───────────────────────
def _iam_to_iam_modify(model: InfrastructureModel) -> None:
    """
    Add edges from IAM roles/users that can modify IAM policies.
    This represents critical privilege escalation capability.
    """
    for role in model.iam_roles:
        metadata = getattr(role, "metadata", {})
        if metadata.get("can_modify_iam"):
            model.relationships.append(Relationship(
                source_id=role.arn,
                target_id="IAM_MODIFY_CAPABILITY",
                rel_type="can_modify",
                properties={"capability": "iam_policy_modification", "via": "iam_policy"},
            ))

    for user in model.iam_users:
        metadata = getattr(user, "metadata", {})
        if metadata.get("can_modify_iam"):
            model.relationships.append(Relationship(
                source_id=user.arn,
                target_id="IAM_MODIFY_CAPABILITY",
                rel_type="can_modify",
                properties={"capability": "iam_policy_modification", "via": "iam_policy"},
            ))
