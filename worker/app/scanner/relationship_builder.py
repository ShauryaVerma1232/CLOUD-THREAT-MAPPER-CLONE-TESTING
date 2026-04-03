"""
Relationship Builder

Takes a fully populated InfrastructureModel (all resource lists filled)
and derives all security relationships (edges) between resources.

These relationships feed directly into the graph builder in Day 3.
"""
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

    _ec2_to_iam_role(model)
    _ec2_to_security_group(model)
    _iam_user_assume_role_policies(model)
    _ec2_public_exposure(model)
    _lambda_to_iam_role(model)
    _lambda_vpc_attachment(model)
    _iam_role_trust_relationships(model)
    _rds_public_exposure(model)
    _s3_public_exposure(model)
    _subnet_to_vpc(model)
    _ec2_to_subnet(model)

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
    for inst in model.ec2_instances:
        if inst.iam_role_name and inst.iam_role_name in role_by_name:
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
                properties={},
            ))
