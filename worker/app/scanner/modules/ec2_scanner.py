"""
EC2 Scanner Module

Collects:
- EC2 instances (all states)
- Security groups
- VPCs
- Subnets (with public/private classification)
"""
import structlog
from botocore.exceptions import ClientError

from app.scanner.aws_session import AWSSession
from app.scanner.model import (
    EC2Instance, SecurityGroup, VPC, Subnet, InfrastructureModel
)

log = structlog.get_logger()


def _extract_tag(tags: list | None, key: str) -> str | None:
    if not tags:
        return None
    for t in tags:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def _tags_to_dict(tags: list | None) -> dict[str, str]:
    if not tags:
        return {}
    return {t["Key"]: t["Value"] for t in tags}


def _parse_ingress_rules(rules: list) -> list[dict]:
    parsed = []
    for rule in rules:
        cidr_ranges = [r["CidrIp"] for r in rule.get("IpRanges", [])]
        cidr_ranges += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
        sg_refs = [
            {"group_id": r["GroupId"], "group_name": r.get("GroupName", "")}
            for r in rule.get("UserIdGroupPairs", [])
        ]
        parsed.append({
            "protocol":   rule.get("IpProtocol", "-1"),
            "from_port":  rule.get("FromPort"),
            "to_port":    rule.get("ToPort"),
            "cidr_ranges": cidr_ranges,
            "sg_refs":    sg_refs,
            "description": rule.get("Description", ""),
        })
    return parsed


def _is_public_rule(rules: list[dict]) -> bool:
    """Return True if any ingress rule allows traffic from 0.0.0.0/0 or ::/0."""
    for rule in rules:
        for cidr in rule.get("cidr_ranges", []):
            if cidr in ("0.0.0.0/0", "::/0"):
                return True
    return False


def scan_ec2(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all EC2 instances in the region."""
    log.info("scanner.ec2.start", region=session.region)
    ec2 = session.client("ec2")
    iam = session.client("iam")
    paginator = ec2.get_paginator("describe_instances")

    count = 0
    try:
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    # Extract IAM role from instance profile ARN
                    profile = inst.get("IamInstanceProfile", {})
                    profile_arn = profile.get("Arn")
                    profile_name = None
                    role_arn = None
                    role_name = None

                    if profile_arn:
                        # arn:aws:iam::123:instance-profile/MyProfile
                        parts = profile_arn.split("/")
                        profile_name = parts[-1] if len(parts) > 1 else None

                        # Resolve instance profile to get the actual role
                        if profile_name:
                            try:
                                profile_info = iam.get_instance_profile(InstanceProfileName=profile_name)
                                roles = profile_info.get("InstanceProfile", {}).get("Roles", [])
                                if roles:
                                    role_arn = roles[0].get("Arn")
                                    role_name = roles[0].get("RoleName")
                            except ClientError:
                                # Fall back to profile name if we can't resolve
                                role_name = profile_name

                    instance = EC2Instance(
                        instance_id=inst["InstanceId"],
                        instance_type=inst.get("InstanceType", "unknown"),
                        state=inst["State"]["Name"],
                        vpc_id=inst.get("VpcId"),
                        subnet_id=inst.get("SubnetId"),
                        private_ip=inst.get("PrivateIpAddress"),
                        public_ip=inst.get("PublicIpAddress"),
                        iam_instance_profile_arn=profile_arn,
                        iam_role_name=role_name,
                        iam_role_arn=role_arn,
                        security_group_ids=[
                            sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                        ],
                        tags=_tags_to_dict(inst.get("Tags")),
                        platform=inst.get("Platform"),
                        metadata_options=inst.get("MetadataOptions", {}),
                        region=session.region,
                    )
                    model.ec2_instances.append(instance)
                    count += 1

    except ClientError as e:
        model.add_error("ec2", "describe_instances", str(e))
        log.warning("scanner.ec2.error", error=str(e))

    log.info("scanner.ec2.done", count=count)


def scan_security_groups(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all security groups in the region."""
    log.info("scanner.sg.start", region=session.region)
    ec2 = session.client("ec2")
    paginator = ec2.get_paginator("describe_security_groups")

    count = 0
    try:
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                ingress = _parse_ingress_rules(sg.get("IpPermissions", []))
                egress = _parse_ingress_rules(sg.get("IpPermissionsEgress", []))

                security_group = SecurityGroup(
                    group_id=sg["GroupId"],
                    group_name=sg["GroupName"],
                    vpc_id=sg.get("VpcId"),
                    description=sg.get("Description", ""),
                    ingress_rules=ingress,
                    egress_rules=egress,
                    tags=_tags_to_dict(sg.get("Tags")),
                )
                model.security_groups.append(security_group)
                count += 1

    except ClientError as e:
        model.add_error("ec2", "describe_security_groups", str(e))
        log.warning("scanner.sg.error", error=str(e))

    log.info("scanner.sg.done", count=count)


def scan_vpcs(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all VPCs in the region."""
    log.info("scanner.vpc.start", region=session.region)
    ec2 = session.client("ec2")

    try:
        response = AWSSession.safe_call(ec2.describe_vpcs)
        for v in response.get("Vpcs", []):
            vpc = VPC(
                vpc_id=v["VpcId"],
                cidr_block=v.get("CidrBlock", ""),
                is_default=v.get("IsDefault", False),
                state=v.get("State", ""),
                tags=_tags_to_dict(v.get("Tags")),
                region=session.region,
            )
            model.vpcs.append(vpc)

    except ClientError as e:
        model.add_error("ec2", "describe_vpcs", str(e))
        log.warning("scanner.vpc.error", error=str(e))

    log.info("scanner.vpc.done", count=len(model.vpcs))


def scan_subnets(session: AWSSession, model: InfrastructureModel) -> None:
    """
    Scan all subnets and classify each as public or private.

    A subnet is public if there is a route table associated with it (or its VPC)
    that contains a route to an Internet Gateway (0.0.0.0/0 → igw-*).
    """
    log.info("scanner.subnet.start", region=session.region)
    ec2 = session.client("ec2")

    # Build a set of subnet IDs that have a route to an IGW
    public_subnet_ids: set[str] = set()
    public_vpc_ids: set[str] = set()

    try:
        rt_response = AWSSession.safe_call(ec2.describe_route_tables)
        for rt in rt_response.get("RouteTables", []):
            has_igw_route = any(
                route.get("GatewayId", "").startswith("igw-")
                for route in rt.get("Routes", [])
                if route.get("DestinationCidrBlock") == "0.0.0.0/0"
            )
            if has_igw_route:
                # Explicit subnet associations
                for assoc in rt.get("Associations", []):
                    subnet_id = assoc.get("SubnetId")
                    if subnet_id:
                        public_subnet_ids.add(subnet_id)
                    if assoc.get("Main"):
                        public_vpc_ids.add(rt.get("VpcId", ""))

        # Now scan subnets
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for s in page["Subnets"]:
                subnet_id = s["SubnetId"]
                vpc_id = s.get("VpcId", "")
                is_public = (
                    subnet_id in public_subnet_ids
                    or vpc_id in public_vpc_ids
                )
                subnet = Subnet(
                    subnet_id=subnet_id,
                    vpc_id=vpc_id,
                    cidr_block=s.get("CidrBlock", ""),
                    availability_zone=s.get("AvailabilityZone", ""),
                    is_public=is_public,
                    map_public_ip_on_launch=s.get("MapPublicIpOnLaunch", False),
                    tags=_tags_to_dict(s.get("Tags")),
                )
                model.subnets.append(subnet)

    except ClientError as e:
        model.add_error("ec2", "describe_subnets", str(e))
        log.warning("scanner.subnet.error", error=str(e))

    log.info("scanner.subnet.done", count=len(model.subnets))
