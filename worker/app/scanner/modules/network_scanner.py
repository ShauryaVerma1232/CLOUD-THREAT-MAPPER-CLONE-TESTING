"""
Network Scanner Module

Collects:
- NAT Gateways
- Internet Gateways
- VPC Endpoints (Gateway and Interface)
"""
import json
import structlog
from botocore.exceptions import ClientError

from app.scanner.aws_session import AWSSession
from app.scanner.model import (
    NATGateway, InternetGateway, VPCEndpoint, InfrastructureModel
)

log = structlog.get_logger()


def _tags_to_dict(tags: list | None) -> dict[str, str]:
    if not tags:
        return {}
    return {t["Key"]: t["Value"] for t in tags}


def scan_nat_gateways(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all NAT Gateways in the region."""
    log.info("scanner.nat.start", region=session.region)
    ec2 = session.client("ec2")
    paginator = ec2.get_paginator("describe_nat_gateways")

    count = 0
    try:
        for page in paginator.paginate():
            for nat in page["NatGateways"]:
                # Get public IP (if any)
                public_ip = None
                for addr in nat.get("NatGatewayAddresses", []):
                    if addr.get("AllocationId"):  # Has public IP
                        public_ip = addr.get("PublicIp")
                        break

                nat_gateway = NATGateway(
                    nat_gateway_id=nat["NatGatewayId"],
                    vpc_id=nat["VpcId"],
                    subnet_id=nat["SubnetId"],
                    state=nat["State"],
                    connectivity_type=nat.get("ConnectivityType", "public"),
                    public_ip=public_ip,
                    tags=_tags_to_dict(nat.get("Tags")),
                    region=session.region,
                )
                model.nat_gateways.append(nat_gateway)
                count += 1

    except ClientError as e:
        model.add_error("ec2", "describe_nat_gateways", str(e))
        log.warning("scanner.nat.error", error=str(e))

    log.info("scanner.nat.done", count=count)


def scan_internet_gateways(session: AWSSession, model: InfrastructureModel) -> None:
    """
    Scan all Internet Gateways.
    Note: IGWs are region-scoped, not VPC-scoped, but we filter to those
    attached to VPCs we've scanned.
    """
    log.info("scanner.igw.start", region=session.region)
    ec2 = session.client("ec2")

    # Get all VPC IDs we care about
    vpc_ids = {vpc.vpc_id for vpc in model.vpcs}

    try:
        paginator = ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            for igw in page["InternetGateways"]:
                # Find which VPC this IGW is attached to
                attached_vpc = None
                for attachment in igw.get("Attachments", []):
                    if attachment.get("VpcId") in vpc_ids:
                        attached_vpc = attachment["VpcId"]
                        break

                # Only include IGWs attached to our scanned VPCs
                if attached_vpc or not igw.get("Attachments"):
                    internet_gateway = InternetGateway(
                        igw_id=igw["InternetGatewayId"],
                        vpc_id=attached_vpc,
                        state="attached" if attached_vpc else "detached",
                        tags=_tags_to_dict(igw.get("Tags")),
                        region=session.region,
                    )
                    model.internet_gateways.append(internet_gateway)

    except ClientError as e:
        model.add_error("ec2", "describe_internet_gateways", str(e))
        log.warning("scanner.igw.error", error=str(e))

    log.info("scanner.igw.done", count=len(model.internet_gateways))


def scan_vpc_endpoints(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all VPC Endpoints (Gateway and Interface types)."""
    log.info("scanner.vpce.start", region=session.region)
    ec2 = session.client("ec2")
    paginator = ec2.get_paginator("describe_vpc_endpoints")

    count = 0
    try:
        for page in paginator.paginate():
            for endpoint in page["VpcEndpoints"]:
                # Parse endpoint policy
                policy_doc = None
                if endpoint.get("PolicyDocument"):
                    try:
                        policy_doc = json.loads(endpoint["PolicyDocument"])
                    except (json.JSONDecodeError, TypeError):
                        policy_doc = None

                vpc_endpoint = VPCEndpoint(
                    endpoint_id=endpoint["VpcEndpointId"],
                    vpc_id=endpoint["VpcId"],
                    service_name=endpoint["ServiceName"],
                    endpoint_type=endpoint["VpcEndpointType"],
                    subnet_ids=endpoint.get("SubnetIds", []),
                    security_group_ids=endpoint.get("Groups", []),
                    policy_document=policy_doc,
                    private_dns_enabled=endpoint.get("PrivateDnsEnabled", False),
                    state=endpoint["State"],
                    tags=_tags_to_dict(endpoint.get("Tags")),
                    region=session.region,
                )
                model.vpc_endpoints.append(vpc_endpoint)
                count += 1

    except ClientError as e:
        model.add_error("ec2", "describe_vpc_endpoints", str(e))
        log.warning("scanner.vpce.error", error=str(e))

    log.info("scanner.vpce.done", count=count)
