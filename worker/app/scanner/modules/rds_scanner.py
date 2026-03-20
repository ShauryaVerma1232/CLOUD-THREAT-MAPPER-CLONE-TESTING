"""
RDS Scanner Module

Collects:
- RDS DB instances (not clusters — added in a future iteration)
- Key security attributes: public accessibility, IAM auth, encryption
"""
import structlog
from botocore.exceptions import ClientError

from app.scanner.aws_session import AWSSession
from app.scanner.model import RDSInstance, InfrastructureModel

log = structlog.get_logger()


def scan_rds(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all RDS DB instances in the region."""
    log.info("scanner.rds.start", region=session.region)
    rds = session.client("rds")
    paginator = rds.get_paginator("describe_db_instances")

    count = 0
    try:
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                endpoint = db.get("Endpoint", {})
                vpc_sg_ids = [
                    sg["VpcSecurityGroupId"]
                    for sg in db.get("VpcSecurityGroups", [])
                ]
                tags = {
                    t["Key"]: t["Value"]
                    for t in db.get("TagList", [])
                }

                instance = RDSInstance(
                    db_instance_id=db["DBInstanceIdentifier"],
                    db_instance_class=db.get("DBInstanceClass", ""),
                    engine=db.get("Engine", ""),
                    engine_version=db.get("EngineVersion", ""),
                    endpoint_address=endpoint.get("Address"),
                    endpoint_port=endpoint.get("Port"),
                    vpc_id=db.get("DBSubnetGroup", {}).get("VpcId"),
                    subnet_group=db.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                    security_group_ids=vpc_sg_ids,
                    publicly_accessible=db.get("PubliclyAccessible", False),
                    multi_az=db.get("MultiAZ", False),
                    encrypted=db.get("StorageEncrypted", False),
                    iam_auth_enabled=db.get("IAMDatabaseAuthenticationEnabled", False),
                    tags=tags,
                    region=session.region,
                )
                model.rds_instances.append(instance)
                count += 1

    except ClientError as e:
        model.add_error("rds", "describe_db_instances", str(e))
        log.warning("scanner.rds.error", error=str(e))

    log.info("scanner.rds.done", count=count)
