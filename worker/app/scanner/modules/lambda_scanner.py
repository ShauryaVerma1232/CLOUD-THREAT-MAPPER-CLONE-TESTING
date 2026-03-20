"""
Lambda Scanner Module

Collects:
- Lambda functions with execution roles and VPC config
- Environment variable KEYS only (never values)
"""
import structlog
from botocore.exceptions import ClientError

from app.scanner.aws_session import AWSSession
from app.scanner.model import LambdaFunction, InfrastructureModel

log = structlog.get_logger()


def scan_lambda(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all Lambda functions in the region."""
    log.info("scanner.lambda.start", region=session.region)
    lam = session.client("lambda")
    paginator = lam.get_paginator("list_functions")

    count = 0
    try:
        for page in paginator.paginate():
            for fn in page["Functions"]:
                role_arn = fn.get("Role", "")
                # Extract role name from ARN: arn:aws:iam::123:role/MyRole
                role_name = role_arn.split("/")[-1] if "/" in role_arn else None

                # VPC config
                vpc_config_raw = fn.get("VpcConfig", {})
                vpc_config = None
                if vpc_config_raw.get("VpcId"):
                    vpc_config = {
                        "vpc_id": vpc_config_raw.get("VpcId"),
                        "subnet_ids": vpc_config_raw.get("SubnetIds", []),
                        "security_group_ids": vpc_config_raw.get("SecurityGroupIds", []),
                    }

                # Environment variable keys only — never values
                env_keys = list(
                    fn.get("Environment", {}).get("Variables", {}).keys()
                )

                # Tags
                tags = {}
                try:
                    tag_resp = AWSSession.safe_call(
                        lam.list_tags, Resource=fn["FunctionArn"]
                    )
                    tags = tag_resp.get("Tags", {})
                except ClientError:
                    pass

                function = LambdaFunction(
                    function_name=fn["FunctionName"],
                    function_arn=fn["FunctionArn"],
                    runtime=fn.get("Runtime"),
                    role_arn=role_arn,
                    role_name=role_name,
                    vpc_config=vpc_config,
                    environment_variables=env_keys,
                    tags=tags,
                    region=session.region,
                )
                model.lambda_functions.append(function)
                count += 1

    except ClientError as e:
        model.add_error("lambda", "list_functions", str(e))
        log.warning("scanner.lambda.error", error=str(e))

    log.info("scanner.lambda.done", count=count)
