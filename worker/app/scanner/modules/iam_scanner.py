"""
IAM Scanner Module

Collects:
- IAM roles (with trust policies and all attached/inline policies)
- IAM users (with access keys, MFA status, policies)
"""
import json
import urllib.parse

import structlog
from botocore.exceptions import ClientError

from app.scanner.aws_session import AWSSession
from app.scanner.model import IAMRole, IAMUser, InfrastructureModel

log = structlog.get_logger()


def _decode_policy(policy_document) -> dict:
    """URL-decode and parse an IAM policy document."""
    if isinstance(policy_document, str):
        decoded = urllib.parse.unquote(policy_document)
        return json.loads(decoded)
    return policy_document


def _get_role_inline_policies(iam_client, role_name: str) -> list[dict]:
    """Fetch all inline policy documents for a role."""
    policies = []
    try:
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page["PolicyNames"]:
                try:
                    resp = AWSSession.safe_call(
                        iam_client.get_role_policy,
                        RoleName=role_name,
                        PolicyName=policy_name,
                    )
                    policies.append({
                        "name": policy_name,
                        "document": _decode_policy(resp["PolicyDocument"]),
                    })
                except ClientError as e:
                    log.warning("iam.inline_policy_fetch_error",
                                role=role_name, policy=policy_name, error=str(e))
    except ClientError as e:
        log.warning("iam.list_inline_policies_error", role=role_name, error=str(e))
    return policies


def _get_managed_policy_document(iam_client, policy_arn: str) -> dict | None:
    """Fetch the default version document for a managed policy."""
    try:
        policy = AWSSession.safe_call(iam_client.get_policy, PolicyArn=policy_arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        version = AWSSession.safe_call(
            iam_client.get_policy_version,
            PolicyArn=policy_arn,
            VersionId=version_id,
        )
        return _decode_policy(version["PolicyVersion"]["Document"])
    except ClientError as e:
        log.warning("iam.managed_policy_fetch_error", arn=policy_arn, error=str(e))
        return None


def scan_iam_roles(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all IAM roles with their full policy documents."""
    log.info("scanner.iam_roles.start")
    iam = session.client("iam")
    paginator = iam.get_paginator("list_roles")

    count = 0
    try:
        for page in paginator.paginate():
            for role_data in page["Roles"]:
                role_name = role_data["RoleName"]
                role_arn = role_data["Arn"]

                # Skip AWS service-linked roles (not attacker-controllable)
                if "aws-service-role" in role_arn:
                    continue

                # Trust policy
                trust_policy = _decode_policy(
                    role_data.get("AssumeRolePolicyDocument", {})
                )

                # Inline policies
                inline_policies = _get_role_inline_policies(iam, role_name)

                # Attached managed policies
                attached_arns = []
                managed_policies = []
                try:
                    att_paginator = iam.get_paginator("list_attached_role_policies")
                    for att_page in att_paginator.paginate(RoleName=role_name):
                        for p in att_page["AttachedPolicies"]:
                            arn = p["PolicyArn"]
                            attached_arns.append(arn)
                            # Only fetch AWS-managed policies for well-known ones to save API calls
                            # Always fetch customer-managed policies
                            if not arn.startswith("arn:aws:iam::aws:policy/"):
                                doc = _get_managed_policy_document(iam, arn)
                                if doc:
                                    managed_policies.append({
                                        "arn": arn,
                                        "name": p["PolicyName"],
                                        "document": doc,
                                    })
                            else:
                                # Record AWS-managed policy by name only
                                managed_policies.append({
                                    "arn": arn,
                                    "name": p["PolicyName"],
                                    "document": None,  # Well-known; looked up by name
                                })
                except ClientError as e:
                    log.warning("iam.attached_policies_error",
                                role=role_name, error=str(e))

                # Tags
                tags = {}
                try:
                    tag_resp = AWSSession.safe_call(
                        iam.list_role_tags, RoleName=role_name
                    )
                    tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}
                except ClientError:
                    pass

                role = IAMRole(
                    role_id=role_data["RoleId"],
                    role_name=role_name,
                    arn=role_arn,
                    trust_policy=trust_policy,
                    inline_policies=inline_policies,
                    attached_policy_arns=attached_arns,
                    managed_policies=managed_policies,
                    max_session_duration=role_data.get("MaxSessionDuration", 3600),
                    tags=tags,
                )
                model.iam_roles.append(role)
                count += 1

    except ClientError as e:
        model.add_error("iam", "list_roles", str(e))
        log.warning("scanner.iam_roles.error", error=str(e))

    log.info("scanner.iam_roles.done", count=count)


def scan_iam_users(session: AWSSession, model: InfrastructureModel) -> None:
    """Scan all IAM users with access key status and MFA."""
    log.info("scanner.iam_users.start")
    iam = session.client("iam")
    paginator = iam.get_paginator("list_users")

    count = 0
    try:
        for page in paginator.paginate():
            for user_data in page["Users"]:
                user_name = user_data["UserName"]

                # Login profile (console access)
                has_console = False
                try:
                    AWSSession.safe_call(
                        iam.get_login_profile, UserName=user_name
                    )
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        log.warning("iam.login_profile_error",
                                    user=user_name, error=str(e))

                # MFA devices
                has_mfa = False
                try:
                    mfa_resp = AWSSession.safe_call(
                        iam.list_mfa_devices, UserName=user_name
                    )
                    has_mfa = len(mfa_resp.get("MFADevices", [])) > 0
                except ClientError:
                    pass

                # Access keys (IDs + status only — never secret keys)
                access_keys = []
                try:
                    keys_resp = AWSSession.safe_call(
                        iam.list_access_keys, UserName=user_name
                    )
                    for k in keys_resp.get("AccessKeyMetadata", []):
                        last_used = None
                        try:
                            lu = AWSSession.safe_call(
                                iam.get_access_key_last_used,
                                AccessKeyId=k["AccessKeyId"],
                            )
                            last_used = lu.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        except ClientError:
                            pass
                        access_keys.append({
                            "key_id": k["AccessKeyId"],
                            "status": k["Status"],
                            "last_used": str(last_used) if last_used else None,
                        })
                except ClientError:
                    pass

                # Attached policies
                attached_arns = []
                try:
                    att_p = iam.get_paginator("list_attached_user_policies")
                    for att_page in att_p.paginate(UserName=user_name):
                        attached_arns += [
                            p["PolicyArn"] for p in att_page["AttachedPolicies"]
                        ]
                except ClientError:
                    pass

                # Groups
                groups = []
                try:
                    g_p = iam.get_paginator("list_groups_for_user")
                    for g_page in g_p.paginate(UserName=user_name):
                        groups += [g["GroupName"] for g in g_page["Groups"]]
                except ClientError:
                    pass

                user = IAMUser(
                    user_id=user_data["UserId"],
                    user_name=user_name,
                    arn=user_data["Arn"],
                    has_console_access=has_console,
                    has_mfa=has_mfa,
                    access_keys=access_keys,
                    attached_policy_arns=attached_arns,
                    inline_policies=[],
                    groups=groups,
                    tags={},
                )
                model.iam_users.append(user)
                count += 1

    except ClientError as e:
        model.add_error("iam", "list_users", str(e))
        log.warning("scanner.iam_users.error", error=str(e))

    log.info("scanner.iam_users.done", count=count)
