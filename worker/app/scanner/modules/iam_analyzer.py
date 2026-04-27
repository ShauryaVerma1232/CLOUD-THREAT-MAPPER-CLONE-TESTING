"""
IAM Analyzer Module

Analyzes IAM policies for privilege escalation vectors and resource creation capabilities.
This module runs AFTER the base IAM scanner and enriches roles/users with escalation metadata.

Detects:
- EC2 creation/modification permissions (ec2:RunInstances, ec2:ModifyInstanceAttribute)
- Lambda creation/modification permissions
- IAM policy modification permissions
- PassRole vulnerabilities
"""
import structlog
from app.scanner.model import InfrastructureModel

log = structlog.get_logger()

# EC2 actions that enable privilege escalation via resource creation
EC2_ESCALATION_ACTIONS = {
    "ec2:*",
    "ec2:RunInstances",
    "ec2:StartInstances",
    "ec2:ModifyInstanceAttribute",
    "ec2:AssociateIamInstanceProfile",
    "ec2:ReplaceIamInstanceProfileAssociation",
}

# Lambda actions for function manipulation
LAMBDA_ESCALATION_ACTIONS = {
    "lambda:*",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:InvokeFunction",
}

# IAM actions for policy manipulation
IAM_ESCALATION_ACTIONS = {
    "iam:*",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:PassRole",
}


def _has_actions(policy_doc: dict, action_set: set) -> tuple[bool, list[str]]:
    """Check if policy contains any of the specified actions. Returns (has_any, matched_actions)."""
    matched = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action in action_set:
                matched.append(action)
    return len(matched) > 0, matched


def _matches_resource(resource: str, target_type: str) -> bool:
    """Check if a policy resource pattern matches a target type."""
    if resource == "*":
        return True
    if target_type.lower() in resource.lower():
        return True
    return False


def analyze_iam_privilege_escalation(model: InfrastructureModel) -> None:
    """
    Analyze IAM roles and users for privilege escalation capabilities.
    Adds risk indicators to the metadata that will be used in graph analysis.
    """
    log.info("scanner.iam_analysis.start")

    for role in model.iam_roles:
        escalation_vectors = []
        can_create_ec2 = False
        can_create_lambda = False
        can_modify_iam = False
        can_pass_role = False

        # Check inline policies
        for policy in role.inline_policies:
            doc = policy.get("document", {})

            # EC2 escalation
            has_ec2, matched = _has_actions(doc, EC2_ESCALATION_ACTIONS)
            if has_ec2:
                can_create_ec2 = True
                escalation_vectors.extend(matched)

            # Lambda escalation
            has_lambda, matched = _has_actions(doc, LAMBDA_ESCALATION_ACTIONS)
            if has_lambda:
                can_create_lambda = True
                escalation_vectors.extend(matched)

            # IAM escalation
            has_iam, matched = _has_actions(doc, IAM_ESCALATION_ACTIONS)
            if has_iam:
                can_modify_iam = True
                escalation_vectors.extend(matched)
                if "iam:PassRole" in matched:
                    can_pass_role = True

        # Check managed policies
        for policy in role.managed_policies:
            doc = policy.get("document")
            if not doc:
                # Check well-known AWS managed policies by name
                policy_name = policy.get("name", "")
                if "AdministratorAccess" in policy_name or "PowerUser" in policy_name:
                    can_create_ec2 = True
                    can_create_lambda = True
                    can_modify_iam = True
                    can_pass_role = True
                    escalation_vectors.append(f"managed:{policy_name}")
                continue

            has_ec2, matched = _has_actions(doc, EC2_ESCALATION_ACTIONS)
            if has_ec2:
                can_create_ec2 = True
                escalation_vectors.extend(matched)

            has_lambda, matched = _has_actions(doc, LAMBDA_ESCALATION_ACTIONS)
            if has_lambda:
                can_create_lambda = True
                escalation_vectors.extend(matched)

            has_iam, matched = _has_actions(doc, IAM_ESCALATION_ACTIONS)
            if has_iam:
                can_modify_iam = True
                escalation_vectors.extend(matched)

        # Store findings in role metadata (will be picked up by graph builder)
        role.metadata = getattr(role, "metadata", {})
        role.metadata["can_create_ec2"] = can_create_ec2
        role.metadata["can_create_lambda"] = can_create_lambda
        role.metadata["can_modify_iam"] = can_modify_iam
        role.metadata["can_pass_role"] = can_pass_role
        role.metadata["escalation_vectors"] = list(set(escalation_vectors))

    # Same analysis for IAM users
    for user in model.iam_users:
        escalation_vectors = []
        can_create_ec2 = False
        can_create_lambda = False
        can_modify_iam = False
        can_pass_role = False

        for policy in user.inline_policies:
            doc = policy.get("document", {})

            has_ec2, matched = _has_actions(doc, EC2_ESCALATION_ACTIONS)
            if has_ec2:
                can_create_ec2 = True
                escalation_vectors.extend(matched)

            has_lambda, matched = _has_actions(doc, LAMBDA_ESCALATION_ACTIONS)
            if has_lambda:
                can_create_lambda = True
                escalation_vectors.extend(matched)

            has_iam, matched = _has_actions(doc, IAM_ESCALATION_ACTIONS)
            if has_iam:
                can_modify_iam = True
                escalation_vectors.extend(matched)
                if "iam:PassRole" in matched:
                    can_pass_role = True

        user.metadata = getattr(user, "metadata", {})
        user.metadata["can_create_ec2"] = can_create_ec2
        user.metadata["can_create_lambda"] = can_create_lambda
        user.metadata["can_modify_iam"] = can_modify_iam
        user.metadata["can_pass_role"] = can_pass_role
        user.metadata["escalation_vectors"] = list(set(escalation_vectors))

    log.info("scanner.iam_analysis.done")
