"""
Graph Builder

Reads a saved InfrastructureModel JSON artifact and constructs a
NetworkX directed multigraph where:
  - Nodes  = AWS resources + the virtual INTERNET node
  - Edges  = security relationships (exposes, assumes_role, can_access, etc.)

The resulting graph is passed to:
  - AttackPathFinder  (path enumeration + scoring)
  - Neo4jWriter       (persistence)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import structlog

log = structlog.get_logger()

# ── Node type constants ────────────────────────────────────────────────────────
NT_INTERNET  = "INTERNET"
NT_EC2       = "EC2"
NT_IAM_ROLE  = "IAM_ROLE"
NT_IAM_USER  = "IAM_USER"
NT_S3        = "S3_BUCKET"
NT_VPC       = "VPC"
NT_SUBNET    = "SUBNET"
NT_SG        = "SECURITY_GROUP"
NT_RDS       = "RDS"
NT_LAMBDA    = "LAMBDA"

# ── Edge type constants ────────────────────────────────────────────────────────
ET_EXPOSES      = "exposes"
ET_ASSUMES      = "assumes_role"
ET_CAN_ASSUME   = "can_assume"
ET_CAN_ACCESS   = "can_access"
ET_CONNECTED    = "connected_to"
ET_TRUSTS       = "trusts"
ET_NETWORK      = "network_access"

# ── High-value target node types (used in path finding) ───────────────────────
HIGH_VALUE_TYPES = {NT_S3, NT_RDS, NT_IAM_ROLE}

# ── Risk weights per resource type ────────────────────────────────────────────
IMPACT_WEIGHTS = {
    NT_S3:      0.80,
    NT_RDS:     0.90,
    NT_IAM_ROLE: 0.70,
    NT_EC2:     0.50,
    NT_LAMBDA:  0.55,
    NT_SUBNET:  0.20,
    NT_VPC:     0.20,
    NT_SG:      0.15,
    NT_INTERNET: 0.0,
    NT_IAM_USER: 0.60,
}


def build_graph(artifact_path: Path) -> nx.DiGraph:
    """
    Load an InfrastructureModel JSON artifact and build a directed graph.

    Returns a NetworkX DiGraph with full node/edge attribute sets
    ready for attack path analysis.
    """
    log.info("graph_builder.start", artifact=str(artifact_path))

    with open(artifact_path) as f:
        data = json.load(f)

    G = nx.DiGraph()

    # ── Add virtual INTERNET node ─────────────────────────────────────────────
    G.add_node(
        "INTERNET",
        node_type=NT_INTERNET,
        label="Internet",
        risk_score=0.0,
        public=True,
        account_id=data.get("account_id", ""),
        region="global",
        metadata={},
    )

    # ── EC2 instances ─────────────────────────────────────────────────────────
    for inst in data.get("ec2_instances", []):
        node_id = inst["instance_id"]
        name = _tag(inst.get("tags", {}), "Name") or node_id
        G.add_node(
            node_id,
            node_type=NT_EC2,
            label=f"EC2: {name}",
            risk_score=0.0,
            public=inst.get("public_ip") is not None,
            account_id=data["account_id"],
            region=inst.get("region", data["region"]),
            metadata={
                "instance_type": inst.get("instance_type"),
                "state":         inst.get("state"),
                "private_ip":    inst.get("private_ip"),
                "public_ip":     inst.get("public_ip"),
                "iam_role":      inst.get("iam_role_name"),
                "imdsv1_enabled": inst.get("metadata_options", {}).get(
                    "HttpTokens"
                ) == "optional",
            },
        )

    # ── IAM roles ─────────────────────────────────────────────────────────────
    for role in data.get("iam_roles", []):
        node_id = role["arn"]
        # Derive permission scope label
        is_admin = _is_admin_role(role)
        scope = "admin" if is_admin else "limited"
        G.add_node(
            node_id,
            node_type=NT_IAM_ROLE,
            label=f"Role: {role['role_name']}",
            risk_score=0.0,
            public=False,
            account_id=data["account_id"],
            region="global",
            metadata={
                "role_name":    role["role_name"],
                "is_admin":     is_admin,
                "scope":        scope,
                "policy_count": (
                    len(role.get("inline_policies", []))
                    + len(role.get("attached_policy_arns", []))
                ),
            },
        )

    # ── IAM users ─────────────────────────────────────────────────────────────
    for user in data.get("iam_users", []):
        node_id = user["arn"]
        G.add_node(
            node_id,
            node_type=NT_IAM_USER,
            label=f"User: {user['user_name']}",
            risk_score=0.0,
            public=False,
            account_id=data["account_id"],
            region="global",
            metadata={
                "user_name":        user["user_name"],
                "has_console":      user.get("has_console_access", False),
                "has_mfa":          user.get("has_mfa", False),
                "active_key_count": sum(
                    1 for k in user.get("access_keys", [])
                    if k.get("status") == "Active"
                ),
            },
        )

    # ── S3 buckets ────────────────────────────────────────────────────────────
    for bucket in data.get("s3_buckets", []):
        node_id = bucket["arn"]
        G.add_node(
            node_id,
            node_type=NT_S3,
            label=f"S3: {bucket['name']}",
            risk_score=0.0,
            public=bucket.get("is_public", False),
            account_id=data["account_id"],
            region=bucket.get("region", data["region"]),
            metadata={
                "bucket_name":        bucket["name"],
                "is_public":          bucket.get("is_public", False),
                "versioning":         bucket.get("versioning_enabled", False),
                "encryption":         bucket.get("encryption_enabled", False),
                "public_access_block": bucket.get("public_access_block", {}),
            },
        )

    # ── VPCs ──────────────────────────────────────────────────────────────────
    for vpc in data.get("vpcs", []):
        G.add_node(
            vpc["vpc_id"],
            node_type=NT_VPC,
            label=f"VPC: {vpc['vpc_id']}",
            risk_score=0.0,
            public=False,
            account_id=data["account_id"],
            region=vpc.get("region", data["region"]),
            metadata={"cidr": vpc.get("cidr_block"), "is_default": vpc.get("is_default")},
        )

    # ── Subnets ───────────────────────────────────────────────────────────────
    for subnet in data.get("subnets", []):
        name = _tag(subnet.get("tags", {}), "Name") or subnet["subnet_id"]
        G.add_node(
            subnet["subnet_id"],
            node_type=NT_SUBNET,
            label=f"Subnet: {name}",
            risk_score=0.0,
            public=subnet.get("is_public", False),
            account_id=data["account_id"],
            region=data["region"],
            metadata={"cidr": subnet.get("cidr_block"), "is_public": subnet.get("is_public")},
        )

    # ── Security groups ───────────────────────────────────────────────────────
    for sg in data.get("security_groups", []):
        has_public_ingress = _sg_has_public_ingress(sg)
        G.add_node(
            sg["group_id"],
            node_type=NT_SG,
            label=f"SG: {sg.get('group_name', sg['group_id'])}",
            risk_score=0.0,
            public=has_public_ingress,
            account_id=data["account_id"],
            region=data["region"],
            metadata={
                "group_name":        sg.get("group_name"),
                "has_public_ingress": has_public_ingress,
                "ingress_rule_count": len(sg.get("ingress_rules", [])),
            },
        )

    # ── RDS instances ─────────────────────────────────────────────────────────
    for db in data.get("rds_instances", []):
        node_id = db["db_instance_id"]
        G.add_node(
            node_id,
            node_type=NT_RDS,
            label=f"RDS: {node_id}",
            risk_score=0.0,
            public=db.get("publicly_accessible", False),
            account_id=data["account_id"],
            region=db.get("region", data["region"]),
            metadata={
                "engine":             db.get("engine"),
                "publicly_accessible": db.get("publicly_accessible"),
                "encrypted":          db.get("encrypted"),
                "iam_auth":           db.get("iam_auth_enabled"),
            },
        )

    # ── Lambda functions ──────────────────────────────────────────────────────
    for fn in data.get("lambda_functions", []):
        node_id = fn["function_arn"]
        G.add_node(
            node_id,
            node_type=NT_LAMBDA,
            label=f"Lambda: {fn['function_name']}",
            risk_score=0.0,
            public=False,
            account_id=data["account_id"],
            region=fn.get("region", data["region"]),
            metadata={
                "function_name": fn["function_name"],
                "runtime":       fn.get("runtime"),
                "in_vpc":        fn.get("vpc_config") is not None,
            },
        )

    # ── Add edges from relationships ──────────────────────────────────────────
    for rel in data.get("relationships", []):
        src = rel["source_id"]
        tgt = rel["target_id"]
        rel_type = rel["rel_type"]
        props = rel.get("properties", {})

        # Only add edge if both nodes exist
        if src in G and tgt in G:
            # Weight: how "easy" is it to traverse this edge (1.0 = trivial)
            weight = _edge_weight(rel_type, props)
            G.add_edge(
                src, tgt,
                edge_type=rel_type,
                weight=weight,
                validated=False,
                **props,
            )
        else:
            # Nodes might be cross-region or missing due to partial scans
            log.debug(
                "graph_builder.edge_skipped",
                src=src, tgt=tgt, missing_src=src not in G, missing_tgt=tgt not in G
            )

    # ── Add edges from INTERNET to public-facing resources ────────────────────
    # EC2 instances with public IPs
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("node_type") == NT_EC2 and attrs.get("public", False):
            G.add_edge(
                "INTERNET", node_id,
                edge_type=ET_EXPOSES,
                weight=1.0,
                validated=False,
                exposure_reason="public_ip",
            )
            log.debug("graph_builder.internet_edge", target=node_id, reason="public_ip")

    # Security groups with public ingress (0.0.0.0/0)
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("node_type") == NT_SG and attrs.get("public", False):
            G.add_edge(
                "INTERNET", node_id,
                edge_type=ET_EXPOSES,
                weight=1.0,
                validated=False,
                exposure_reason="public_ingress",
            )
            log.debug("graph_builder.internet_edge", target=node_id, reason="public_ingress")

    # Public S3 buckets
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("node_type") == NT_S3 and attrs.get("public", False):
            G.add_edge(
                "INTERNET", node_id,
                edge_type=ET_EXPOSES,
                weight=1.0,
                validated=False,
                exposure_reason="public_bucket",
            )
            log.debug("graph_builder.internet_edge", target=node_id, reason="public_bucket")

    # Publicly accessible RDS instances
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("node_type") == NT_RDS and attrs.get("public", False):
            G.add_edge(
                "INTERNET", node_id,
                edge_type=ET_EXPOSES,
                weight=1.0,
                validated=False,
                exposure_reason="publicly_accessible",
            )
            log.debug("graph_builder.internet_edge", target=node_id, reason="publicly_accessible")

    node_count = G.number_of_nodes()
    edge_count = G.number_of_edges()
    log.info("graph_builder.done", nodes=node_count, edges=edge_count)
    return G


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tag(tags: dict, key: str) -> str | None:
    return tags.get(key)


def _is_admin_role(role: dict) -> bool:
    """Heuristic: role is admin if it has AdministratorAccess or iam:* or *:*."""
    admin_arns = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }
    for arn in role.get("attached_policy_arns", []):
        if arn in admin_arns:
            return True
    for policy in role.get("managed_policies", []):
        if policy.get("arn") in admin_arns:
            return True
        doc = policy.get("document") or {}
        if _policy_has_star_star(doc):
            return True
    for policy in role.get("inline_policies", []):
        if _policy_has_star_star(policy.get("document", {})):
            return True
    return False


def _policy_has_star_star(doc: dict) -> bool:
    """Return True if a policy document has Action:* on Resource:*."""
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def _sg_has_public_ingress(sg: dict) -> bool:
    for rule in sg.get("ingress_rules", []):
        for cidr in rule.get("cidr_ranges", []):
            if cidr in ("0.0.0.0/0", "::/0"):
                return True
    return False


def _edge_weight(rel_type: str, props: dict) -> float:
    """
    Edge traversal weight (0.0–1.0).
    Higher = easier for attacker to traverse.
    Used in path scoring.
    """
    weights = {
        ET_EXPOSES:    1.0,   # Direct internet exposure = easiest
        ET_TRUSTS:     0.9,   # Role trust = very easy if reachable
        ET_ASSUMES:    0.8,   # EC2 metadata SSRF → role assumption
        ET_CAN_ASSUME: 0.85,  # IAM user can assume role (privilege escalation)
        ET_CAN_ACCESS: 0.75,
        ET_NETWORK:    0.7,
        ET_CONNECTED:  0.4,
    }
    base = weights.get(rel_type, 0.5)
    # Bump weight if this is a "*" trust (completely open)
    if props.get("principal") == "*":
        base = min(base + 0.1, 1.0)
    return base
