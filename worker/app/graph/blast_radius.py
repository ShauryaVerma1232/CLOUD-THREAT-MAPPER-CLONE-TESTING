"""
Blast Radius Simulator

Calculates the potential impact of a compromised node by finding all
reachable resources through the attack graph. Uses BFS/DFS traversal
to determine direct, secondary, and critical resource exposure.

This enables "What If" security analysis:
  - "If this EC2 is compromised, what can the attacker reach?"
  - "What's the blast radius of this IAM user?"
  - "Which resources are at risk if this S3 bucket is breached?"
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

import networkx as nx
import structlog

log = structlog.get_logger()

# High-value resource types that represent "crown jewels"
CRITICAL_RESOURCE_TYPES = {
    "S3_BUCKET",      # Data storage
    "RDS",            # Databases
    "IAM_ROLE",       # Privilege escalation
    "IAM_USER",       # Credential source
    "SECRET",         # Secrets manager
    "KMS_KEY",        # Encryption keys
}

# Resource types that are typically high-value targets
HIGH_VALUE_TYPES = {
    "S3_BUCKET",
    "RDS",
    "IAM_ROLE",
    "EC2",
    "LAMBDA",
}


@dataclass
class BlastRadiusResult:
    """Result of a blast radius calculation."""

    # The compromised node ID
    compromised_node_id: str

    # Node type and label for display
    compromised_node_type: str = ""
    compromised_node_label: str = ""

    # Direct reach (1 hop from compromised node)
    direct_reach: list[str] = field(default_factory=list)
    direct_reach_count: int = 0

    # Secondary reach (2 hops from compromised node)
    secondary_reach: list[str] = field(default_factory=list)
    secondary_reach_count: int = 0

    # All reachable nodes (excluding the compromised node itself)
    all_reachable: list[str] = field(default_factory=list)
    total_reachable_count: int = 0

    # Critical resources at risk (high-value types)
    critical_at_risk: list[dict] = field(default_factory=list)
    critical_count: int = 0

    # Classification by hop distance
    by_hop_distance: dict[int, list[str]] = field(default_factory=dict)

    # Risk assessment
    blast_radius_severity: str = "low"  # critical | high | medium | low
    blast_radius_score: float = 0.0  # 0-10 scale

    # Attack paths from compromised node
    attack_paths_from_here: list[dict] = field(default_factory=list)


def calculate_blast_radius(
    G: nx.DiGraph,
    compromised_node_id: str,
    max_hops: int = 4,
    include_attack_paths: bool = True,
) -> BlastRadiusResult:
    """
    Calculate the blast radius of a compromised node.

    Args:
        G: NetworkX directed graph
        compromised_node_id: ID of the compromised node
        max_hops: Maximum hop distance to traverse (default 4)
        include_attack_paths: Whether to enumerate attack paths (slower but more informative)

    Returns:
        BlastRadiusResult with all reachable resources and risk assessment
    """
    log.info(
        "blast_radius.start",
        compromised_node=compromised_node_id,
        max_hops=max_hops,
    )

    if compromised_node_id not in G:
        raise ValueError(f"Node not found in graph: {compromised_node_id}")

    result = BlastRadiusResult(compromised_node_id=compromised_node_id)

    # Get node metadata
    node_attrs = G.nodes[compromised_node_id]
    result.compromised_node_type = node_attrs.get("node_type", "UNKNOWN")
    result.compromised_node_label = node_attrs.get("label", compromised_node_id)

    # BFS to find all reachable nodes and classify by hop distance
    reachable_by_hop = _bfs_by_hop_distance(G, compromised_node_id, max_hops)

    # Store hop-distance classification
    result.by_hop_distance = reachable_by_hop

    # Flatten all reachable nodes
    all_reachable = set()
    for hop_nodes in reachable_by_hop.values():
        all_reachable.update(hop_nodes)

    result.all_reachable = list(all_reachable)
    result.total_reachable_count = len(all_reachable)

    # Direct reach (hop 1)
    result.direct_reach = reachable_by_hop.get(1, [])
    result.direct_reach_count = len(result.direct_reach)

    # Secondary reach (hop 2)
    result.secondary_reach = reachable_by_hop.get(2, [])
    result.secondary_reach_count = len(result.secondary_reach)

    # Identify critical resources at risk
    result.critical_at_risk = _identify_critical_resources(G, all_reachable)
    result.critical_count = len(result.critical_at_risk)

    # Calculate blast radius score
    result.blast_radius_score = _calculate_blast_score(
        G,
        compromised_node_id,
        all_reachable,
        result.critical_at_risk,
        reachable_by_hop,
    )

    # Classify severity
    result.blast_radius_severity = _classify_blast_severity(
        result.blast_radius_score,
        result.critical_count,
    )

    # Optionally enumerate attack paths from this node
    if include_attack_paths and all_reachable:
        result.attack_paths_from_here = _find_paths_from_compromised(
            G,
            compromised_node_id,
            all_reachable,
        )

    log.info(
        "blast_radius.complete",
        total_reachable=result.total_reachable_count,
        critical_at_risk=result.critical_count,
        severity=result.blast_radius_severity,
    )

    return result


def _bfs_by_hop_distance(
    G: nx.DiGraph,
    start_node: str,
    max_hops: int,
) -> dict[int, list[str]]:
    """
    Perform BFS from start node and return reachable nodes grouped by hop distance.

    Returns:
        Dict mapping hop distance (1, 2, 3...) to list of node IDs at that distance
    """
    result: dict[int, list[str]] = {}
    visited = {start_node}
    queue = deque([(start_node, 0)])  # (node_id, hop_distance)

    while queue:
        current, distance = queue.popleft()

        if distance >= max_hops:
            continue

        for successor in G.successors(current):
            if successor not in visited:
                visited.add(successor)
                next_distance = distance + 1

                if next_distance not in result:
                    result[next_distance] = []
                result[next_distance].append(successor)

                queue.append((successor, next_distance))

    return result


def _identify_critical_resources(
    G: nx.DiGraph,
    reachable_node_ids: set[str],
) -> list[dict]:
    """
    Identify high-value/critical resources in the reachable set.

    Returns:
        List of dicts with node_id, node_type, label, and risk metadata
    """
    critical = []

    for node_id in reachable_node_ids:
        if node_id not in G:
            continue

        attrs = G.nodes[node_id]
        node_type = attrs.get("node_type", "")

        if node_type in CRITICAL_RESOURCE_TYPES:
            metadata = attrs.get("metadata", {})
            critical.append({
                "node_id": node_id,
                "node_type": node_type,
                "label": attrs.get("label", node_id),
                "is_admin": metadata.get("is_admin", False),
                "is_public": attrs.get("public", False),
                "metadata": metadata,
            })

    # Sort by criticality: admin IAM roles first, then databases, then S3
    type_priority = {
        "IAM_ROLE": 0,
        "RDS": 1,
        "S3_BUCKET": 2,
        "IAM_USER": 3,
        "EC2": 4,
        "LAMBDA": 5,
    }
    critical.sort(key=lambda x: (type_priority.get(x["node_type"], 99), x["node_id"]))

    return critical


def _calculate_blast_score(
    G: nx.DiGraph,
    compromised_node_id: str,
    reachable_node_ids: set[str],
    critical_resources: list[dict],
    reachable_by_hop: dict[int, list[str]],
) -> float:
    """
    Calculate a 0-10 blast radius score based on:
    - Number of reachable resources
    - Critical resources at risk
    - Hop distance distribution (closer = worse)
    - Node types reachable
    """
    if not reachable_node_ids:
        return 0.0

    # Component 1: Reach count (0-3 points)
    reach_count = len(reachable_node_ids)
    reach_score = min(3.0, reach_count / 10.0)  # 30 resources = max score

    # Component 2: Critical resources (0-4 points)
    critical_count = len(critical_resources)
    critical_score = min(4.0, critical_count * 0.8)  # 5 critical = max score

    # Component 3: Hop distance penalty (0-2 points)
    # More resources at closer range = worse
    direct_count = len(reachable_by_hop.get(1, []))
    secondary_count = len(reachable_by_hop.get(2, []))
    proximity_score = min(2.0, (direct_count * 0.3) + (secondary_count * 0.15))

    # Component 4: Node type diversity (0-1 point)
    reachable_types = set()
    for node_id in reachable_node_ids:
        if node_id in G:
            reachable_types.add(G.nodes[node_id].get("node_type", ""))
    diversity_score = min(1.0, len(reachable_types) / 5.0)

    # Composite score
    total_score = reach_score + critical_score + proximity_score + diversity_score

    return round(total_score, 2)


def _classify_blast_severity(score: float, critical_count: int) -> str:
    """
    Classify blast radius severity based on score and critical resource count.
    """
    # Critical if 3+ critical resources OR score >= 8
    if critical_count >= 3 or score >= 8.0:
        return "critical"

    # High if 2 critical resources OR score >= 6
    if critical_count >= 2 or score >= 6.0:
        return "high"

    # Medium if 1 critical resource OR score >= 3.5
    if critical_count >= 1 or score >= 3.5:
        return "medium"

    return "low"


def _find_paths_from_compromised(
    G: nx.DiGraph,
    compromised_node_id: str,
    reachable_node_ids: set[str],
    max_paths: int = 10,
) -> list[dict]:
    """
    Find attack paths starting from the compromised node to high-value targets.

    Returns:
        List of simplified path dicts with path_string, target, and hop_count
    """
    from app.graph.attack_path_finder import AttackPath, _score_path

    paths = []
    seen_targets = set()

    # Find high-value targets in reachable set
    targets = [
        node_id for node_id in reachable_node_ids
        if node_id in G and G.nodes[node_id].get("node_type") in HIGH_VALUE_TYPES
    ]

    for target in targets[:max_paths]:
        if target in seen_targets:
            continue

        try:
            # Find shortest path to this target
            raw_path = nx.shortest_path(G, source=compromised_node_id, target=target)

            # Score the path
            ap = _score_path(G, raw_path, source_type="credential")

            paths.append({
                "path_string": ap.path_string,
                "path_nodes": ap.path_nodes,
                "target_node": target,
                "target_type": G.nodes[target].get("node_type", ""),
                "hop_count": len(raw_path) - 1,
                "risk_score": ap.risk_score,
                "severity": ap.severity,
            })

            seen_targets.add(target)

        except nx.NetworkXNoPath:
            pass
        except Exception:
            pass

    # Sort by risk score descending
    paths.sort(key=lambda p: p["risk_score"], reverse=True)

    return paths[:max_paths]


def calculate_multi_node_blast_radius(
    G: nx.DiGraph,
    compromised_node_ids: list[str],
    max_hops: int = 4,
) -> dict:
    """
    Calculate combined blast radius when multiple nodes are compromised.

    This is useful for scenarios like:
    - Multiple EC2 instances in same security group
    - All IAM users with admin access
    - All public-facing resources

    Returns:
        Dict with combined reach, unique critical resources, and overlap analysis
    """
    log.info(
        "blast_radius.multi_node_start",
        compromised_count=len(compromised_node_ids),
    )

    all_reachable = set()
    critical_resources = {}  # node_id -> resource info
    per_node_results = {}

    for node_id in compromised_node_ids:
        if node_id not in G:
            continue

        result = calculate_blast_radius(G, node_id, max_hops, include_attack_paths=False)
        per_node_results[node_id] = {
            "total_reachable": result.total_reachable_count,
            "critical_count": result.critical_count,
            "severity": result.blast_radius_severity,
        }

        all_reachable.update(result.all_reachable)

        for crit in result.critical_at_risk:
            critical_resources[crit["node_id"]] = crit

    # Calculate overlap - resources reachable from multiple compromised nodes
    reachability_sources: dict[str, list[str]] = {}
    for node_id in compromised_node_ids:
        if node_id in per_node_results:
            result = calculate_blast_radius(G, node_id, max_hops, include_attack_paths=False)
            for reachable_id in result.all_reachable:
                if reachable_id not in reachability_sources:
                    reachability_sources[reachable_id] = []
                reachability_sources[reachable_id].append(node_id)

    overlapping_resources = {
        node_id: sources
        for node_id, sources in reachability_sources.items()
        if len(sources) > 1
    }

    return {
        "compromised_nodes": compromised_node_ids,
        "total_unique_reachable": len(all_reachable),
        "critical_resources_at_risk": list(critical_resources.values()),
        "critical_count": len(critical_resources),
        "per_node_results": per_node_results,
        "overlapping_resources": overlapping_resources,
        "overlap_count": len(overlapping_resources),
    }
