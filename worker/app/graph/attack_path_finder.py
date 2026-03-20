"""
Attack Path Finder

Takes the NetworkX graph and finds all meaningful attack paths:
  - Origin: INTERNET node (or any publicly-accessible node)
  - Target: High-value nodes (S3, RDS, IAM roles with admin scope)
  - Method: All simple paths up to MAX_PATH_LENGTH

Each path receives a composite risk score and severity classification.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx
import structlog

from app.graph.graph_builder import (
    NT_INTERNET, NT_S3, NT_RDS, NT_IAM_ROLE, NT_EC2, NT_LAMBDA,
    NT_IAM_USER, HIGH_VALUE_TYPES, IMPACT_WEIGHTS,
)

log = structlog.get_logger()

# ── Config ────────────────────────────────────────────────────────────────────
MAX_PATH_LENGTH   = 6     # Max hops in a single path
MAX_PATHS_PER_TGT = 20    # Cap paths per target (avoids explosion in dense graphs)
MIN_RISK_SCORE    = 1.5   # Discard paths below this score


@dataclass
class AttackPath:
    path_nodes: list[str]           # Node IDs in order
    path_edges: list[dict]          # Edge metadata for each hop
    path_string: str                # Human-readable "A → B → C"

    # Score components
    reachability_score: float = 0.0
    impact_score: float = 0.0
    exploitability_score: float = 0.0
    exposure_score: float = 0.0
    risk_score: float = 0.0

    severity: str = "low"           # critical | high | medium | low
    node_labels: list[str] = field(default_factory=list)


def find_attack_paths(G: nx.DiGraph) -> list[AttackPath]:
    """
    Enumerate all attack paths from INTERNET to high-value targets.
    Returns a list of AttackPath objects sorted by risk_score descending.
    """
    log.info("path_finder.start", nodes=G.number_of_nodes(), edges=G.number_of_edges())

    if "INTERNET" not in G:
        log.warning("path_finder.no_internet_node")
        return []

    # Identify high-value target nodes
    targets = [
        node_id for node_id, attrs in G.nodes(data=True)
        if attrs.get("node_type") in HIGH_VALUE_TYPES
        and node_id != "INTERNET"
    ]
    log.info("path_finder.targets", count=len(targets))

    all_paths: list[AttackPath] = []
    seen_path_strings: set[str] = set()

    for target in targets:
        try:
            paths_found = 0
            for raw_path in nx.all_simple_paths(
                G,
                source="INTERNET",
                target=target,
                cutoff=MAX_PATH_LENGTH,
            ):
                if paths_found >= MAX_PATHS_PER_TGT:
                    break

                path_str = _path_string(G, raw_path)
                if path_str in seen_path_strings:
                    continue
                seen_path_strings.add(path_str)

                ap = _score_path(G, raw_path)
                if ap.risk_score >= MIN_RISK_SCORE:
                    all_paths.append(ap)
                    paths_found += 1

        except nx.NetworkXNoPath:
            pass
        except nx.NodeNotFound:
            pass

    # Sort by risk score descending
    all_paths.sort(key=lambda p: p.risk_score, reverse=True)

    log.info("path_finder.done", paths_found=len(all_paths))
    return all_paths


def _score_path(G: nx.DiGraph, node_ids: list[str]) -> AttackPath:
    """
    Compute all score components for a single path.

    Formula:
      risk_score = (reachability × 0.30)
                 + (impact       × 0.35)
                 + (exploitability × 0.25)
                 + (exposure     × 0.10)
    """
    edges: list[dict] = []
    for i in range(len(node_ids) - 1):
        src, tgt = node_ids[i], node_ids[i + 1]
        edge_data = G.edges[src, tgt]
        edges.append({
            "source": src,
            "target": tgt,
            "edge_type": edge_data.get("edge_type", "unknown"),
            "weight": edge_data.get("weight", 0.5),
            **{k: v for k, v in edge_data.items()
               if k not in ("edge_type", "weight", "validated")},
        })

    node_labels = [G.nodes[n].get("label", n) for n in node_ids]

    # ── Reachability ──────────────────────────────────────────────────────────
    # Fraction of edges that are "easy" (weight >= 0.7)
    if edges:
        easy_edges = sum(1 for e in edges if e["weight"] >= 0.7)
        reachability = easy_edges / len(edges)
    else:
        reachability = 0.0

    # ── Impact ────────────────────────────────────────────────────────────────
    # Value of the terminal node
    terminal_type = G.nodes[node_ids[-1]].get("node_type", "")
    impact = IMPACT_WEIGHTS.get(terminal_type, 0.5)

    # Boost for admin roles
    if terminal_type == NT_IAM_ROLE:
        meta = G.nodes[node_ids[-1]].get("metadata", {})
        if meta.get("is_admin"):
            impact = min(impact + 0.25, 1.0)

    # ── Exploitability ────────────────────────────────────────────────────────
    # Fewer hops = more exploitable
    # Penalise paths requiring many steps
    hop_count = len(node_ids) - 1
    exploitability = max(0.0, 1.0 - (hop_count - 1) * 0.15)

    # Boost if path contains an IMDSv1-enabled EC2 (trivial credential theft)
    for nid in node_ids:
        meta = G.nodes[nid].get("metadata", {})
        if meta.get("imdsv1_enabled"):
            exploitability = min(exploitability + 0.2, 1.0)
            break

    # ── Exposure ──────────────────────────────────────────────────────────────
    # Is the first non-INTERNET node directly internet-accessible?
    if len(node_ids) > 1:
        second_node = G.nodes[node_ids[1]]
        first_edge = edges[0] if edges else {}
        if first_edge.get("edge_type") == "exposes" and second_node.get("public"):
            exposure = 1.0
        elif second_node.get("public"):
            exposure = 0.7
        else:
            exposure = 0.3
    else:
        exposure = 0.0

    # ── Composite score ───────────────────────────────────────────────────────
    risk_score = (
        reachability   * 0.30 +
        impact         * 0.35 +
        exploitability * 0.25 +
        exposure       * 0.10
    ) * 10.0   # Scale to 0–10

    severity = _classify_severity(risk_score)
    path_str = _path_string(G, node_ids)

    return AttackPath(
        path_nodes=node_ids,
        path_edges=edges,
        path_string=path_str,
        reachability_score=round(reachability, 4),
        impact_score=round(impact, 4),
        exploitability_score=round(exploitability, 4),
        exposure_score=round(exposure, 4),
        risk_score=round(risk_score, 2),
        severity=severity,
        node_labels=node_labels,
    )


def _path_string(G: nx.DiGraph, node_ids: list[str]) -> str:
    labels = [G.nodes[n].get("label", n) for n in node_ids]
    return " → ".join(labels)


def _classify_severity(score: float) -> str:
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 3.5:
        return "medium"
    return "low"
