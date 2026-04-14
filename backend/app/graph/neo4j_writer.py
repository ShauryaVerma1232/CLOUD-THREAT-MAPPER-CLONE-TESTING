"""
Neo4j Writer

Persists the NetworkX graph and computed attack paths into Neo4j.

Schema:
  (:Resource {node_id, node_type, label, risk_score, public, ...})
  -[:EDGE_TYPE {edge_type, weight, validated, ...}]->
  (:Resource)

  (:AttackPath {path_id, scan_job_id, path_string, risk_score, severity, ...})
  -[:CONTAINS {position}]->
  (:Resource)
"""
from __future__ import annotations

import json
import uuid
from typing import Any

import networkx as nx
import structlog
from neo4j import AsyncSession as Neo4jSession

from app.graph.attack_path_finder import AttackPath

log = structlog.get_logger()

# Batch size for Cypher UNWIND writes (keeps transactions fast)
BATCH_SIZE = 200


async def write_graph_to_neo4j(
    session: Neo4jSession,
    G: nx.DiGraph,
    scan_job_id: str,
    attack_paths: list[AttackPath],
) -> dict:
    """
    Full Neo4j write pipeline:
      1. Clear previous data for this scan_job_id
      2. Write all nodes
      3. Write all edges
      4. Write attack paths
    """
    log.info("neo4j_writer.start", scan_job_id=scan_job_id,
             nodes=G.number_of_nodes(), edges=G.number_of_edges(),
             paths=len(attack_paths))

    await _clear_scan_data(session, scan_job_id)
    node_count = await _write_nodes(session, G, scan_job_id)
    edge_count = await _write_edges(session, G, scan_job_id)
    path_count = await _write_attack_paths(session, attack_paths, scan_job_id)

    log.info("neo4j_writer.done",
             nodes=node_count, edges=edge_count, paths=path_count)
    return {
        "nodes_written": node_count,
        "edges_written": edge_count,
        "paths_written": path_count,
    }


async def _clear_scan_data(session: Neo4jSession, scan_job_id: str) -> None:
    """Remove all previously stored nodes/relationships for this scan."""
    await session.run(
        """
        MATCH (n:Resource {scan_job_id: $scan_job_id})
        DETACH DELETE n
        """,
        scan_job_id=scan_job_id,
    )
    await session.run(
        """
        MATCH (p:AttackPath {scan_job_id: $scan_job_id})
        DETACH DELETE p
        """,
        scan_job_id=scan_job_id,
    )


async def _write_nodes(
    session: Neo4jSession, G: nx.DiGraph, scan_job_id: str
) -> int:
    """Write all graph nodes in batches using UNWIND."""
    nodes = []
    for node_id, attrs in G.nodes(data=True):
        nodes.append({
            "node_id":    node_id,
            "node_type":  attrs.get("node_type", "UNKNOWN"),
            "label":      attrs.get("label", node_id),
            "risk_score": attrs.get("risk_score", 0.0),
            "public":     attrs.get("public", False),
            "account_id": attrs.get("account_id", ""),
            "region":     attrs.get("region", ""),
            "scan_job_id": scan_job_id,
            "metadata_json": json.dumps(attrs.get("metadata", {})),
        })

    # Write in batches
    total = 0
    for batch in _chunks(nodes, BATCH_SIZE):
        await session.run(
            """
            UNWIND $nodes AS n
            MERGE (r:Resource {node_id: n.node_id, scan_job_id: n.scan_job_id})
            SET r += {
                node_type:     n.node_type,
                label:         n.label,
                risk_score:    n.risk_score,
                public:        n.public,
                account_id:    n.account_id,
                region:        n.region,
                scan_job_id:   n.scan_job_id,
                metadata_json: n.metadata_json
            }
            WITH r, n
            CALL apoc.create.addLabels(r, [n.node_type]) YIELD node
            RETURN count(node)
            """,
            nodes=batch,
        )
        total += len(batch)

    return total


async def _write_edges(
    session: Neo4jSession, G: nx.DiGraph, scan_job_id: str
) -> int:
    """Write all edges. Groups edges by type for efficient UNWIND."""
    # Collect all edges with their type
    edges: list[dict] = []
    for src, tgt, data in G.edges(data=True):
        props = {k: v for k, v in data.items()
                 if k not in ("edge_type",) and isinstance(v, (str, int, float, bool))}
        edges.append({
            "source_id":   src,
            "target_id":   tgt,
            "edge_type":   data.get("edge_type", "connected_to"),
            "weight":      data.get("weight", 0.5),
            "validated":   data.get("validated", False),
            "scan_job_id": scan_job_id,
            "props_json":  json.dumps(props),
        })

    total = 0
    for batch in _chunks(edges, BATCH_SIZE):
        await session.run(
            """
            UNWIND $edges AS e
            MATCH (src:Resource {node_id: e.source_id, scan_job_id: e.scan_job_id})
            MATCH (tgt:Resource {node_id: e.target_id, scan_job_id: e.scan_job_id})
            MERGE (src)-[r:RELATIONSHIP {
                edge_type: e.edge_type,
                scan_job_id: e.scan_job_id
            }]->(tgt)
            SET r.weight     = e.weight,
                r.validated  = e.validated,
                r.props_json = e.props_json
            RETURN count(r)
            """,
            edges=batch,
        )
        total += len(batch)

    return total


async def _write_attack_paths(
    session: Neo4jSession,
    paths: list[AttackPath],
    scan_job_id: str,
) -> int:
    """Write each AttackPath as a node linked to its member resources."""
    for i, ap in enumerate(paths):
        path_id = str(uuid.uuid4())
        await session.run(
            """
            CREATE (p:AttackPath {
                path_id:              $path_id,
                scan_job_id:          $scan_job_id,
                path_string:          $path_string,
                risk_score:           $risk_score,
                severity:             $severity,
                reachability_score:   $reachability_score,
                impact_score:         $impact_score,
                exploitability_score: $exploitability_score,
                exposure_score:       $exposure_score,
                hop_count:            $hop_count,
                validated:            false,
                ai_explanation:       null,
                ai_remediation:       null,
                ai_privilege_escalation: null,
                ai_escalation_techniques: null,
                ai_true_risk_assessment: null,
                ai_remediation_priority: null
            })
            """,
            path_id=path_id,
            scan_job_id=scan_job_id,
            path_string=ap.path_string,
            risk_score=ap.risk_score,
            severity=ap.severity,
            reachability_score=ap.reachability_score,
            impact_score=ap.impact_score,
            exploitability_score=ap.exploitability_score,
            exposure_score=ap.exposure_score,
            hop_count=len(ap.path_nodes) - 1,
        )

        # Link path to each node in order
        for pos, node_id in enumerate(ap.path_nodes):
            await session.run(
                """
                MATCH (p:AttackPath {path_id: $path_id})
                MATCH (r:Resource {node_id: $node_id, scan_job_id: $scan_job_id})
                MERGE (p)-[:CONTAINS {position: $pos}]->(r)
                """,
                path_id=path_id,
                node_id=node_id,
                scan_job_id=scan_job_id,
                pos=pos,
            )

    return len(paths)


async def get_graph_for_scan(
    session: Neo4jSession, scan_job_id: str
) -> dict:
    """
    Retrieve the full graph for a scan in Cytoscape.js-compatible format.
    Returns {nodes: [...], edges: [...]}
    """
    # Nodes
    node_result = await session.run(
        """
        MATCH (r:Resource {scan_job_id: $scan_job_id})
        RETURN r.node_id AS id, r.node_type AS node_type,
               r.label AS label, r.risk_score AS risk_score,
               r.public AS public, r.region AS region,
               r.metadata_json AS metadata_json
        """,
        scan_job_id=scan_job_id,
    )
    nodes = []
    async for record in node_result:
        meta = {}
        try:
            meta = json.loads(record["metadata_json"] or "{}")
        except Exception:
            pass
        nodes.append({
            "data": {
                "id":         record["id"],
                "node_type":  record["node_type"],
                "label":      record["label"],
                "risk_score": record["risk_score"],
                "public":     record["public"],
                "region":     record["region"],
                **meta,
            }
        })

    # Edges
    edge_result = await session.run(
        """
        MATCH (src:Resource {scan_job_id: $scan_job_id})-[r:RELATIONSHIP]->(tgt:Resource {scan_job_id: $scan_job_id})
        RETURN src.node_id AS source, tgt.node_id AS target,
               r.edge_type AS edge_type, r.weight AS weight,
               r.validated AS validated
        """,
        scan_job_id=scan_job_id,
    )
    edges = []
    edge_id = 0
    async for record in edge_result:
        edges.append({
            "data": {
                "id":        f"e{edge_id}",
                "source":    record["source"],
                "target":    record["target"],
                "edge_type": record["edge_type"],
                "weight":    record["weight"],
                "validated": record["validated"],
            }
        })
        edge_id += 1

    return {"nodes": nodes, "edges": edges}


async def get_attack_paths_for_scan(
    session: Neo4jSession, scan_job_id: str
) -> list[dict]:
    """Retrieve all attack paths for a scan, ordered by risk score."""
    result = await session.run(
        """
        MATCH (p:AttackPath {scan_job_id: $scan_job_id})
        RETURN p.path_id AS path_id, p.path_string AS path_string,
               p.risk_score AS risk_score, p.severity AS severity,
               p.reachability_score AS reachability_score,
               p.impact_score AS impact_score,
               p.exploitability_score AS exploitability_score,
               p.exposure_score AS exposure_score,
               p.hop_count AS hop_count,
               p.validated AS validated,
               p.ai_explanation AS ai_explanation,
               p.ai_remediation AS ai_remediation,
               p.ai_iam_detected AS ai_iam_detected,
               p.ai_iam_techniques AS ai_escalation_techniques,
               p.ai_iam_technique_count AS ai_technique_count,
               p.ai_true_risk_assessment AS ai_true_risk_assessment,
               p.ai_remediation_priority AS ai_remediation_priority
        ORDER BY p.risk_score DESC
        """,
        scan_job_id=scan_job_id,
    )
    paths = []
    async for record in result:
        path_data = dict(record)

        # Parse techniques from JSON string
        techniques_str = path_data.get("ai_escalation_techniques")
        if techniques_str:
            try:
                techniques = json.loads(techniques_str)
            except Exception:
                techniques = []
        else:
            techniques = []
        path_data["ai_escalation_techniques"] = techniques

        # Build ai_privilege_escalation dict for schema compatibility
        detected = path_data.get("ai_iam_detected", "false") == "true"
        path_data["ai_privilege_escalation"] = {
            "detected": detected,
            "technique_count": path_data.get("ai_technique_count", 0),
            "true_risk_assessment": path_data.get("ai_true_risk_assessment", ""),
            "remediation_priority": path_data.get("ai_remediation_priority", "normal"),
        } if detected else None

        paths.append(path_data)
    return paths


def _chunks(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


async def update_attack_path_iam_analysis(
    session: Neo4jSession,
    scan_job_id: str,
    path_string: str,
    iam_analysis: dict,
) -> None:
    """Update an attack path with IAM privilege escalation analysis results."""
    await session.run(
        """
        MATCH (p:AttackPath {scan_job_id: $scan_job_id, path_string: $path_string})
        SET p.ai_privilege_escalation = $iam_analysis,
            p.ai_escalation_techniques = $techniques,
            p.ai_true_risk_assessment = $risk_assessment,
            p.ai_remediation_priority = $priority
        """,
        scan_job_id=scan_job_id,
        path_string=path_string,
        iam_analysis=iam_analysis,
        techniques=iam_analysis.get("escalation_techniques", []),
        risk_assessment=iam_analysis.get("true_risk_assessment", ""),
        priority=iam_analysis.get("remediation_priority", "normal"),
    )
