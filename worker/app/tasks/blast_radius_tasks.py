"""
Blast Radius Celery Tasks

Tasks for calculating and storing blast radius analysis results.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import structlog
from neo4j import GraphDatabase

from app.celery_app import celery_app
from app.graph.graph_builder import build_graph
from app.graph.blast_radius import calculate_blast_radius, calculate_multi_node_blast_radius
from app.tasks.db_utils import insert_blast_radius_result, get_sync_session
from sqlalchemy import text

log = structlog.get_logger()


def _get_neo4j_driver():
    """Create a Neo4j driver instance from environment variables."""
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://neo4j:7687"),
        auth=(
            os.environ.get("NEO4J_USER", "neo4j"),
            os.environ.get("NEO4J_PASSWORD", ""),
        ),
    )


def _write_blast_radius_to_neo4j(driver, scan_job_id: str, compromised_node_id: str, result: dict) -> None:
    """
    Write blast radius result to Neo4j graph database.

    Creates a :BlastRadius node linked to the compromised :Resource node.
    """
    with driver.session() as session:
        # Delete any existing blast radius for this compromised node
        session.run(
            """
            MATCH (br:BlastRadius {scan_job_id: $sjid, compromised_node_id: $cid})
            DETACH DELETE br
            """,
            sjid=scan_job_id,
            cid=compromised_node_id,
        )

        # Create new BlastRadius node
        session.run(
            """
            MATCH (r:Resource {node_id: $cid, scan_job_id: $sjid})
            CREATE (br:BlastRadius {
                scan_job_id: $sjid,
                compromised_node_id: $cid,
                total_reachable: $total,
                critical_count: $critical,
                severity: $severity,
                score: $score,
                created_at: datetime()
            })
            CREATE (r)-[:HAS_BLAST_RADIUS]->(br)
            """,
            sjid=scan_job_id,
            cid=compromised_node_id,
            total=result.get("total_reachable_count", 0),
            critical=result.get("critical_count", 0),
            severity=result.get("blast_radius_severity", "low"),
            score=result.get("blast_radius_score", 0.0),
        )

        # Link critical resources at risk
        critical_resources = result.get("critical_at_risk", [])
        for crit in critical_resources[:20]:  # Cap at 20 to avoid huge transactions
            session.run(
                """
                MATCH (br:BlastRadius {scan_job_id: $sjid, compromised_node_id: $cid})
                MATCH (r:Resource {node_id: $rid, scan_job_id: $sjid})
                MERGE (br)-[:CRITICAL_RESOURCE_AT_RISK {position: $pos}]->(r)
                """,
                sjid=scan_job_id,
                cid=compromised_node_id,
                rid=crit.get("node_id"),
                pos=critical_resources.index(crit),
            )


@celery_app.task(
    bind=True,
    name="app.tasks.blast_radius_tasks.calculate_blast_radius",
    max_retries=1,
    soft_time_limit=120,
    time_limit=180,
)
def calculate_blast_radius_task(
    self,
    scan_job_id: str,
    compromised_node_id: str,
    artifact_path: str = None,
    max_hops: int = 4,
    include_attack_paths: bool = True,
) -> dict:
    """
    Calculate blast radius for a specific compromised node.

    Args:
        scan_job_id: The scan job UUID
        compromised_node_id: The node ID to simulate compromise of
        artifact_path: Path to the infrastructure model JSON (optional, loads from Neo4j if not provided)
        max_hops: Maximum hop distance to traverse (default 4)

    Returns:
        Dict with blast radius analysis results
    """
    log.info(
        "blast_radius_task.start",
        scan_job_id=scan_job_id,
        compromised_node_id=compromised_node_id,
    )

    try:
        # Build graph from artifact
        if not artifact_path:
            raise ValueError("artifact_path is required for blast radius calculation")

        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        G = build_graph(path)

        # Calculate blast radius
        result = calculate_blast_radius(G, compromised_node_id, max_hops, include_attack_paths=include_attack_paths)

        # Convert result to dict for storage
        result_data = {
            "compromised_node_id": result.compromised_node_id,
            "compromised_node_type": result.compromised_node_type,
            "compromised_node_label": result.compromised_node_label,
            "direct_reach": result.direct_reach,
            "direct_reach_count": result.direct_reach_count,
            "secondary_reach": result.secondary_reach,
            "secondary_reach_count": result.secondary_reach_count,
            "all_reachable": result.all_reachable,
            "total_reachable_count": result.total_reachable_count,
            "critical_at_risk": result.critical_at_risk,
            "critical_count": result.critical_count,
            "by_hop_distance": {str(k): v for k, v in result.by_hop_distance.items()},
            "blast_radius_severity": result.blast_radius_severity,
            "blast_radius_score": result.blast_radius_score,
            "attack_paths_from_here": result.attack_paths_from_here,
        }

        # Write to PostgreSQL
        result_id = insert_blast_radius_result(
            scan_job_id,
            compromised_node_id,
            result_data,
        )

        # Write to Neo4j
        driver = _get_neo4j_driver()
        try:
            _write_blast_radius_to_neo4j(driver, scan_job_id, compromised_node_id, result_data)
        finally:
            driver.close()

        log.info(
            "blast_radius_task.complete",
            result_id=result_id,
            total_reachable=result.total_reachable_count,
            critical_count=result.critical_count,
            severity=result.blast_radius_severity,
        )

        return {
            "result_id": result_id,
            "scan_job_id": scan_job_id,
            "compromised_node_id": compromised_node_id,
            **result_data,
        }

    except Exception as e:
        log.error("blast_radius_task.error", scan_job_id=scan_job_id, error=str(e))
        raise


@celery_app.task(
    bind=True,
    name="app.tasks.blast_radius_tasks.calculate_multi_node_blast_radius",
    max_retries=1,
    soft_time_limit=180,
    time_limit=240,
)
def calculate_multi_node_blast_radius_task(
    self,
    scan_job_id: str,
    compromised_node_ids: list[str],
    artifact_path: str,
    max_hops: int = 4,
) -> dict:
    """
    Calculate combined blast radius when multiple nodes are compromised.

    Useful for analyzing:
    - All EC2 instances in a security group
    - All IAM users with admin access
    - All public-facing resources

    Returns:
        Dict with combined blast radius analysis
    """
    log.info(
        "blast_radius_task.multi_node_start",
        scan_job_id=scan_job_id,
        compromised_count=len(compromised_node_ids),
    )

    try:
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        G = build_graph(path)

        result = calculate_multi_node_blast_radius(G, compromised_node_ids, max_hops)

        log.info(
            "blast_radius_task.multi_node_complete",
            total_reachable=result.get("total_unique_reachable", 0),
            critical_count=result.get("critical_count", 0),
        )

        return {
            "scan_job_id": scan_job_id,
            **result,
        }

    except Exception as e:
        log.error("blast_radius_task.multi_node_error", scan_job_id=scan_job_id, error=str(e))
        raise


@celery_app.task(
    bind=True,
    name="app.tasks.blast_radius_tasks.analyze_all_public_resources",
    max_retries=1,
    soft_time_limit=300,
    time_limit=420,
)
def analyze_all_public_resources_blast_radius(
    self,
    scan_job_id: str,
    artifact_path: str,
    max_hops: int = 4,
) -> dict:
    """
    Analyze blast radius for all publicly-exposed resources.

    This identifies which public resources have the largest blast radius
    and should be prioritized for hardening.

    Returns:
        Dict with blast radius analysis for all public resources
    """
    log.info(
        "blast_radius_task.analyze_public_start",
        scan_job_id=scan_job_id,
    )

    try:
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        G = build_graph(path)

        # Find all public nodes
        public_nodes = [
            node_id for node_id, attrs in G.nodes(data=True)
            if attrs.get("public", False) and node_id != "INTERNET"
        ]

        log.info(
            "blast_radius_task.found_public_nodes",
            count=len(public_nodes),
        )

        results = []
        for node_id in public_nodes:
            try:
                result = calculate_blast_radius(G, node_id, max_hops, include_attack_paths=False)
                results.append({
                    "node_id": node_id,
                    "node_type": result.compromised_node_type,
                    "node_label": result.compromised_node_label,
                    "total_reachable": result.total_reachable_count,
                    "critical_count": result.critical_count,
                    "severity": result.blast_radius_severity,
                    "score": result.blast_radius_score,
                })
            except Exception as e:
                log.warning(
                    "blast_radius_task.node_error",
                    node_id=node_id,
                    error=str(e),
                )

        # Sort by blast radius score descending
        results.sort(key=lambda x: x["score"], reverse=True)

        log.info(
            "blast_radius_task.analyze_public_complete",
            analyzed_count=len(results),
        )

        return {
            "scan_job_id": scan_job_id,
            "public_resources_analyzed": len(results),
            "results": results,
        }

    except Exception as e:
        log.error("blast_radius_task.analyze_public_error", scan_job_id=scan_job_id, error=str(e))
        raise
