"""
Graph Build Celery Task — fixed DB operations via db_utils.
"""
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import structlog
from neo4j import GraphDatabase

from app.celery_app import celery_app
from app.graph.graph_builder import build_graph
from app.graph.attack_path_finder import find_attack_paths, AttackPath
from app.tasks.db_utils import update_scan_job, insert_attack_paths

log = structlog.get_logger()


def _get_neo4j_driver():
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://neo4j:7687"),
        auth=(
            os.environ.get("NEO4J_USER", "neo4j"),
            os.environ.get("NEO4J_PASSWORD", ""),
        ),
    )


def _write_to_neo4j_sync(driver, G, scan_job_id: str, paths: list) -> dict:
    import json

    BATCH = 200

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    with driver.session() as session:
        session.run("MATCH (n:Resource {scan_job_id:$s}) DETACH DELETE n", s=scan_job_id)
        session.run("MATCH (p:AttackPath {scan_job_id:$s}) DETACH DELETE p", s=scan_job_id)

        nodes = [
            {
                "node_id":      node_id,
                "node_type":    attrs.get("node_type", "UNKNOWN"),
                "label":        attrs.get("label", node_id),
                "risk_score":   attrs.get("risk_score", 0.0),
                "public":       attrs.get("public", False),
                "account_id":   attrs.get("account_id", ""),
                "region":       attrs.get("region", ""),
                "scan_job_id":  scan_job_id,
                "metadata_json": json.dumps(attrs.get("metadata", {})),
            }
            for node_id, attrs in G.nodes(data=True)
        ]
        for batch in chunks(nodes, BATCH):
            session.run("""
                UNWIND $nodes AS n
                MERGE (r:Resource {node_id: n.node_id, scan_job_id: n.scan_job_id})
                SET r += {node_type: n.node_type, label: n.label,
                          risk_score: n.risk_score, public: n.public,
                          account_id: n.account_id, region: n.region,
                          metadata_json: n.metadata_json}
            """, nodes=batch)

        edges = [
            {
                "source_id":  src,
                "target_id":  tgt,
                "edge_type":  data.get("edge_type", "connected_to"),
                "weight":     data.get("weight", 0.5),
                "validated":  data.get("validated", False),
                "scan_job_id": scan_job_id,
            }
            for src, tgt, data in G.edges(data=True)
        ]
        for batch in chunks(edges, BATCH):
            session.run("""
                UNWIND $edges AS e
                MATCH (src:Resource {node_id: e.source_id, scan_job_id: e.scan_job_id})
                MATCH (tgt:Resource {node_id: e.target_id, scan_job_id: e.scan_job_id})
                MERGE (src)-[r:RELATIONSHIP {edge_type: e.edge_type, scan_job_id: e.scan_job_id}]->(tgt)
                SET r.weight = e.weight, r.validated = e.validated
            """, edges=batch)

        for ap in paths:
            path_id = str(uuid.uuid4())
            session.run("""
                CREATE (p:AttackPath {
                    path_id: $pid, scan_job_id: $sjid,
                    path_string: $ps, risk_score: $rs,
                    severity: $sev, hop_count: $hc, validated: false,
                    reachability_score: $reach, impact_score: $impact,
                    exploitability_score: $exploit, exposure_score: $exposure
                })
            """, pid=path_id, sjid=scan_job_id, ps=ap.path_string,
                rs=ap.risk_score, sev=ap.severity, hc=len(ap.path_nodes) - 1,
                reach=ap.reachability_score, impact=ap.impact_score,
                exploit=ap.exploitability_score, exposure=ap.exposure_score)

            for pos, node_id in enumerate(ap.path_nodes):
                try:
                    session.run("""
                        MATCH (p:AttackPath {path_id: $pid})
                        MATCH (r:Resource {node_id: $nid, scan_job_id: $sjid})
                        MERGE (p)-[:CONTAINS {position: $pos}]->(r)
                    """, pid=path_id, nid=node_id, sjid=scan_job_id, pos=pos)
                except Exception:
                    pass

    return {
        "nodes_written": len(nodes),
        "edges_written": len(edges),
        "paths_written": len(paths),
    }


@celery_app.task(
    bind=True,
    name="app.tasks.graph_tasks.build_attack_graph",
    max_retries=1,
    soft_time_limit=600,
    time_limit=720,
)
def build_attack_graph(self, scan_job_id: str, artifact_path: str) -> dict:
    """Build attack graph from a completed scan artifact."""
    log.info("graph_task.start", scan_job_id=scan_job_id, artifact=artifact_path)

    try:
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        G = build_graph(path)
        log.info("graph_task.graph_built",
                 nodes=G.number_of_nodes(), edges=G.number_of_edges())

        attack_paths = find_attack_paths(G)
        log.info("graph_task.paths_found", count=len(attack_paths))

        driver = _get_neo4j_driver()
        try:
            neo4j_result = _write_to_neo4j_sync(driver, G, scan_job_id, attack_paths)
        finally:
            driver.close()

        inserted = insert_attack_paths(scan_job_id, attack_paths)

        critical_count = sum(1 for p in attack_paths if p.severity == "critical")
        overall_risk = max((p.risk_score for p in attack_paths), default=0.0)

        update_scan_job(scan_job_id, {
            "attack_path_count":  len(attack_paths),
            "critical_path_count": critical_count,
            "overall_risk_score":  overall_risk,
            "updated_at":          datetime.now(timezone.utc),
        })

        result = {
            "scan_job_id":    scan_job_id,
            "graph_nodes":    G.number_of_nodes(),
            "graph_edges":    G.number_of_edges(),
            "attack_paths":   len(attack_paths),
            "critical_paths": critical_count,
            "overall_risk":   overall_risk,
            **neo4j_result,
        }
        log.info("graph_task.complete", **result)

        # ── Auto-chain AI analysis ────────────────────────────────────────────
        try:
            from app.tasks.ai_tasks import run_ai_analysis
            run_ai_analysis.delay(scan_job_id=scan_job_id)
            log.info("graph_task.ai_analysis_queued", scan_job_id=scan_job_id)
        except Exception as e:
            log.warning("graph_task.ai_chain_error", error=str(e))

        return result

    except Exception as e:
        log.error("graph_task.error", scan_job_id=scan_job_id, error=str(e))
        raise
