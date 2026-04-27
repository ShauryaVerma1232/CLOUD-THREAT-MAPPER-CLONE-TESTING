"""
AI Reasoning Celery Task — Day 4 (rate-limit safe)

Changes from original:
  - MAX_NODES_TO_ANNOTATE reduced to 3 (most impactful nodes only)
  - INTER_CALL_DELAY added between every Gemini API call
  - Node annotation now sequential with delay, not rapid-fire
"""
import json
import os
import time
import uuid as uuid_mod
from datetime import datetime, timezone

import structlog
from neo4j import GraphDatabase
from sqlalchemy import text

from app.celery_app import celery_app
from app.ai.reasoning_engine import AIReasoningEngine
from app.tasks.db_utils import get_sync_engine, get_sync_session

log = structlog.get_logger()

MAX_PATHS_TO_EXPLAIN   = 5    # reduced from 10
MAX_NODES_TO_ANNOTATE  = 3    # reduced from 20 — annotate top 3 most risky only
MAX_DEEP_IAM_ANALYSIS  = 2    # Deep IAM analysis for top 2 highest-risk paths
MAX_THREAT_ACTOR_MAP   = 2    # Threat actor mapping for top 2 critical paths
MAX_BLAST_RADIUS       = 3    # Blast radius analysis for top 3 paths
INTER_CALL_DELAY       = 12.0  # seconds between API calls — conservative for Groq free tier (5 RPM)

# Risk escalation multipliers
ESCALATION_MULTIPLIER_CRITICAL = 2.0  # For admin privilege escalation
ESCALATION_MULTIPLIER_HIGH = 1.7      # For significant privilege escalation
ESCALATION_MULTIPLIER_MEDIUM = 1.5    # For moderate privilege escalation
MIN_ESCALATION_MULTIPLIER = 1.3       # Minimum multiplier when escalation detected


# ── Infrastructure helpers ─────────────────────────────────────────────────────

def _get_neo4j():
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI",      "bolt://neo4j:7687"),
        auth=(
            os.environ.get("NEO4J_USER",     "neo4j"),
            os.environ.get("NEO4J_PASSWORD", ""),
        ),
    )


# ── DB helpers — NO ::cast syntax ─────────────────────────────────────────────

def _load_attack_paths(db, scan_job_id: str) -> list[dict]:
    rows = db.execute(
        text("""
            SELECT id::text, path_string, path_nodes, path_edges,
                   risk_score, severity, reachability_score,
                   impact_score, exploitability_score, exposure_score
            FROM attack_paths
            WHERE scan_job_id = :scan_job_id
            ORDER BY risk_score DESC
        """),
        {"scan_job_id": scan_job_id},
    ).fetchall()
    return [dict(r._mapping) for r in rows]


def _update_path_ai(db, path_id: str, explanation: dict) -> None:
    try:
        db.execute(
            text("""
                UPDATE attack_paths
                SET ai_explanation = :explanation,
                    ai_remediation = :remediation
                WHERE id::text = :path_id
            """),
            {
                "path_id":     path_id,
                "explanation": explanation.get("explanation", ""),
                "remediation": json.dumps(explanation.get("remediation_steps", [])),
            },
        )
        db.commit()
    except Exception as e:
        db.rollback()
        log.warning("ai_task.path_update_error", error=str(e))


def _update_path_iam_analysis(db, path_id: str, iam_analysis: dict) -> None:
    """
    Update attack_paths table with deep IAM privilege escalation analysis.
    """
    try:
        db.execute(
            text("""
                UPDATE attack_paths
                SET ai_privilege_escalation = CAST(:iam_analysis AS JSONB),
                    ai_escalation_techniques = CAST(:techniques AS JSONB),
                    ai_true_risk_assessment = :risk_assessment,
                    ai_remediation_priority = :priority
                WHERE id::text = :path_id
            """),
            {
                "path_id":       path_id,
                "iam_analysis":  json.dumps(iam_analysis),
                "techniques":    json.dumps(iam_analysis.get("escalation_techniques", [])),
                "risk_assessment": iam_analysis.get("true_risk_assessment", ""),
                "priority":      iam_analysis.get("remediation_priority", "normal"),
            },
        )
        db.commit()
        log.info("ai_task.iam_analysis_saved", path_id=path_id)
    except Exception as e:
        db.rollback()
        log.warning("ai_task.iam_analysis_update_error", error=str(e))


def _update_path_threat_actor_mapping(db, path_id: str, threat_actor_data: dict) -> None:
    """
    Update attack_paths table with threat actor TTP mapping.
    """
    try:
        db.execute(
            text("""
                UPDATE attack_paths
                SET ai_threat_actors = CAST(:threat_actors AS JSONB),
                    ai_mitre_mapping = CAST(:mitre_mapping AS JSONB)
                WHERE id::text = :path_id
            """),
            {
                "path_id":       path_id,
                "threat_actors": json.dumps(threat_actor_data.get("threat_actor_matches", [])),
                "mitre_mapping": json.dumps(threat_actor_data.get("mitre_attack_cloud_matrix", {})),
            },
        )
        db.commit()
        log.info("ai_task.threat_actor_mapping_saved", path_id=path_id)
    except Exception as e:
        db.rollback()
        log.warning("ai_task.threat_actor_mapping_error", error=str(e))


def _update_path_blast_radius(db, path_id: str, blast_radius_data: dict) -> None:
    """
    Update attack_paths table with blast radius quantification.
    """
    try:
        db.execute(
            text("""
                UPDATE attack_paths
                SET ai_blast_radius = CAST(:blast_radius AS JSONB),
                    ai_compromise_timeline = CAST(:timeline AS JSONB)
                WHERE id::text = :path_id
            """),
            {
                "path_id":   path_id,
                "blast_radius": json.dumps(blast_radius_data.get("blast_radius_summary", {})),
                "timeline": json.dumps(blast_radius_data.get("compromise_timeline", {})),
            },
        )
        db.commit()
        log.info("ai_task.blast_radius_saved", path_id=path_id)
    except Exception as e:
        db.rollback()
        log.warning("ai_task.blast_radius_error", error=str(e))


def _update_path_risk_score(db, path_id: str, new_risk_score: float, new_severity: str) -> None:
    """
    Update attack_paths table with escalated risk score after AI analysis.
    """
    try:
        db.execute(
            text("""
                UPDATE attack_paths
                SET risk_score = :risk_score,
                    severity = :severity,
                    ai_escalation_applied = true
                WHERE id::text = :path_id
            """),
            {
                "path_id":    path_id,
                "risk_score": new_risk_score,
                "severity":   new_severity,
            },
        )
        db.commit()
        log.info("ai_task.risk_score_escalated", path_id=path_id, new_score=new_risk_score, new_severity=new_severity)
    except Exception as e:
        db.rollback()
        log.warning("ai_task.risk_score_update_error", error=str(e))


def _update_neo4j_path_iam_analysis(
    neo4j_driver,
    scan_job_id: str,
    path_string: str,
    iam_analysis: dict,
) -> None:
    """
    Update Neo4j AttackPath node with IAM privilege escalation analysis.
    Neo4j requires primitive types only, so we serialize complex objects to JSON strings.
    """
    try:
        # Serialize all complex data to JSON strings for Neo4j compatibility
        techniques = iam_analysis.get("escalation_techniques", [])
        techniques_json = json.dumps(techniques) if techniques else "[]"

        # Convert boolean to string to avoid Neo4j type issues
        detected = str(iam_analysis.get("privilege_escalation_detected", False)).lower()

        with neo4j_driver.session() as session:
            session.run(
                """
                MATCH (p:AttackPath {scan_job_id: $sjid, path_string: $ps})
                SET p.ai_iam_detected = $detected,
                    p.ai_iam_techniques = $techniques_json,
                    p.ai_iam_technique_count = $tech_count,
                    p.ai_true_risk_assessment = $risk_assessment,
                    p.ai_remediation_priority = $priority
                """,
                sjid=scan_job_id,
                ps=path_string,
                detected=detected,
                techniques_json=techniques_json,
                tech_count=len(techniques),
                risk_assessment=iam_analysis.get("true_risk_assessment", ""),
                priority=iam_analysis.get("remediation_priority", "normal"),
            )
        log.info("ai_task.neo4j_iam_analysis_updated", path_string=path_string[:50])
    except Exception as e:
        log.warning("ai_task.neo4j_iam_analysis_error", path_string=path_string[:50], error=str(e))


def _update_neo4j_threat_actor_mapping(
    neo4j_driver,
    scan_job_id: str,
    path_string: str,
    threat_actor_data: dict,
) -> None:
    """
    Update Neo4j AttackPath node with threat actor TTP mapping.
    """
    try:
        with neo4j_driver.session() as session:
            session.run(
                """
                MATCH (p:AttackPath {scan_job_id: $sjid, path_string: $ps})
                SET p.ai_threat_actors = $threat_actors,
                    p.ai_mitre_mapping = $mitre_mapping
                """,
                sjid=scan_job_id,
                ps=path_string,
                threat_actors=json.dumps(threat_actor_data.get("threat_actor_matches", [])),
                mitre_mapping=json.dumps(threat_actor_data.get("mitre_attack_cloud_matrix", {})),
            )
        log.info("ai_task.neo4j_threat_actor_updated", path_string=path_string[:50])
    except Exception as e:
        log.warning("ai_task.neo4j_threat_actor_error", path_string=path_string[:50], error=str(e))


def _update_neo4j_blast_radius(
    neo4j_driver,
    scan_job_id: str,
    path_string: str,
    blast_radius_data: dict,
) -> None:
    """
    Update Neo4j AttackPath node with blast radius quantification.
    """
    try:
        with neo4j_driver.session() as session:
            session.run(
                """
                MATCH (p:AttackPath {scan_job_id: $sjid, path_string: $ps})
                SET p.ai_blast_radius = $blast_radius,
                    p.ai_compromise_timeline = $timeline
                """,
                sjid=scan_job_id,
                ps=path_string,
                blast_radius=json.dumps(blast_radius_data.get("blast_radius_summary", {})),
                timeline=json.dumps(blast_radius_data.get("compromise_timeline", {})),
            )
        log.info("ai_task.neo4j_blast_radius_updated", path_string=path_string[:50])
    except Exception as e:
        log.warning("ai_task.neo4j_blast_radius_error", path_string=path_string[:50], error=str(e))


def _update_neo4j_path_risk_score(
    neo4j_driver,
    scan_job_id: str,
    path_string: str,
    new_risk_score: float,
    new_severity: str,
    escalation_multiplier: float,
) -> None:
    """
    Update Neo4j AttackPath node with escalated risk score.
    """
    try:
        with neo4j_driver.session() as session:
            session.run(
                """
                MATCH (p:AttackPath {scan_job_id: $sjid, path_string: $ps})
                SET p.risk_score = $risk_score,
                    p.severity = $severity,
                    p.ai_escalation_multiplier = $multiplier,
                    p.ai_escalation_applied = true
                """,
                sjid=scan_job_id,
                ps=path_string,
                risk_score=new_risk_score,
                severity=new_severity,
                multiplier=escalation_multiplier,
            )
        log.info("ai_task.neo4j_risk_score_escalated", path_string=path_string[:50], new_score=new_risk_score)
    except Exception as e:
        log.warning("ai_task.neo4j_risk_score_update_error", path_string=path_string[:50], error=str(e))


def _load_scan_job(db, scan_job_id: str) -> dict | None:
    row = db.execute(
        text("SELECT * FROM scan_jobs WHERE id::text = :id"),
        {"id": scan_job_id},
    ).fetchone()
    return dict(row._mapping) if row else None


def _save_report(db, scan_job_id: str, analysis: dict) -> None:
    from psycopg2.extras import Json as PgJson

    exec_summary = analysis.get("executive_summary", {})
    exec_text = (
        exec_summary.get("executive_summary", "")
        if isinstance(exec_summary, dict)
        else str(exec_summary)
    )

    engine = get_sync_engine()
    try:
        with engine.connect() as conn:
            raw = conn.connection
            cursor = raw.cursor()
            cursor.execute(
                """
                INSERT INTO reports (
                    id, scan_job_id, title, executive_summary,
                    findings_json, remediation_roadmap, created_at
                ) VALUES (
                    %s::uuid, %s::uuid, %s, %s, %s, %s, %s
                )
                ON CONFLICT DO NOTHING
                """,
                (
                    str(uuid_mod.uuid4()),
                    scan_job_id,
                    f"AI Security Analysis — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
                    exec_text,
                    PgJson(analysis.get("priority_ranking", [])),
                    PgJson(analysis.get("remediation_roadmap", {})),
                    datetime.now(timezone.utc),
                ),
            )
            raw.commit()
            cursor.close()
        log.info("ai_task.report_saved", scan_job_id=scan_job_id)
    except Exception as e:
        log.error("ai_task.report_save_error", error=str(e))


def _update_neo4j_path_annotation(
    session, scan_job_id: str, path_string: str, annotation: dict
) -> None:
    try:
        session.run(
            """
            MATCH (p:AttackPath {scan_job_id: $sjid, path_string: $ps})
            SET p.ai_explanation       = $explanation,
                p.ai_remediation       = $remediation,
                p.ai_attack_narrative  = $narrative,
                p.ai_business_impact   = $impact,
                p.ai_likelihood        = $likelihood,
                p.ai_detection_signals = $detection
            """,
            sjid=scan_job_id,
            ps=path_string,
            explanation=annotation.get("explanation", ""),
            remediation=json.dumps(annotation.get("remediation_steps", [])),
            narrative=annotation.get("attack_narrative", ""),
            impact=annotation.get("business_impact", ""),
            likelihood=annotation.get("likelihood", ""),
            detection=annotation.get("detection_signals", ""),
        )
    except Exception as e:
        log.warning("ai_task.neo4j_path_update_error", error=str(e))


def _annotate_high_risk_nodes(
    engine: AIReasoningEngine, neo4j_driver, scan_job_id: str
) -> int:
    """
    Annotate top N highest-risk nodes with a delay between each call
    to avoid hitting the free tier RPM limit.
    """
    annotated = 0
    try:
        with neo4j_driver.session() as session:
            result = session.run(
                """
                MATCH (r:Resource {scan_job_id: $sjid})
                WHERE r.node_type IN ['IAM_ROLE','S3_BUCKET','RDS','EC2','LAMBDA']
                   OR r.public = true
                RETURN r.node_id AS node_id, r.node_type AS node_type,
                       r.metadata_json AS metadata_json, r.public AS public
                LIMIT $limit
                """,
                sjid=scan_job_id,
                limit=MAX_NODES_TO_ANNOTATE,
            )
            nodes = [dict(r) for r in result]

        for i, node in enumerate(nodes):
            # Delay between calls to stay under RPM limit
            if i > 0:
                log.info("ai_task.rate_limit_pause", seconds=INTER_CALL_DELAY)
                time.sleep(INTER_CALL_DELAY)

            try:
                metadata = json.loads(node.get("metadata_json") or "{}")
                metadata["is_public"] = node.get("public", False)

                annotation = engine.annotate_node(
                    node_type=node["node_type"],
                    metadata=metadata,
                )

                with neo4j_driver.session() as session:
                    session.run(
                        """
                        MATCH (r:Resource {node_id: $nid, scan_job_id: $sjid})
                        SET r.ai_risk_label  = $label,
                            r.ai_risk_detail = $detail,
                            r.ai_risk_level  = $level
                        """,
                        nid=node["node_id"],
                        sjid=scan_job_id,
                        label=annotation.get("risk_label", ""),
                        detail=annotation.get("risk_detail", ""),
                        level=annotation.get("risk_level", "info"),
                    )
                annotated += 1
            except Exception as e:
                log.warning("ai_task.node_annotation_error",
                            node=node.get("node_id"), error=str(e))

    except Exception as e:
        log.warning("ai_task.annotate_nodes_error", error=str(e))

    return annotated


# ── Main Celery task ───────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="app.tasks.ai_tasks.run_ai_analysis",
    max_retries=1,
    soft_time_limit=1200,
    time_limit=1500,
)
def run_ai_analysis(self, scan_job_id: str) -> dict:
    """
    Full AI analysis pipeline — auto-triggered after build_attack_graph.
    Rate-limit safe: 5s delay between calls, max 3 node annotations.
    Total API calls per scan: ~5-8 (well within free tier 15 RPM).
    """
    log.info("ai_task.start", scan_job_id=scan_job_id)

    db          = get_sync_session()
    neo4j_drv   = _get_neo4j()
    ai_engine   = AIReasoningEngine()

    results = {
        "scan_job_id":     scan_job_id,
        "paths_explained": 0,
        "nodes_annotated": 0,
        "provider":        ai_engine._provider.name,
    }

    try:
        # 1 — Load attack paths
        paths = _load_attack_paths(db, scan_job_id)
        log.info("ai_task.paths_loaded", count=len(paths))

        # 2 — Prioritize (1 API call)
        priority_result = ai_engine.prioritize_paths(paths)
        log.info("ai_task.prioritized")
        time.sleep(INTER_CALL_DELAY)

        # 3 — Explain top critical/high/medium paths (1 call each, with delay)
        to_explain = [p for p in paths if p.get("severity") in ("critical", "high", "medium")][:MAX_PATHS_TO_EXPLAIN]

        with neo4j_drv.session() as neo4j_session:
            for path in to_explain:
                try:
                    nodes_list = (path["path_nodes"] if isinstance(path["path_nodes"], list)
                                  else json.loads(path["path_nodes"] or "[]"))
                    edges_list = (path["path_edges"] if isinstance(path["path_edges"], list)
                                  else json.loads(path["path_edges"] or "[]"))
                except Exception:
                    nodes_list, edges_list = [], []

                explanation = ai_engine.explain_attack_path(
                    path_string=path["path_string"],
                    path_nodes=nodes_list,
                    path_edges=edges_list,
                    risk_score=float(path["risk_score"]),
                    severity=path["severity"],
                )
                _update_path_ai(db, path["id"], explanation)
                _update_neo4j_path_annotation(
                    neo4j_session, scan_job_id, path["path_string"], explanation
                )
                results["paths_explained"] += 1
                log.info("ai_task.path_explained", path=path["path_string"][:60])
                time.sleep(INTER_CALL_DELAY)

        # 3b — Deep IAM privilege escalation analysis (optional, for highest-risk paths)
        # Only run on paths with IAM-related resources and medium+ severity
        iam_paths = []
        for p in paths:
            if p.get("severity") not in ("critical", "high", "medium"):
                continue
            # Parse path_nodes from JSON string if needed
            nodes_data = p.get("path_nodes", "[]")
            if isinstance(nodes_data, str):
                try:
                    nodes_data = json.loads(nodes_data)
                except Exception:
                    nodes_data = []
            # Check if any node is IAM-related
            # Nodes can be either dicts with node_type OR string ARNs
            is_iam_path = False
            for n in nodes_data:
                if isinstance(n, dict) and "IAM" in str(n.get("node_type", "")):
                    is_iam_path = True
                    break
                elif isinstance(n, str) and ":iam:" in n.lower():
                    is_iam_path = True
                    break
            if is_iam_path:
                iam_paths.append(p)
            if len(iam_paths) >= MAX_DEEP_IAM_ANALYSIS:
                break

        for path in iam_paths:
            try:
                # Parse path_nodes and path_edges from JSON strings
                nodes_list = json.loads(path["path_nodes"]) if isinstance(path["path_nodes"], str) else path["path_nodes"]
                edges_list = json.loads(path["path_edges"]) if isinstance(path["path_edges"], str) else path["path_edges"]

                original_risk_score = float(path["risk_score"])
                original_severity = path["severity"]

                iam_analysis = ai_engine.analyze_iam_privilege_escalation(
                    path_string=path["path_string"],
                    path_nodes=nodes_list,
                    path_edges=edges_list,
                    risk_score=original_risk_score,
                    severity=original_severity,
                )

                # Save IAM analysis
                _update_path_iam_analysis(db, path["id"], iam_analysis)
                _update_neo4j_path_iam_analysis(
                    neo4j_drv, scan_job_id, path["path_string"], iam_analysis
                )

                # Apply risk score escalation if privilege escalation detected
                escalation_detected = iam_analysis.get("privilege_escalation_detected", False)
                if escalation_detected:
                    # Determine multiplier based on remediation priority
                    priority = iam_analysis.get("remediation_priority", "normal")
                    if priority == "critical":
                        multiplier = ESCALATION_MULTIPLIER_CRITICAL
                    elif priority == "high":
                        multiplier = ESCALATION_MULTIPLIER_HIGH
                    elif priority == "medium":
                        multiplier = ESCALATION_MULTIPLIER_MEDIUM
                    else:
                        multiplier = MIN_ESCALATION_MULTIPLIER

                    # Calculate new risk score
                    new_risk_score = min(original_risk_score * multiplier, 10.0)  # Cap at 10.0

                    # Determine new severity
                    if new_risk_score >= 8.0:
                        new_severity = "critical"
                    elif new_risk_score >= 6.0:
                        new_severity = "high"
                    elif new_risk_score >= 3.5:
                        new_severity = "medium"
                    else:
                        new_severity = "low"

                    # Update database and Neo4j with escalated score
                    _update_path_risk_score(db, path["id"], new_risk_score, new_severity)
                    _update_neo4j_path_risk_score(
                        neo4j_drv, scan_job_id, path["path_string"],
                        new_risk_score, new_severity, multiplier
                    )

                    log.info(
                        "ai_task.risk_escalated",
                        path=path["path_string"][:50],
                        original_score=original_risk_score,
                        new_score=new_risk_score,
                        multiplier=multiplier,
                        priority=priority,
                    )
                else:
                    log.info(
                        "ai_task.iam_analysis_complete",
                        path=path["path_string"][:50],
                        escalation_detected=escalation_detected,
                        priority=iam_analysis.get("remediation_priority"),
                    )

                time.sleep(INTER_CALL_DELAY)
            except Exception as e:
                log.warning("ai_task.iam_analysis_error", path=path.get("path_string"), error=str(e))

        # 3c — Threat actor TTP mapping (for top critical paths)
        # Maps attack paths to known APT groups and real-world incidents
        threat_actor_paths = [p for p in paths if p.get("severity") in ("critical", "high")][:MAX_THREAT_ACTOR_MAP]

        for path in threat_actor_paths:
            try:
                nodes_list = json.loads(path["path_nodes"]) if isinstance(path["path_nodes"], str) else path["path_nodes"]
                edges_list = json.loads(path["path_edges"]) if isinstance(path["path_edges"], str) else path["path_edges"]

                threat_actor_data = ai_engine.map_threat_actors(
                    path_string=path["path_string"],
                    path_nodes=nodes_list,
                    path_edges=edges_list,
                )

                _update_path_threat_actor_mapping(db, path["id"], threat_actor_data)
                _update_neo4j_threat_actor_mapping(neo4j_drv, scan_job_id, path["path_string"], threat_actor_data)
                log.info("ai_task.threat_actor_mapped", path=path["path_string"][:50])
                time.sleep(INTER_CALL_DELAY)

            except Exception as e:
                log.warning("ai_task.threat_actor_mapping_error", path=path.get("path_string"), error=str(e))

        # 3d — Blast radius quantification (for top 3 highest-risk paths)
        # Computes quantitative impact: how many resources compromised
        blast_radius_paths = sorted(paths, key=lambda p: p.get("risk_score", 0), reverse=True)[:MAX_BLAST_RADIUS]

        # Load all resources for blast radius calculation
        all_resources = []
        try:
            with neo4j_drv.session() as neo4j_session:
                result = neo4j_session.run(
                    """
                    MATCH (r:Resource {scan_job_id: $sjid})
                    RETURN r.node_id AS node_id, r.node_type AS node_type,
                           r.metadata_json AS metadata_json, r.public AS public
                    """,
                    sjid=scan_job_id,
                )
                all_resources = [dict(r) for r in result]
        except Exception as e:
            log.warning("ai_task.resource_load_error", error=str(e))

        for path in blast_radius_paths:
            try:
                nodes_list = json.loads(path["path_nodes"]) if isinstance(path["path_nodes"], str) else path["path_nodes"]
                edges_list = json.loads(path["path_edges"]) if isinstance(path["path_edges"], str) else path["path_edges"]

                blast_radius_data = ai_engine.analyze_blast_radius(
                    path_string=path["path_string"],
                    path_nodes=nodes_list,
                    path_edges=edges_list,
                    all_resources=all_resources,
                )

                _update_path_blast_radius(db, path["id"], blast_radius_data)
                _update_neo4j_blast_radius(neo4j_drv, scan_job_id, path["path_string"], blast_radius_data)
                log.info("ai_task.blast_radius_analyzed", path=path["path_string"][:50])
                time.sleep(INTER_CALL_DELAY)

            except Exception as e:
                log.warning("ai_task.blast_radius_error", path=path.get("path_string"), error=str(e))

        # 4 — Annotate top 3 nodes (with delay between each)
        results["nodes_annotated"] = _annotate_high_risk_nodes(
            ai_engine, neo4j_drv, scan_job_id
        )
        log.info("ai_task.nodes_annotated", count=results["nodes_annotated"])
        time.sleep(INTER_CALL_DELAY)

        # 5 — Load scan metadata
        scan_row = _load_scan_job(db, scan_job_id)

        # 6 — Executive summary (1 API call)
        exec_summary = {}
        if scan_row:
            exec_summary = ai_engine.generate_executive_summary(
                account_id=scan_row.get("aws_account_id") or "unknown",
                region=scan_row.get("aws_region", "us-east-1"),
                resource_count=int(scan_row.get("resource_count") or 0),
                attack_path_count=int(scan_row.get("attack_path_count") or 0),
                critical_count=int(scan_row.get("critical_path_count") or 0),
                overall_risk_score=float(scan_row.get("overall_risk_score") or 0.0),
                top_paths=[
                    {"path_string": p["path_string"],
                     "risk_score": p["risk_score"],
                     "severity": p["severity"]}
                    for p in paths[:3]
                ],
            )
        time.sleep(INTER_CALL_DELAY)

        # 7 — Remediation roadmap (1 API call)
        remediation = ai_engine.generate_remediation_roadmap(
            scan_summary={
                "account_id":        scan_row.get("aws_account_id") if scan_row else "unknown",
                "region":            scan_row.get("aws_region") if scan_row else "unknown",
                "resource_count":    scan_row.get("resource_count") if scan_row else 0,
                "attack_path_count": scan_row.get("attack_path_count") if scan_row else 0,
                "critical_count":    scan_row.get("critical_path_count") if scan_row else 0,
            },
            top_paths=[
                {"path_string": p["path_string"],
                 "risk_score": p["risk_score"],
                 "severity": p["severity"]}
                for p in paths[:5]
            ],
        )

        # 8 — Save report
        _save_report(db, scan_job_id, {
            "executive_summary":   exec_summary,
            "priority_ranking":    priority_result.get("priority_ranking", []),
            "remediation_roadmap": remediation,
        })

        results["executive_summary_headline"] = exec_summary.get("headline_risk", "")
        results["quick_wins"] = priority_result.get("top_quick_wins", [])

        log.info("ai_task.complete",
                 **{k: v for k, v in results.items() if k != "scan_job_id"})
        return results

    except Exception as e:
        log.error("ai_task.error", scan_job_id=scan_job_id, error=str(e), exc_info=True)
        raise
    finally:
        db.close()
        neo4j_drv.close()
