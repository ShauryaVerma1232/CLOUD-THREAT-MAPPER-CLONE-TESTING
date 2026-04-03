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

MAX_PATHS_TO_EXPLAIN  = 5    # reduced from 10
MAX_NODES_TO_ANNOTATE = 3    # reduced from 20 — annotate top 3 most risky only
INTER_CALL_DELAY      = 5.0  # seconds between API calls — stays under 15 RPM


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
                p.ai_attack_narrative  = $narrative,
                p.ai_business_impact   = $impact,
                p.ai_likelihood        = $likelihood,
                p.ai_detection_signals = $detection
            """,
            sjid=scan_job_id,
            ps=path_string,
            explanation=annotation.get("explanation", ""),
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
