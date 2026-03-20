"""
Graph API Routes

POST /graph/build/{scan_job_id}   → trigger graph build task
GET  /graph/{scan_job_id}         → get full graph for Cytoscape.js
GET  /graph/{scan_job_id}/paths   → get attack paths list
GET  /graph/{scan_job_id}/paths/{path_id} → get single path with node highlight list
"""
import os
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from neo4j import AsyncGraphDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, get_neo4j_session
from app.schemas.graph_schemas import (
    GraphResponse, GraphBuildRequest, GraphBuildResponse,
    AttackPathListResponse, AttackPathResponse,
)
from app.services.scan_service import get_scan_job

log = structlog.get_logger()
router = APIRouter(prefix="/graph", tags=["graph"])


@router.post("/build/{scan_job_id}", response_model=GraphBuildResponse)
async def trigger_graph_build(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Dispatch the graph build task for a completed scan.
    The scan must have status='complete' and a saved artifact.
    """
    job = await get_scan_job(db, scan_job_id)
    if not job:
        raise HTTPException(404, "Scan job not found")
    if job.status != "complete":
        raise HTTPException(400, f"Scan is not complete (status: {job.status})")
    if not job.artifact_path:
        raise HTTPException(400, "No artifact found for this scan")

    try:
        from celery import Celery
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        app = Celery(broker=redis_url)
        app.send_task(
            "app.tasks.graph_tasks.build_attack_graph",
            kwargs={
                "scan_job_id":   str(scan_job_id),
                "artifact_path": job.artifact_path,
            },
            queue="graph",
        )
    except Exception as e:
        raise HTTPException(503, f"Failed to dispatch graph task: {e}")

    return GraphBuildResponse(
        scan_job_id=str(scan_job_id),
        status="dispatched",
        message="Graph build task queued. Poll GET /graph/{scan_job_id} for data.",
    )


@router.get("/{scan_job_id}", response_model=GraphResponse)
async def get_graph(
    scan_job_id: uuid.UUID,
    neo4j: AsyncSession = Depends(get_neo4j_session),
):
    """Return the full graph in Cytoscape.js elements format."""
    from app.graph.neo4j_writer import get_graph_for_scan
    scan_id_str = str(scan_job_id)

    data = await get_graph_for_scan(neo4j, scan_id_str)

    if not data["nodes"]:
        raise HTTPException(404, "No graph data found for this scan. "
                                 "Run POST /graph/build/{id} first.")

    return GraphResponse(
        scan_job_id=scan_id_str,
        nodes=data["nodes"],
        edges=data["edges"],
        node_count=len(data["nodes"]),
        edge_count=len(data["edges"]),
    )


@router.get("/{scan_job_id}/paths", response_model=AttackPathListResponse)
async def get_attack_paths(
    scan_job_id: uuid.UUID,
    neo4j: AsyncSession = Depends(get_neo4j_session),
):
    """Return all scored attack paths for a scan, ordered by risk score."""
    from app.graph.neo4j_writer import get_attack_paths_for_scan
    scan_id_str = str(scan_job_id)

    paths = await get_attack_paths_for_scan(neo4j, scan_id_str)
    items = [AttackPathResponse(**p) for p in paths]

    return AttackPathListResponse(
        scan_job_id=scan_id_str,
        items=items,
        total=len(items),
        critical_count=sum(1 for p in items if p.severity == "critical"),
        high_count=sum(1 for p in items if p.severity == "high"),
    )


@router.get("/{scan_job_id}/paths/{path_id}")
async def get_attack_path_detail(
    scan_job_id: uuid.UUID,
    path_id: str,
    neo4j: AsyncSession = Depends(get_neo4j_session),
):
    """Get a single attack path with the list of node IDs for frontend highlighting."""
    result = await neo4j.run(
        """
        MATCH (p:AttackPath {path_id: $path_id, scan_job_id: $scan_job_id})
        OPTIONAL MATCH (p)-[c:CONTAINS]->(r:Resource)
        RETURN p, collect({pos: c.position, node_id: r.node_id, label: r.label}) AS nodes
        """,
        path_id=path_id,
        scan_job_id=str(scan_job_id),
    )
    record = await result.single()
    if not record:
        raise HTTPException(404, "Attack path not found")

    path_node = dict(record["p"])
    path_nodes_sorted = sorted(record["nodes"], key=lambda x: x["pos"])

    return {
        **path_node,
        "node_sequence": [n["node_id"] for n in path_nodes_sorted],
        "node_labels":   [n["label"] for n in path_nodes_sorted],
    }
