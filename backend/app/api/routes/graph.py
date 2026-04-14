"""
Graph API Routes

POST /graph/build/{scan_job_id}   → trigger graph build task
GET  /graph/{scan_job_id}         → get full graph for Cytoscape.js
GET  /graph/{scan_job_id}/paths   → get attack paths list
GET  /graph/{scan_job_id}/paths/{path_id} → get single path with node highlight list
POST /graph/{scan_job_id}/blast-radius/calculate → trigger blast radius calculation
GET  /graph/{scan_job_id}/blast-radius/{node_id} → get blast radius for a node
GET  /graph/{scan_job_id}/blast-radius/public    → analyze all public resources
"""
import os
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from neo4j import AsyncGraphDatabase
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db, get_neo4j_session
from app.models.models import BlastRadius
from app.schemas.graph_schemas import (
    GraphResponse, GraphBuildRequest, GraphBuildResponse,
    AttackPathListResponse, AttackPathResponse,
    BlastRadiusRequest, BlastRadiusResponse, BlastRadiusTriggerResponse,
    PublicResourcesBlastRadiusResponse,
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


# ── Blast Radius API Routes ────────────────────────────────────────────────────


@router.post("/{scan_job_id}/blast-radius/calculate", response_model=BlastRadiusTriggerResponse)
async def trigger_blast_radius_calculation(
    scan_job_id: uuid.UUID,
    request: BlastRadiusRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger blast radius calculation for a specific compromised node.

    The blast radius shows what resources would be at risk if the specified
    node is compromised, including direct reach (1 hop), secondary reach (2 hops),
    and critical resources that could be accessed.
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
            "app.tasks.blast_radius_tasks.calculate_blast_radius",
            kwargs={
                "scan_job_id": str(scan_job_id),
                "compromised_node_id": request.compromised_node_id,
                "artifact_path": job.artifact_path,
                "max_hops": request.max_hops,
                "include_attack_paths": request.include_attack_paths,
            },
            queue="graph",
        )
    except Exception as e:
        raise HTTPException(503, f"Failed to dispatch blast radius task: {e}")

    return BlastRadiusTriggerResponse(
        scan_job_id=str(scan_job_id),
        compromised_node_id=request.compromised_node_id,
        status="dispatched",
        message="Blast radius calculation queued. Poll GET /graph/{scan_job_id}/blast-radius/{node_id} for results.",
    )


@router.get("/{scan_job_id}/blast-radius/{node_id:path}", response_model=BlastRadiusResponse)
async def get_blast_radius(
    scan_job_id: uuid.UUID,
    node_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get blast radius analysis results for a compromised node.

    Returns detailed information about what resources would be at risk
    if the specified node is compromised.
    """
    scan_id_str = str(scan_job_id)

    # Direct query without using the session from Depends
    from app.core.database import AsyncSessionFactory
    async with AsyncSessionFactory() as session:
        result = await session.execute(
            select(BlastRadius).where(
                BlastRadius.scan_job_id == scan_id_str,
                BlastRadius.compromised_node_id == node_id,
            )
        )
        br = result.scalar_one_or_none()

    if not br:
        raise HTTPException(
            404,
            f"No blast radius result found for node '{node_id}' in scan '{scan_id_str}'. "
            "Trigger calculation with POST /graph/{scan_job_id}/blast-radius/calculate first.",
        )

    return BlastRadiusResponse(
        result_id=str(br.id),
        scan_job_id=scan_id_str,
        compromised_node_id=br.compromised_node_id,
        compromised_node_type=br.compromised_node_type or "",
        compromised_node_label=br.compromised_node_label or "",
        direct_reach_count=br.direct_reach_count,
        secondary_reach_count=br.secondary_reach_count,
        total_reachable_count=br.total_reachable_count,
        critical_count=br.critical_count,
        direct_reach=br.direct_reach or [],
        secondary_reach=br.secondary_reach or [],
        all_reachable=br.all_reachable or [],
        critical_at_risk=br.critical_at_risk or [],
        by_hop_distance=br.by_hop_distance or {},
        blast_radius_severity=br.blast_radius_severity or "low",
        blast_radius_score=br.blast_radius_score or 0.0,
        attack_paths_from_here=br.attack_paths_from_here or [],
    )


@router.get("/{scan_job_id}/blast-radius/public", response_model=PublicResourcesBlastRadiusResponse)
async def analyze_public_resources_blast_radius(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyze blast radius for all publicly-exposed resources.

    This identifies which public resources have the largest blast radius
    and should be prioritized for hardening. Returns a list of public
    resources sorted by blast radius score (highest first).
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
        task_result = app.send_task(
            "app.tasks.blast_radius_tasks.analyze_all_public_resources_blast_radius",
            kwargs={
                "scan_job_id": str(scan_job_id),
                "artifact_path": job.artifact_path,
                "max_hops": 4,
            },
            queue="graph",
        )

        # For now, return a pending response since this is async
        # In a real implementation, you'd poll for results or use websockets
        return {
            "scan_job_id": str(scan_job_id),
            "status": "analyzing",
            "message": "Public resources blast radius analysis queued. Results will be available once calculation completes.",
            "task_id": task_result.id if hasattr(task_result, "id") else None,
        }

    except Exception as e:
        raise HTTPException(503, f"Failed to dispatch blast radius analysis task: {e}")
