"""
AI API Routes

POST /ai/analyze/{scan_job_id}   → manually trigger AI analysis
GET  /ai/status/{scan_job_id}    → check if AI analysis is done
GET  /ai/paths/{scan_job_id}     → AI-annotated attack paths
GET  /ai/summary/{scan_job_id}   → executive summary + roadmap
GET  /ai/provider                → active AI provider info
"""
import json
import os
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.database import get_db
from app.services.scan_service import get_scan_job

log = structlog.get_logger()
router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/provider")
async def get_ai_provider():
    """Return which AI provider is currently configured."""
    provider = os.environ.get("AI_PROVIDER", "none")
    has_key = False
    if provider == "groq":
        has_key = bool(os.environ.get("GROQ_API_KEY"))
    elif provider == "gemini":
        has_key = bool(os.environ.get("GEMINI_API_KEY"))
    elif provider == "anthropic":
        has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    elif provider == "openai":
        has_key = bool(os.environ.get("OPENAI_API_KEY"))
    elif provider == "ollama":
        has_key = True

    return {
        "provider":   provider,
        "configured": has_key or provider in ("none", "ollama"),
        "ready":      provider != "none" and (has_key or provider == "ollama"),
        "model": {
            "groq":      os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"),
            "gemini":    os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
            "anthropic": "claude-sonnet-4-20250514",
            "openai":    "gpt-4o",
            "ollama":    os.environ.get("OLLAMA_MODEL", "llama3"),
            "none":      "stub — set AI_PROVIDER=groq + GROQ_API_KEY in .env",
        }.get(provider, "unknown"),
    }


@router.post("/analyze/{scan_job_id}")
async def trigger_ai_analysis(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger AI analysis (normally auto-triggered after graph build)."""
    job = await get_scan_job(db, scan_job_id)
    if not job:
        raise HTTPException(404, "Scan job not found")
    if job.status != "complete":
        raise HTTPException(400, f"Scan not complete (status: {job.status})")

    try:
        from celery import Celery
        app = Celery(broker=os.environ.get("REDIS_URL", "redis://redis:6379/0"))
        app.send_task(
            "app.tasks.ai_tasks.run_ai_analysis",
            kwargs={"scan_job_id": str(scan_job_id)},
            queue="ai",
        )
    except Exception as e:
        raise HTTPException(503, f"Failed to dispatch AI task: {e}")

    return {
        "scan_job_id": str(scan_job_id),
        "status":      "dispatched",
        "message":     "AI analysis queued. Poll GET /ai/status/{id} for completion.",
    }


@router.get("/status/{scan_job_id}")
async def get_ai_status(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Check whether AI analysis results are available."""
    # FIX: no ::uuid cast — pass as plain string
    sid = str(scan_job_id)

    row = (await db.execute(
        text("""
            SELECT
                COUNT(*) FILTER (WHERE ai_explanation IS NOT NULL AND ai_explanation != '') AS annotated_paths,
                COUNT(*) AS total_paths
            FROM attack_paths
            WHERE scan_job_id::text = :sid
        """),
        {"sid": sid},
    )).fetchone()

    has_report = (await db.execute(
        text("SELECT id FROM reports WHERE scan_job_id::text = :sid LIMIT 1"),
        {"sid": sid},
    )).fetchone() is not None

    annotated = row.annotated_paths if row else 0
    total     = row.total_paths if row else 0

    return {
        "scan_job_id":     sid,
        "ai_available":    annotated > 0 or has_report,
        "annotated_paths": annotated,
        "total_paths":     total,
        "has_report":      has_report,
        "ai_provider":     os.environ.get("AI_PROVIDER", "none"),
    }


@router.get("/paths/{scan_job_id}")
async def get_ai_annotated_paths(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Return attack paths with AI explanations. Returns all paths, annotated or not."""
    sid = str(scan_job_id)

    rows = (await db.execute(
        text("""
            SELECT id::text, path_string, risk_score, severity,
                   ai_explanation, ai_remediation,
                   reachability_score, impact_score,
                   exploitability_score, exposure_score,
                   ai_privilege_escalation::text,
                   ai_escalation_techniques::text,
                   ai_threat_actors::text,
                   ai_mitre_mapping::text,
                   ai_blast_radius::text,
                   ai_compromise_timeline::text
            FROM attack_paths
            WHERE scan_job_id::text = :sid
            ORDER BY risk_score DESC
            LIMIT 50
        """),
        {"sid": sid},
    )).fetchall()

    paths = []
    for row in rows:
        remediation = []
        privilege_escalation = None
        escalation_techniques = []
        threat_actors = []
        mitre_mapping = {}
        blast_radius = None
        compromise_timeline = None

        try:
            remediation = json.loads(row.ai_remediation or "[]")
            privilege_escalation = json.loads(row.ai_privilege_escalation) if row.ai_privilege_escalation else None
            escalation_techniques = json.loads(row.ai_escalation_techniques or "[]")
            threat_actors = json.loads(row.ai_threat_actors or "[]")
            mitre_mapping = json.loads(row.ai_mitre_mapping or "{}")
            blast_radius = json.loads(row.ai_blast_radius) if row.ai_blast_radius else None
            compromise_timeline = json.loads(row.ai_compromise_timeline) if row.ai_compromise_timeline else None
        except Exception:
            pass

        paths.append({
            "id":                   row.id,
            "path_string":          row.path_string,
            "risk_score":           row.risk_score,
            "severity":             row.severity,
            "ai_explanation":       row.ai_explanation or "",
            "ai_remediation_steps": remediation,
            "reachability_score":   row.reachability_score,
            "impact_score":         row.impact_score,
            "exploitability_score": row.exploitability_score,
            "exposure_score":       row.exposure_score,
            "ai_privilege_escalation": privilege_escalation,
            "ai_escalation_techniques": escalation_techniques,
            "ai_threat_actors": threat_actors,
            "ai_mitre_mapping": mitre_mapping,
            "ai_blast_radius": blast_radius,
            "ai_compromise_timeline": compromise_timeline,
        })

    return {"scan_job_id": sid, "items": paths, "total": len(paths)}


@router.get("/summary/{scan_job_id}")
async def get_ai_summary(
    scan_job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Return AI-generated executive summary and remediation roadmap with enriched threat intelligence."""
    sid = str(scan_job_id)

    row = (await db.execute(
        text("""
            SELECT title, executive_summary, findings_json::text, remediation_roadmap::text, created_at
            FROM reports
            WHERE CAST(scan_job_id AS text) = :sid
            ORDER BY created_at DESC
            LIMIT 1
        """),
        {"sid": sid},
    )).fetchone()

    if not row:
        raise HTTPException(
            404,
            "No AI report yet. Run POST /ai/analyze/{id} or wait for auto-analysis."
        )

    findings, roadmap = {}, {}
    try:
        findings = json.loads(row.findings_json or "[]")
        roadmap  = json.loads(row.remediation_roadmap or "{}")
    except Exception:
        pass

    # Fetch enriched AI analysis from attack_paths (threat actors, blast radius, IAM escalation)
    enriched_paths = (await db.execute(
        text("""
            SELECT
                path_string,
                ai_privilege_escalation::text,
                ai_escalation_techniques::text,
                ai_threat_actors::text,
                ai_mitre_mapping::text,
                ai_blast_radius::text,
                ai_compromise_timeline::text
            FROM attack_paths
            WHERE scan_job_id::text = :sid
              AND (ai_threat_actors IS NOT NULL OR ai_blast_radius IS NOT NULL OR ai_privilege_escalation IS NOT NULL)
            ORDER BY risk_score DESC
            LIMIT 10
        """),
        {"sid": sid},
    )).fetchall()

    enriched_analysis = []
    for p in enriched_paths:
        enriched_analysis.append({
            "path_string": p.path_string,
            "privilege_escalation": json.loads(p.ai_privilege_escalation or "null"),
            "escalation_techniques": json.loads(p.ai_escalation_techniques or "[]"),
            "threat_actors": json.loads(p.ai_threat_actors or "[]"),
            "mitre_mapping": json.loads(p.ai_mitre_mapping or "{}"),
            "blast_radius": json.loads(p.ai_blast_radius or "{}"),
            "compromise_timeline": json.loads(p.ai_compromise_timeline or "{}"),
        })

    return {
        "scan_job_id":         sid,
        "title":               row.title,
        "executive_summary":   row.executive_summary or "",
        "priority_ranking":    findings if isinstance(findings, list) else [],
        "remediation_roadmap": roadmap,
        "generated_at":        row.created_at.isoformat() if row.created_at else None,
        "enriched_analysis":   enriched_analysis,
    }
