"""
Shared synchronous DB utilities for Celery tasks.

Key fix: SQLAlchemy text() uses :param syntax for named parameters.
PostgreSQL's ::type cast syntax also contains colons, which confuses
the psycopg2 driver.

Rules followed here:
  - NEVER use ::type casts inside text() parameter expressions
  - Pass UUIDs as plain strings — PostgreSQL implicitly casts varchar → uuid
  - Pass JSON as pre-serialized strings with explicit type_ in execute_values
  - Use psycopg2 Json() wrapper for jsonb columns
"""
import json
import os
from datetime import datetime, timezone

import structlog
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

log = structlog.get_logger()

_engine = None


def get_sync_engine():
    """Return a cached synchronous SQLAlchemy engine."""
    global _engine
    if _engine is None:
        db_url = os.environ.get("DATABASE_URL", "").replace(
            "postgresql+asyncpg://", "postgresql+psycopg2://"
        )
        _engine = create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
    return _engine


def get_sync_session() -> Session:
    """Return a new synchronous SQLAlchemy session."""
    Session = sessionmaker(bind=get_sync_engine())
    return Session()


def update_scan_job(scan_job_id: str, updates: dict) -> None:
    """
    Update scan_jobs row.

    FIX: Do not use ::uuid cast in WHERE clause.
    Pass scan_job_id as a plain string — PostgreSQL casts implicitly.
    Use named :params only for values, never for type annotations.
    """
    session = get_sync_session()
    try:
        set_clauses = ", ".join(f"{k} = :{k}" for k in updates)
        # No ::uuid — plain string comparison, Postgres handles the cast
        sql = f"UPDATE scan_jobs SET {set_clauses} WHERE id = :scan_job_id"
        session.execute(text(sql), {"scan_job_id": scan_job_id, **updates})
        session.commit()
        log.debug("db.scan_job_updated", scan_job_id=scan_job_id, fields=list(updates.keys()))
    except Exception as e:
        log.error("db.update_scan_job_error", error=str(e), scan_job_id=scan_job_id)
        session.rollback()
        raise
    finally:
        session.close()


def insert_attack_paths(scan_job_id: str, paths: list) -> int:
    """
    Bulk-insert attack paths into PostgreSQL.

    FIX: Use direct psycopg2 execute_values for jsonb columns,
    bypassing SQLAlchemy text() parameter substitution entirely.
    This avoids the ::jsonb cast issue.
    """
    if not paths:
        return 0

    import uuid as uuid_mod
    from psycopg2.extras import execute_values, Json

    engine = get_sync_engine()
    inserted = 0

    with engine.connect() as conn:
        raw_conn = conn.connection
        cursor = raw_conn.cursor()

        rows = []
        for ap in paths:
            path_id = str(uuid_mod.uuid4())

            # Convert path_nodes list → JSON string
            if isinstance(ap.path_nodes, list):
                nodes_json = json.dumps(ap.path_nodes)
            else:
                nodes_json = str(ap.path_nodes)

            # Convert path_edges → safe JSON
            safe_edges = []
            for e in (ap.path_edges if isinstance(ap.path_edges, list) else []):
                safe_edges.append({
                    k: v for k, v in e.items()
                    if isinstance(v, (str, int, float, bool, type(None)))
                })
            edges_json = json.dumps(safe_edges)

            rows.append((
                path_id,
                scan_job_id,
                Json(json.loads(nodes_json)),   # jsonb
                Json(safe_edges),               # jsonb
                ap.path_string,
                float(ap.reachability_score),
                float(ap.impact_score),
                float(ap.exploitability_score),
                float(ap.exposure_score),
                float(ap.risk_score),
                ap.severity,
                False,
                datetime.now(timezone.utc),
            ))

        try:
            execute_values(
                cursor,
                """
                INSERT INTO attack_paths (
                    id, scan_job_id, path_nodes, path_edges, path_string,
                    reachability_score, impact_score, exploitability_score,
                    exposure_score, risk_score, severity, validated, created_at
                ) VALUES %s
                """,
                rows,
                template="""(
                    %s::uuid, %s::uuid,
                    %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s::severity_level, %s, %s
                )""",
            )
            raw_conn.commit()
            inserted = len(rows)
            log.info("db.attack_paths_inserted", count=inserted, scan_job_id=scan_job_id)
        except Exception as e:
            raw_conn.rollback()
            log.error("db.attack_paths_insert_error", error=str(e))
            raise
        finally:
            cursor.close()

    return inserted
