"""
Database connection management.
- PostgreSQL via async SQLAlchemy (asyncpg driver)
- Neo4j via official Python driver
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from neo4j import AsyncGraphDatabase, AsyncDriver
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# ── PostgreSQL ────────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

AsyncSessionFactory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async database session."""
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Neo4j ─────────────────────────────────────────────────────────────────────
_neo4j_driver: AsyncDriver | None = None


def get_neo4j_driver() -> AsyncDriver:
    """Return the shared Neo4j async driver instance."""
    if _neo4j_driver is None:
        raise RuntimeError("Neo4j driver has not been initialized. Call init_neo4j() first.")
    return _neo4j_driver


async def init_neo4j() -> None:
    """Initialize the Neo4j async driver. Called at application startup."""
    global _neo4j_driver
    _neo4j_driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    # Verify connectivity
    await _neo4j_driver.verify_connectivity()
    log.info("neo4j.connected", uri=settings.neo4j_uri)


async def close_neo4j() -> None:
    """Close the Neo4j driver. Called at application shutdown."""
    global _neo4j_driver
    if _neo4j_driver:
        await _neo4j_driver.close()
        _neo4j_driver = None
        log.info("neo4j.disconnected")


@asynccontextmanager
async def neo4j_session():
    """Context manager for a Neo4j async session."""
    driver = get_neo4j_driver()
    async with driver.session() as session:
        yield session


async def get_neo4j_session():
    """FastAPI dependency: yields a Neo4j session."""
    async with neo4j_session() as session:
        yield session
