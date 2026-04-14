"""Threat Mapper — FastAPI Application Entry Point (Day 4)"""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.database import init_neo4j, close_neo4j
from app.core.logging import setup_logging
from app.api.routes import health, scans, graph, ai

setup_logging()
log = structlog.get_logger()
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("app.starting", name=settings.app_name, version=settings.app_version)
    await init_neo4j()
    log.info("app.ready")
    yield
    await close_neo4j()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cloud Infrastructure Threat Surface Mapper — API",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:13000"] if settings.debug else [],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(scans.router)
app.include_router(graph.router)
app.include_router(ai.router)

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

@app.get("/", include_in_schema=False)
async def root():
    return {"service": settings.app_name, "version": settings.app_version, "docs": "/docs"}
