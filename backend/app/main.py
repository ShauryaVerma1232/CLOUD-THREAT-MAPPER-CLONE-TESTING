"""
Threat Mapper — FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.database import init_neo4j, close_neo4j
from app.core.logging import setup_logging
from app.api.routes import health

# ── Logging must be set up before anything else ────────────────────────────────
setup_logging()
log = structlog.get_logger()
settings = get_settings()


# ── Application lifespan ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle hooks."""
    # Startup
    log.info(
        "app.starting",
        name=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
    )
    await init_neo4j()
    log.info("app.ready")

    yield  # Application runs here

    # Shutdown
    log.info("app.shutting_down")
    await close_neo4j()
    log.info("app.stopped")


# ── FastAPI instance ──────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cloud Infrastructure Threat Surface Mapper — API",
    docs_url="/docs" if settings.debug else None,    # Disable Swagger in prod
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# In dev: allow the local frontend dev server
# In prod: lock down to specific origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"] if settings.debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router)

# ── Global exception handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    log.error("unhandled_exception", path=request.url.path, error=str(exc), exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Threat Mapper API",
    version="0.1.0",
    description="Cloud Infrastructure Threat Surface Mapper"
)

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Threat Mapper backend running"}

@app.get("/health")
async def health():
    return {"status": "ok"}
