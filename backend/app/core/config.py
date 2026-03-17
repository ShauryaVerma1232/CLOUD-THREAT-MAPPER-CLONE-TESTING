"""
Application configuration — loaded from environment variables / .env file.
All settings are validated at startup by Pydantic.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ────────────────────────────────────────────────────────────────────
    app_name: str = "Threat Mapper"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "info"
    secret_key: str

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str
    # Sync URL for Alembic (replaces asyncpg with psycopg2)
    @property
    def sync_database_url(self) -> str:
        return self.database_url.replace(
            "postgresql+asyncpg://", "postgresql+psycopg2://"
        )

    # ── Neo4j ──────────────────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str

    # ── Redis ──────────────────────────────────────────────────────────────────
    redis_url: str

    # ── AI Provider ────────────────────────────────────────────────────────────
    ai_provider: str = "none"  # none | anthropic | openai | ollama
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    ollama_base_url: str = "http://host.docker.internal:11434"

    # ── AWS ────────────────────────────────────────────────────────────────────
    aws_scan_profile: str = "default"
    aws_sandbox_profile: str = "sandbox"

    # ── Celery ─────────────────────────────────────────────────────────────────
    celery_worker_concurrency: int = 4

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"debug", "info", "warning", "error", "critical"}
        v = v.lower()
        if v not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v


@lru_cache
def get_settings() -> Settings:
    """Cached settings — called once at startup."""
    return Settings()
