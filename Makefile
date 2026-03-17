# ─────────────────────────────────────────────────────────────────────────────
# Threat Mapper — Makefile
# Usage: make <target>
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help up down restart logs shell-backend shell-worker migrate \
        test lint clean reset status

# Default target
help:
	@echo ""
	@echo "  Threat Mapper — Available Commands"
	@echo "  ─────────────────────────────────────────"
	@echo "  make setup       → First-time setup (copy .env, create dirs)"
	@echo "  make up          → Start all services"
	@echo "  make down        → Stop all services"
	@echo "  make restart     → Restart all services"
	@echo "  make logs        → Tail all logs"
	@echo "  make logs-back   → Tail backend logs only"
	@echo "  make logs-worker → Tail worker logs only"
	@echo "  make migrate     → Run Alembic DB migrations"
	@echo "  make shell-back  → Open shell in backend container"
	@echo "  make shell-worker→ Open shell in worker container"
	@echo "  make test        → Run backend test suite"
	@echo "  make lint        → Run ruff linter"
	@echo "  make status      → Show container health status"
	@echo "  make reset       → ⚠️  Wipe all volumes and restart fresh"
	@echo ""

# ── First-time setup ──────────────────────────────────────────────────────────
setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅  Created .env from .env.example — fill in your passwords before running 'make up'"; \
	else \
		echo "ℹ️   .env already exists, skipping copy"; \
	fi
	@mkdir -p backend/artifacts backend/reports worker/artifacts worker/terraform_state
	@echo "✅  Artifact directories created"

# ── Service lifecycle ─────────────────────────────────────────────────────────
up:
	docker compose up -d --build
	@echo ""
	@echo "  ✅  Services starting up:"
	@echo "     Frontend  → http://localhost:3000"
	@echo "     Backend   → http://localhost:8000"
	@echo "     API Docs  → http://localhost:8000/docs"
	@echo "     Neo4j     → http://localhost:7474"
	@echo ""

down:
	docker compose down

restart:
	docker compose down && docker compose up -d --build

# ── Logs ──────────────────────────────────────────────────────────────────────
logs:
	docker compose logs -f

logs-back:
	docker compose logs -f backend

logs-worker:
	docker compose logs -f worker

# ── Database ──────────────────────────────────────────────────────────────────
migrate:
	docker compose exec backend alembic upgrade head
	@echo "✅  Migrations applied"

migrate-create:
	@read -p "Migration name: " name; \
	docker compose exec backend alembic revision --autogenerate -m "$$name"

# ── Shells ────────────────────────────────────────────────────────────────────
shell-back:
	docker compose exec backend bash

shell-worker:
	docker compose exec worker bash

shell-db:
	docker compose exec postgres psql -U threatmapper -d threatmapper

# ── Testing & Linting ─────────────────────────────────────────────────────────
test:
	docker compose exec backend pytest tests/ -v

lint:
	docker compose exec backend ruff check app/

# ── Status ────────────────────────────────────────────────────────────────────
status:
	docker compose ps

# ── Reset (destructive!) ──────────────────────────────────────────────────────
reset:
	@echo "⚠️  This will delete ALL local data (postgres, neo4j, redis volumes)."
	@read -p "Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		docker compose down -v; \
		docker compose up -d --build; \
		echo "✅  Full reset complete"; \
	else \
		echo "Cancelled."; \
	fi
