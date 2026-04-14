# Threat Mapper

**Cloud Infrastructure Threat Surface Mapper**
with Autonomous Sandbox Cloning & Automated Security Testing

> Local-first security platform — all orchestration runs on your machine.
> Cloud APIs accessed read-only. Sandbox tests run in isolated environments only.

---

## Prerequisites (WSL2 / Windows 11)

Everything runs inside WSL2. Install these **inside your WSL2 Ubuntu terminal**.

### 1. Docker Desktop (Windows side)
1. Download from https://www.docker.com/products/docker-desktop/
2. Install and open Docker Desktop
3. Go to **Settings → Resources → WSL Integration**
4. Enable integration for your WSL2 distro (Ubuntu)
5. Verify inside WSL2:
   ```bash
   docker --version       # Docker Engine 24+
   docker compose version # Docker Compose v2+
   ```

### 2. Make (WSL2 side)
```bash
sudo apt update && sudo apt install -y make
```

### 3. Git (WSL2 side)
```bash
sudo apt install -y git
git --version
```

---


### Step 1 — Clone / create the project
```bash
# If you already have the files:
cd threat-mapper

# Or initialize git:
git init
git add .
git commit -m "Day 1: Foundation scaffold"
```

### Step 2 — Create your .env file
```bash
make setup
```

This copies `.env.example` to `.env`. Now **open `.env` and set real passwords**:

```bash
nano .env   # or code .env if you have VS Code + WSL extension
```

Change these three values (anything is fine for local dev):
```
POSTGRES_PASSWORD=mydevpassword
NEO4J_PASSWORD=myneo4jpassword
REDIS_PASSWORD=myredispassword
SECRET_KEY=at_least_32_random_characters_here
```

> Leave AWS, AI, and other settings as-is for now — we'll configure them on their respective days.

### Step 3 — Start all services
```bash
make up
```

First run downloads Docker images and builds containers (~5–10 minutes).
Subsequent starts take ~20 seconds.

### Step 4 — Run database migrations
```bash
make migrate
```

### Step 5 — Verify everything is working

Open these in your browser:

| URL | What you should see |
|-----|-------------------|
| http://localhost:13000 | Threat Mapper dashboard (React app) |
| http://localhost:18000/docs | FastAPI Swagger UI |
| http://localhost:18000/health | `{"status": "ok"}` |
| http://localhost:18000/health/ready | All checks green |
| http://localhost:17474 | Neo4j browser (login: neo4j / your password) |

---

## Daily Commands

```bash
make up           # Start all services
make down         # Stop all services
make logs         # Tail all logs
make logs-back    # Backend logs only
make logs-worker  # Worker logs only
make status       # Container health overview
make migrate      # Apply any new DB migrations
make shell-back   # Bash shell in backend container
make shell-db     # psql shell in postgres container
make reset        # ⚠️ Wipe everything and start fresh
```

---

## Project Structure

```
threat-mapper/
│
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── main.py           # FastAPI entry point
│   │   ├── core/
│   │   │   ├── config.py     # Pydantic settings
│   │   │   ├── database.py   # PostgreSQL + Neo4j connections
│   │   │   └── logging.py    # Structured logging
│   │   ├── api/routes/
│   │   │   └── health.py     # Health check endpoints
│   │   └── models/
│   │       └── models.py     # SQLAlchemy ORM models
│   ├── alembic/              # DB migrations
│   ├── requirements.txt
│   └── Dockerfile
│
├── worker/                   # Celery task worker
│   ├── app/
│   │   ├── celery_app.py     # Celery configuration
│   │   └── tasks/
│   │       └── scan_tasks.py # Scan task stubs (Day 2)
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                 # React + Vite + Tailwind
│   ├── src/
│   │   ├── main.tsx          # Entry point
│   │   ├── App.tsx           # Router
│   │   ├── components/
│   │   │   └── Layout.tsx    # Sidebar + shell
│   │   ├── pages/            # One file per route
│   │   └── api/
│   │       └── client.ts     # Axios API client
│   └── Dockerfile
│
├── infra/terraform/          # Sandbox IaC templates (Day 5)
├── docker-compose.yml        # All 8 services
├── Makefile                  # Dev commands
├── .env.example              # Template — copy to .env
└── .gitignore
```

---

## Architecture Overview

```
Browser (localhost:3000)
        │
        ▼
   React Frontend
        │  (HTTP via Vite proxy)
        ▼
   FastAPI Backend  (:8000)
        │
   ┌────┴─────────────────────┐
   │                          │
PostgreSQL (:5432)       Neo4j (:7474)
   │                          │
   └────┬─────────────────────┘
        │
   Celery Worker  ←─── Redis (:6379)
        │
   (Day 2+: boto3 → AWS APIs)
```

---

## Build Roadmap

| Day | Phase | Feature |
|-----|-------|---------|
| **1** ✅ | Foundation | Docker stack, FastAPI, PostgreSQL, Neo4j, React shell |
| 2 | Scanner | AWS boto3 multi-service infrastructure scanner |
| 3 | Graph | NetworkX graph builder + Neo4j + Cytoscape.js visualization |
| 4 | AI | LLM reasoning layer + attack path explanation |
| 5 | Clone | Sandbox clone generator + Terraform deployment |
| 6 | Tests | Automated security test suite |
| 7 | Reports | AI-generated security report generation |
| 8 | Harden | Audit logging, rate limiting, performance |

---

## Security Rules

- **Production AWS credentials** are mounted read-only and used for scanning only
- **No production data** is ever copied to sandbox or local storage
- **All security tests** run against sandbox environments exclusively
- **Sandbox resources** are auto-destroyed after every test run
- **`.env` is gitignored** — never commit secrets
