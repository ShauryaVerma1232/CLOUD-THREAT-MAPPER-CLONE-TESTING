# Claude Code Instructions — Cloud Threat Mapper

This repository contains a **cloud security analysis platform** that scans AWS infrastructure,
builds an attack graph of resources and relationships, and performs AI-assisted security analysis.

The goal of the system is to identify **attack paths, misconfigurations, and privilege escalation risks**
in AWS environments.

Claude should assist with development, debugging, and architecture improvements while respecting
the system design and security constraints described below.

---

# Project Overview

Cloud Threat Mapper performs the following pipeline:

1. **Infrastructure Scan**
   - Uses AWS APIs via boto3
   - Enumerates resources such as:
     - VPCs
     - Subnets
     - Security Groups
     - EC2 instances
     - IAM users
     - IAM roles
     - S3 buckets
     - Lambda functions
     - RDS instances

2. **Infrastructure Model Generation**
   - Converts raw AWS data into a structured JSON model
   - Saves the artifact to `/artifacts/<scan_id>/infrastructure_model.json`

3. **Attack Graph Construction**
   - Builds a directed graph of resources and relationships
   - Example relationships:
     - instance → security group
     - subnet → VPC
     - IAM user → permissions
     - S3 bucket → public access

4. **Attack Path Discovery**
   - Traverses the graph
   - Identifies potential lateral movement paths
   - Finds escalation routes toward sensitive targets

5. **AI Analysis Layer**
   - Uses an LLM to:
     - annotate nodes with security context
     - explain attack paths
     - generate remediation advice
     - produce an executive summary

---

# System Architecture

Backend components:

- **FastAPI** — API server
- **Celery** — asynchronous task queue
- **Redis** — message broker
- **PostgreSQL** — persistent data store
- **Docker Compose** — local orchestration
- **AWS SDK (boto3)** — cloud enumeration
- **LLM Provider** — Gemini / Ollama / OpenAI

Worker pipeline:

```

API Request
↓
Celery Task: run_infrastructure_scan
↓
Artifact JSON
↓
Celery Task: build_attack_graph
↓
Graph nodes + edges stored
↓
Celery Task: run_ai_analysis
↓
AI annotations + remediation report

```

---

# Repository Structure

Example layout:

```

backend/
app/
scanner/
modules/
graph/
ai/
tasks/

docker-compose.yml
.env
artifacts/
CLAUDE.md

```

Important modules:

### scanner/

Responsible for AWS enumeration.

Modules may include:

- vpc_scanner
- subnet_scanner
- ec2_scanner
- iam_scanner
- s3_scanner

### graph/

Responsible for:

- graph construction
- relationship modeling
- attack path search

### ai/

Responsible for:

- LLM provider abstraction
- prompt generation
- risk scoring
- remediation suggestions

### tasks/

Celery background jobs.

Examples:

- `run_infrastructure_scan`
- `build_attack_graph`
- `run_ai_analysis`

---

# AI System Guidelines

AI analysis must follow these rules:

### Minimize API Calls

Do not make one LLM call per node.

Instead:

```

Batch analysis:
nodes + relationships → single prompt

````

### Deterministic Output

AI responses should return structured JSON whenever possible.

Example format:

```json
{
 "node_annotations": [],
 "attack_path_explanations": [],
 "remediation_steps": [],
 "risk_score": 0
}
````

### Security Focus

AI responses should prioritize:

* privilege escalation
* lateral movement
* exposed resources
* overly permissive IAM policies
* public cloud resources

---

# Coding Guidelines

Follow these standards:

### Python Style

* Python 3.11+
* type hints required
* prefer async where possible
* structured logging via `structlog`

Example:

```python
log.info("scan.started", region=region, profile=profile)
```

---

### Error Handling

Never allow worker tasks to crash silently.

Use structured errors:

```
ScannerError
GraphError
AIAnalysisError
```

---

### Celery Tasks

Tasks must:

1. Update scan status in database
2. Log start and completion
3. Handle retries

---

### Logging

Use structured logs.

Example:

```
scan.module_start
scan.module_done
graph_builder.start
graph_builder.done
ai_task.start
ai_task.complete
```

---

# Security Constraints

Claude must follow these rules:

* Never embed API keys or credentials in code
* Never commit `.env`
* Never expose AWS credentials
* Assume the system will run in real environments

---

# Local Development

Start system:

```
docker compose up
```

Run scan:

```
POST /scans
```

Check result:

```
GET /scans/{scan_id}
```

Artifacts are saved in:

```
/artifacts/<scan_id>/
```

---

# Testing Environments

The system will be tested against intentionally vulnerable AWS environments such as:

* CloudGoat
* vulnerable cloud labs
* misconfigured AWS sandbox accounts

Claude should help analyze findings from these environments.

---

# Claude Responsibilities

Claude should help with:

* debugging scan modules
* improving graph algorithms
* improving AI prompts
* optimizing LLM usage
* implementing security detection logic
* writing unit tests

Claude should **not change the architecture unless asked**.

---

# Desired Future Improvements

Potential enhancements include:

* IAM privilege escalation detection
* graph-based risk scoring
* cloud attack simulation
* automated remediation suggestions
* multi-cloud support (Azure/GCP)
* security report generation

---

# Prompt Engineering Notes

When generating prompts for the LLM:

Include:

* resource metadata
* relationships
* possible attack vectors

Avoid:

* overly verbose prompts
* unnecessary tokens
* repeated node descriptions

---

# Example AI Prompt Template

```

You are a cloud security analyst.

Analyze the following AWS infrastructure graph.

Identify:

1. Misconfigurations
2. Privilege escalation paths
3. Lateral movement opportunities
4. Public exposure risks

Graph data:
{graph\_json}

Return structured JSON with:

- node\_annotations
- attack\_path\_explanations
- remediation\_recommendations
- risk\_score

```

---

# End of Instructions

---

# Persistent Memory System

This repository uses a persistent memory system to enable automatic context reconstruction across AI sessions.

## File Locations

- `docs/ARCHITECTURE.md` — System architecture and component descriptions
- `docs/DECISIONS.md` — Architectural decisions log
- `memory/current_state.md` — Current milestone, active modules, and next tasks
- `memory/sessions/` — Chronological session logs (format: `YYYY-MM-DD.md`)

## Workflow Rules

### Before Starting Work

You **must** read the following files in order:

1. `docs/ARCHITECTURE.md` — Understand system architecture
2. `memory/current_state.md` — Understand current milestone and tasks
3. Most recent file in `memory/sessions/` — Understand recent development context

### During Development

You **must**:

- Preserve architectural consistency as defined in `docs/ARCHITECTURE.md`
- Follow previously recorded decisions in `docs/DECISIONS.md`
- Update `memory/current_state.md` when task status changes
- Create a new session file when starting significant new work

### At End of Every Work Session

You **must**:

1. **Generate a session summary** documenting:
   - Work completed
   - Problems encountered
   - Key decisions made
   - Next development steps

2. **Create a new session file** in `memory/sessions/` with the current date:
   - Filename format: `YYYY-MM-DD.md`
   - Use the standard session template structure

3. **Update `memory/current_state.md`** with:
   - Current milestone status
   - Active modules list
   - Immediate next tasks
   - Any blockers

---

# End of Instructions
