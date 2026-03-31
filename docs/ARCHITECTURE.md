# Cloud Threat Mapper — System Architecture

This document defines the architecture of the **Cloud Threat Mapper** system.

The purpose of this document is to help developers and AI coding assistants understand
the design principles, system components, data flow, and constraints of the platform.

AI assistants should reference this document when generating or modifying code.

---

# System Overview

Cloud Threat Mapper is a **cloud security analysis platform** designed to identify
attack paths, privilege escalation risks, and security misconfigurations in AWS environments.

The system works by:

1. Enumerating AWS infrastructure
2. Converting infrastructure into a structured model
3. Building a graph representation of the cloud environment
4. Running security detection logic on the graph
5. Generating AI-assisted analysis and remediation suggestions

The system is designed to support **large cloud environments** and therefore uses
asynchronous processing and modular architecture.

---

# High-Level Architecture

```
User Request
↓
API Server (FastAPI)
↓
Scan Task (Celery Worker)
↓
Infrastructure Model Generation
↓
Graph Builder
↓
Detection Engine
↓
Attack Path Discovery
↓
AI Reasoning Layer
↓
Security Report
```

Each stage is **loosely coupled** and executed asynchronously.

---

# Core System Components

The system consists of five primary subsystems.

1. API Layer
2. Scanner Engine
3. Graph Engine
4. Detection Engine
5. AI Reasoning Layer

Each subsystem is described below.

---

# 1. API Layer

Responsible for receiving user requests and managing scan workflows.

**Technology:** FastAPI

**Responsibilities:**
- Initiate scans
- Track scan status
- Return scan results
- Trigger background tasks

**Example endpoints:**
```
POST /scans
GET /scans/{scan_id}
GET /scans/{scan_id}/report
```

The API server **does not perform heavy computation**.
All scanning and analysis operations are delegated to Celery workers.

---

# 2. Scanner Engine

The scanner engine enumerates AWS infrastructure using the AWS SDK.

**Technology:** boto3

The scanner collects metadata about cloud resources including:
- VPCs
- Subnets
- Security Groups
- EC2 Instances
- IAM Users
- IAM Roles
- IAM Policies
- S3 Buckets
- Lambda Functions
- RDS Instances

Scanner modules are located in:
```
scanner/
```

Example modules:
```
scanner/
  ec2_scanner.py
  iam_scanner.py
  s3_scanner.py
  vpc_scanner.py
```

Scanner output is normalized into a **structured infrastructure model**.

Example output:
```
artifacts/<scan_id>/infrastructure_model.json
```

Example structure:
```json
{
  "resources": [
    {
      "id": "ec2-123",
      "type": "EC2Instance",
      "metadata": {}
    }
  ],
  "relationships": []
}
```

The infrastructure model becomes the **input for the graph engine**.

---

# 3. Graph Engine

The graph engine converts infrastructure models into a graph structure
representing relationships between resources.

The graph is used to detect attack paths and privilege escalation.

**Technology:** NetworkX (initial implementation)

**Graph components:**

Nodes represent resources:
- EC2 Instance
- IAM User
- IAM Role
- S3 Bucket
- Security Group

Edges represent relationships:
- EC2 → SecurityGroup
- SecurityGroup → Internet
- IAM User → IAM Role
- IAM Role → Policy
- Policy → Admin Privileges

Graph modules are located in:
```
graph/
```

Example modules:
```
graph/
  graph_builder.py
  attack_paths.py
  graph_models.py
```

The graph builder performs:
- node creation
- edge creation
- relationship mapping

The attack path engine performs graph traversal to detect:
- lateral movement
- privilege escalation
- exposed services
- sensitive resource access

---

# 4. Detection Engine

The detection engine performs **rule-based security analysis** on the graph.

This stage identifies high-risk patterns before invoking AI reasoning.

**Examples of detection rules:**

### Public Exposure
```
Internet → SecurityGroup → EC2
```

### Privilege Escalation
```
IAM User → RoleAssumption → Admin Role
```

### Public S3 Bucket
```
S3 Bucket → PublicRead
```

### Open Security Group
```
SecurityGroup → 0.0.0.0/0
```

The detection engine outputs:
- high-risk nodes
- attack paths
- security findings

Example output:
```json
{
  "findings": [],
  "attack_paths": []
}
```

This filtered output is passed to the AI reasoning layer.

---

# 5. Attack Path Engine

Attack paths represent potential routes an attacker could take
to escalate privileges or move laterally across the cloud environment.

Example path:
```
Internet
↓
EC2 Instance
↓
IAM Role
↓
Admin Policy
```

Graph traversal algorithms used:
- Depth-first search
- Breadth-first search
- shortest path algorithms

Attack paths are stored as structured objects:
```json
{
  "path": [
    "internet",
    "ec2_instance",
    "iam_role",
    "admin_policy"
  ]
}
```

These paths are used by the AI layer for explanation.

---

# 6. AI Reasoning Layer

The AI layer explains findings and generates remediation guidance.

**Technology:** Grok API

The AI model **does not scan infrastructure directly**.

Instead it receives structured inputs including:
- graph metadata
- detection results
- attack paths

Example prompt input:
```
Infrastructure Graph Summary
Detected Findings
Attack Paths
```

The AI model returns structured JSON.

Example response:
```json
{
  "attack_path_explanations": [],
  "remediation_steps": [],
  "risk_score": 0
}
```

AI is used for:
- explanation
- prioritization
- remediation suggestions
- report generation

AI must **not be used for deterministic detection logic**.

---

# Task Pipeline

All heavy operations are executed using Celery workers.

**Technology:**
- Celery
- Redis (message broker)

Pipeline:
```
run_infrastructure_scan
↓
build_attack_graph
↓
run_detection_engine
↓
discover_attack_paths
↓
run_ai_analysis
```

Each task is idempotent and retry-safe.

---

# Data Storage

Persistent storage is handled by PostgreSQL.

Stored data includes:
- scan metadata
- resource nodes
- graph edges
- findings
- reports

Artifacts are stored locally:
```
artifacts/<scan_id>/
```

Example:
```
artifacts/
  12345/
    infrastructure_model.json
    graph.json
    findings.json
```

---

# Container Architecture

Local development uses Docker Compose.

Services:
```
api
worker
redis
postgres
```

Example startup:
```
docker compose up
```

---

# Performance Considerations

To support large cloud environments the system must:
- parallelize AWS scans
- batch AI analysis
- avoid unnecessary LLM calls
- store intermediate artifacts

---

# Security Constraints

The system must follow strict security rules.

- Never store AWS credentials in source code
- Never commit `.env` files
- Always assume scans run on real cloud environments
- Protect sensitive metadata

---

# Future Extensions

The architecture is designed to support future enhancements.

Potential extensions include:
- Azure support
- GCP support
- graph database (Neo4j)
- real-time cloud monitoring
- automated remediation
- CI/CD integration
- security posture scoring

---

# Design Principles

The system follows these core design principles.

### Modular Architecture
Each subsystem operates independently.

### Deterministic Security Detection
Security logic must be rule-based and testable.

### AI for Reasoning Only
AI should explain and prioritize findings, not replace detection logic.

### Asynchronous Processing
Long-running operations should always be executed in background workers.

---

# End of Architecture Document
