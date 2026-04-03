# Claude Code Skill — Generate Research Presentation

You are tasked with generating a **professional research-style presentation (max 10 slides)** for a cloud security research project.

The final output must be a **PDF slide deck** suitable for:

• academic presentations  
• technical conferences  
• research proposal demonstrations  

The presentation must include **clear diagrams, non-overlapping graphics, and a professional design system**.

---

# Project Title

Cloud Threat Mapper: Graph-Based Attack Path Analysis for Cloud Infrastructure Security

---

# Presentation Design Requirements

## Slide Limit
Maximum **10 slides**

## Format
Output must be exported as:

PDF presentation slides

Use a **16:9 layout**.

---

## Visual Style

Use a **clean professional color palette**:

Primary color:
Deep blue (#1f3a5f)

Secondary color:
Teal (#2a9d8f)

Accent color:
Orange (#f4a261)

Background:
Light gray or white

Text:
Dark charcoal (#222222)

---

## Typography

Title font:
Bold sans-serif

Body font:
Clean sans-serif

Minimum text size for readability.

---

# Graphic Rules

All diagrams must follow these rules:

• No overlapping labels  
• No overlapping nodes  
• Clear directional arrows  
• Consistent spacing  
• Color-coded components  

Every diagram must include **clear labels**.

---

# Diagrams Required

The presentation must include the following **original diagrams**.

### 1 Infrastructure Scanning Pipeline

Show flow:

AWS Environment  
→ Scanner Modules  
→ Infrastructure Model  
→ Graph Builder  
→ Attack Path Analysis  
→ AI Reasoning Layer  
→ Security Report

Use arrows and layered components.

---

### 2 System Architecture Diagram

Components:

Frontend UI

API Layer (FastAPI)

Task Queue (Celery)

Redis Message Broker

Worker Node

Scanner Modules

Graph Engine

AI Analysis Engine

Database (PostgreSQL)

Artifacts Storage

Show interactions between them.

---

### 3 Cloud Resource Graph Example

Illustrate a graph with nodes such as:

IAM User  
EC2 Instance  
Security Group  
Subnet  
VPC  
S3 Bucket

Edges should represent relationships like:

"attached_to"  
"belongs_to"  
"has_permission"

---

### 4 Attack Path Visualization

Example path:

IAM User  
→ IAM Role  
→ EC2 Instance  
→ Security Group  
→ Sensitive Resource

Explain lateral movement.

---

# Slide Structure

Use the following slide structure.

---

## Slide 1 — Title Slide

Include:

Project title  
Subtitle:

Graph-Based Cloud Attack Path Analysis System

Author name placeholder

Include a minimal architecture illustration in the background.

---

## Slide 2 — Problem Statement

Explain:

Cloud infrastructure complexity

Difficulty detecting privilege escalation paths

Limitations of traditional rule-based cloud scanners.

Include a small visual representing **complex cloud environments**.

---

## Slide 3 — Research Question

Present the central research question:

How can graph-based infrastructure modeling improve the detection of privilege escalation paths in cloud environments?

Add supporting points:

• cloud resource relationships  
• attack surface expansion  
• automated reasoning

---

## Slide 4 — Proposed Approach

Explain the methodology:

1 Infrastructure data collection from AWS APIs  
2 Graph-based modeling of cloud resources  
3 Attack path discovery algorithms  
4 AI-assisted reasoning for risk prioritization  

Include a **methodology pipeline diagram**.

---

## Slide 5 — System Architecture

Present the full architecture diagram.

Explain components:

Frontend interface

API server

Task orchestration

Graph engine

AI analysis module

Database layer

---

## Slide 6 — Graph Modeling

Explain how cloud resources are represented as a graph.

Nodes:

IAM identities  
Compute resources  
Network components  
Storage services

Edges:

permissions  
network connectivity  
resource ownership

Include **graph visualization example**.

---

## Slide 7 — Attack Path Discovery

Explain attack path logic.

Example:

Privilege escalation  
Lateral movement  
Resource exposure

Include attack path diagram.

---

## Slide 8 — AI-Assisted Security Analysis

Explain the role of AI:

Risk explanation  
Security context annotation  
Remediation recommendations

Include diagram:

Graph Engine → AI Analysis → Security Insights

---

## Slide 9 — Evaluation Strategy

Describe evaluation approach.

Testing environments:

CloudGoat labs  
intentionally vulnerable AWS environments

Metrics:

Attack path detection accuracy  
False positive rate  
Analysis time

If statistics are needed, request permission to perform a **web search**.

---

## Slide 10 — Contributions and Impact

Highlight contributions:

Graph-based cloud security analysis framework

AI-assisted attack path reasoning

Automated risk prioritization

Real-world cloud lab evaluation

End with:

Future work

Multi-cloud support  
Advanced attack simulations  
Security automation

---

# Content Guidelines

Slides must:

• avoid excessive text  
• emphasize diagrams  
• remain visually clean  
• maintain strong visual hierarchy  

---

# Web Data Policy

If additional statistics or cloud security research references are needed:

Ask the user:

"Requesting permission to perform a web search to retrieve relevant cloud security statistics for the presentation."

Only proceed with web queries after approval.

---

# Output Instructions

1 Generate slides according to the structure above  
2 Render diagrams programmatically  
3 Ensure spacing and alignment are clean  
4 Export the final presentation as a **PDF**

File name:

cloud_attack_path_analysis_presentation.pdf

---

# End of Skill
