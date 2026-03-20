"""
AI Prompt Templates

All prompts are defined here as constants and builder functions.
Keeping prompts in one file makes them easy to tune and version.

Design rules:
  1. System prompt always establishes the security architect persona
  2. User prompts are grounded with structured JSON data
  3. Output format is requested explicitly (JSON or structured text)
  4. Prompts never ask the AI to make infrastructure decisions
"""

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior cloud security architect with deep expertise in:
- AWS IAM privilege escalation and lateral movement
- Network attack surface analysis
- Cloud-native attack patterns (SSRF, metadata service abuse, role chaining)
- Security findings communication to both technical and executive audiences

You are analyzing real AWS infrastructure scan data to identify security risks.
Your analysis must be:
- Accurate and grounded in the data provided
- Specific about attack techniques (name the CVE, technique, or AWS API call)
- Actionable — every finding must include concrete remediation steps
- Clearly structured for inclusion in a professional security report

You are a reasoning tool only. You do not control infrastructure or execute commands."""


# ── Attack path explanation ───────────────────────────────────────────────────

def path_explanation_prompt(
    path_string: str,
    path_nodes: list[dict],
    path_edges: list[dict],
    risk_score: float,
    severity: str,
) -> str:
    """
    Build the user prompt for explaining a single attack path.
    Returns structured JSON with explanation, attack_steps, business_impact, remediation.
    """
    import json
    return f"""Analyze this AWS infrastructure attack path and provide a detailed security explanation.

ATTACK PATH:
{path_string}

RISK SCORE: {risk_score}/10  SEVERITY: {severity.upper()}

PATH DETAILS:
{json.dumps(path_nodes, indent=2)}

EDGES (relationships):
{json.dumps(path_edges, indent=2)}

Respond ONLY with a valid JSON object — no markdown, no preamble:
{{
  "explanation": "2-3 sentence summary of why this path is dangerous",
  "attack_narrative": "Step-by-step description of how an attacker exploits this path. Be specific about AWS API calls, tools (e.g. aws-cli, pacu, impacket), and techniques.",
  "business_impact": "Concrete business impact if exploited (data breach, ransomware pivot, account takeover, etc.)",
  "likelihood": "realistic | likely | highly_likely",
  "remediation_steps": [
    "Specific, actionable fix #1 (include AWS console path or CLI command where possible)",
    "Specific, actionable fix #2",
    "Specific, actionable fix #3"
  ],
  "detection_signals": "What CloudTrail events or GuardDuty findings would indicate this path is being exploited"
}}"""


# ── Path prioritization ───────────────────────────────────────────────────────

def prioritization_prompt(paths: list[dict]) -> str:
    """
    Given a list of attack paths with scores, return a ranked priority list
    with reasoning for why each was ranked where it was.
    """
    import json

    # Limit to top 20 to stay within token budget
    top_paths = sorted(paths, key=lambda p: p.get("risk_score", 0), reverse=True)[:20]

    paths_summary = [
        {
            "path_string": p["path_string"],
            "risk_score":  p["risk_score"],
            "severity":    p["severity"],
            "hop_count":   p.get("hop_count", 0),
        }
        for p in top_paths
    ]

    return f"""You are prioritizing AWS infrastructure attack paths for a security team.

ATTACK PATHS TO PRIORITIZE:
{json.dumps(paths_summary, indent=2)}

Consider:
1. Ease of exploitation (fewer hops, publicly accessible origins = higher priority)
2. Business impact of the target resource (admin roles, databases > compute)
3. Blast radius if the terminal node is compromised
4. Whether the path requires chained exploitation vs single step

Respond ONLY with a valid JSON object:
{{
  "priority_ranking": [
    {{
      "rank": 1,
      "path_string": "exact path string from input",
      "priority_reasoning": "1-2 sentences explaining why this ranks here",
      "recommended_action": "Fix X before Y because..."
    }}
  ],
  "executive_summary": "2-3 sentence overview of the most critical risks across all paths",
  "top_quick_wins": ["Quick fix #1 that would eliminate multiple paths", "Quick fix #2"]
}}"""


# ── Node risk annotation ──────────────────────────────────────────────────────

def node_annotation_prompt(node_type: str, node_metadata: dict) -> str:
    """
    Generate a short risk annotation for a single graph node.
    Used to annotate nodes in the UI and report.
    """
    import json
    return f"""Provide a brief security risk annotation for this AWS resource.

RESOURCE TYPE: {node_type}
METADATA:
{json.dumps(node_metadata, indent=2)}

Respond ONLY with a valid JSON object:
{{
  "risk_label": "1 short phrase (max 8 words) summarising the key risk",
  "risk_detail": "1-2 sentences explaining the specific risk for this resource configuration",
  "risk_level": "critical | high | medium | low | info"
}}"""


# ── Remediation roadmap ───────────────────────────────────────────────────────

def remediation_roadmap_prompt(
    scan_summary: dict,
    top_paths: list[dict],
    test_results: list[dict] | None = None,
) -> str:
    """
    Generate a prioritised remediation roadmap from scan + test data.
    """
    import json
    test_section = ""
    if test_results:
        exploitable = [r for r in test_results if r.get("exploitable")]
        test_section = f"""
CONFIRMED EXPLOITABLE FINDINGS ({len(exploitable)} total):
{json.dumps(exploitable[:10], indent=2)}
"""

    return f"""Create a prioritised remediation roadmap for this AWS environment.

SCAN SUMMARY:
{json.dumps(scan_summary, indent=2)}

TOP ATTACK PATHS:
{json.dumps(top_paths[:10], indent=2)}
{test_section}

Respond ONLY with a valid JSON object:
{{
  "immediate_actions": [
    {{
      "action": "What to do",
      "rationale": "Why this is the highest priority",
      "effort": "low | medium | high",
      "risk_reduction": "What attack paths this eliminates"
    }}
  ],
  "short_term_fixes": [
    {{
      "action": "What to do (within 30 days)",
      "rationale": "Why",
      "effort": "low | medium | high"
    }}
  ],
  "strategic_improvements": [
    "Longer-term architectural improvement #1",
    "Longer-term architectural improvement #2"
  ],
  "overall_risk_narrative": "3-4 sentence executive summary of the current risk posture and trajectory"
}}"""


# ── Executive report summary ──────────────────────────────────────────────────

def executive_summary_prompt(
    account_id: str,
    region: str,
    resource_count: int,
    attack_path_count: int,
    critical_count: int,
    overall_risk_score: float,
    top_paths: list[dict],
) -> str:
    import json
    return f"""Write an executive summary for a cloud security assessment report.

ASSESSMENT DETAILS:
- AWS Account: {account_id}
- Region: {region}
- Resources Scanned: {resource_count}
- Attack Paths Identified: {attack_path_count}
- Critical Paths: {critical_count}
- Overall Risk Score: {overall_risk_score}/10

TOP 3 ATTACK PATHS:
{json.dumps(top_paths[:3], indent=2)}

Write for a non-technical executive audience. 3-4 paragraphs covering:
1. Assessment scope and methodology
2. Key findings and most significant risks
3. Business impact of the top risks
4. Recommended immediate priorities

Respond ONLY with a valid JSON object:
{{
  "executive_summary": "Full multi-paragraph executive summary text",
  "headline_risk": "One sentence: the single most important risk finding",
  "risk_rating": "Critical | High | Medium | Low",
  "key_metrics": {{
    "critical_paths": {critical_count},
    "total_paths": {attack_path_count},
    "overall_score": {overall_risk_score}
  }}
}}"""
