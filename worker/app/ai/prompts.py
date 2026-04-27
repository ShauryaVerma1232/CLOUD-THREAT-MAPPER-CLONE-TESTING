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
    return f"""You are analyzing an AWS infrastructure attack path for a security research paper.

ATTACK PATH:
{path_string}

RISK SCORE: {risk_score}/10  SEVERITY: {severity.upper()}

PATH DETAILS:
{json.dumps(path_nodes, indent=2)}

EDGES (relationships):
{json.dumps(path_edges, indent=2)}

Provide a RESEARCH-GRADE analysis with the following structure. Respond ONLY with valid JSON:

{{
  "explanation": "2-3 sentence technical summary of why this path is dangerous",

  "attack_narrative": "Detailed step-by-step exploitation guide. For EACH step include:
    - The specific AWS CLI command or API call (e.g., `aws sts assume-role --role-arn arn:aws:iam::123456789:role/ExampleRole --role-session-name attacker`)
    - The tool that could be used (aws-cli, pacu, Stratus Red Team, custom scripts)
    - What the attacker gains at this step",

  "mitre_attack_mapping": {{
    "tactics": ["TA0001: Initial Access", "TA0004: Privilege Escalation"],
    "techniques": [
      {{"id": "T1078", "name": "Valid Accounts", "subtechnique": "T1078.001: Cloud Accounts"}},
      {{"id": "T1098", "name": "Account Manipulation"}}
    ],
    "software": "Pacu, Stratus Red Team, aws-cli"
  }},

  "threat_actor_context": "Which real-world threat actors have used similar techniques? Reference specific incidents (e.g., Capital One 2019, Uber 2022, Okta 2023). If no direct match, note 'Novel technique combination' or 'Consistent with APT cloud TTPs'.",

  "business_impact": "Quantify impact: data volume at risk, number of affected customers, regulatory implications (GDPR, HIPAA, SOC2), estimated breach cost",

  "likelihood": "realistic | likely | highly_likely — with 1-sentence justification",

  "exploit_complexity": "low | medium | high — based on: does it require public access? authentication? specific timing?",

  "remediation_steps": [
    {{"action": "Specific fix", "aws_cli": "aws iam ... command to fix", "effort": "low|medium|high", "breaks_legacy": "yes|no — will this break existing apps?"}},
    {{"action": "...", "aws_cli": "...", "effort": "...", "breaks_legacy": "..."}}
  ],

  "detection_queries": {{
    "cloudtrail": "SELECT eventName, userIdentity.arn, sourceIPAddress FROM CloudTrail WHERE eventName = 'AssumeRole' AND ...",
    "guardduty": "Relevant GuardDuty finding types (e.g., PrivilegeEscalation:IAMUser/AssumeRoleAnomaly)",
    "athena_hunt": "Full Athena query to hunt for historical exploitation"
  }},

  "blast_radius_estimate": {{
    "resources_at_risk": "Estimated count of resources accessible post-exploitation",
    "data_assets": "S3 buckets, RDS instances, secrets accessible",
    "iam_principals": "Number of IAM users/roles that can be accessed",
    "lateral_movement_potential": "low | medium | high — can attacker pivot further?"
  }}
}}"""


# ── Threat Actor TTP Mapping ──────────────────────────────────────────────────

def threat_actor_mapping_prompt(
    path_string: str,
    path_nodes: list[dict],
    path_edges: list[dict],
) -> str:
    """
    Map attack path to known threat actors and their TTPs.
    This provides context for research papers by connecting findings to real-world incidents.
    """
    import json
    return f"""Map this AWS attack path to known threat actors and real-world incidents.

ATTACK PATH:
{path_string}

PATH DETAILS:
{json.dumps(path_nodes, indent=2)}

EDGES:
{json.dumps(path_edges, indent=2)}

Research and identify:
1. **APT Groups**: Which APT groups have used similar cloud TTPs? (e.g., APT29, APT41, UNC2904)
2. **Cybercriminal Groups**: Ransomware gangs, eCrime groups with cloud exploitation patterns
3. **Real Breaches**: Specific incidents where similar attack paths were exploited
4. **MITRE ATT&CK for Cloud**: Map to the official matrix

Respond ONLY with valid JSON:
{{
  "threat_actor_matches": [
    {{
      "actor_name": "UNC2904 (SolarStorm)",
      "actor_type": "Nation-state (Russia SVR)",
      "similarity": "high | medium | low",
      "overlapping_techniques": ["SSRF to IMDSv1", "IAM role assumption", "Cross-account lateral movement"],
      "source": "Mandiant M-Trends 2021, CISA AA21-028A"
    }}
  ],

  "real_world_incidents": [
    {{
      "incident_name": "Capital One Breach (2019)",
      "year": 2019,
      "attacker": " Paige Thompson (hacktivist)",
      "technique": "SSRF via web application firewall to IMDSv1, retrieved IAM role credentials",
      "impact": "100M+ customer records",
      "similarity_to_current_path": "Explain how this relates to the current scan"
    }}
  ],

  "mitre_attack_cloud_matrix": {{
    "tactics": [
      {{"id": "TA0001", "name": "Initial Access", "techniques_used": ["T1190: Exploit Public-Facing Application"]}}
    ],
    "full_mapping": "https://attack.mitre.org/matrices/enterprise/cloud/"
  }},

  "industry_sector_relevance": "Which sectors are most targeted by actors using these TTPs? (e.g., 'Financial services and healthcare are primary targets for ransomware groups using cloud privilege escalation')"
}}"""


# ── Blast Radius Quantification ───────────────────────────────────────────────

def blast_radius_analysis_prompt(
    path_string: str,
    path_nodes: list[dict],
    path_edges: list[dict],
    all_resources: list[dict],
) -> str:
    """
    Quantify the blast radius of an attack path.
    This computes HOW MANY resources would be compromised if this path is exploited.
    """
    import json
    return f"""Quantify the blast radius of this attack path.

ATTACK PATH:
{path_string}

PATH NODES:
{json.dumps(path_nodes, indent=2)}

ALL RESOURCES IN SCOPE:
{json.dumps(all_resources[:30], indent=2)}  # Limited to top 30 for token budget

Calculate the blast radius by analyzing:
1. **Direct Access**: Resources directly accessible from the terminal node
2. **IAM Principal Access**: How many IAM users/roles can be accessed/assumed
3. **Data Assets**: S3 buckets, RDS instances, Secrets Manager secrets accessible
4. **Compute Resources**: EC2 instances, Lambda functions that can be modified
5. **Network Access**: VPCs, subnets, security groups that can be modified
6. **Persistence**: Can attacker create backdoors (access keys, login profiles, IAM users)?

Respond ONLY with valid JSON:
{{
  "blast_radius_summary": {{
    "total_resources_at_risk": <integer count>,
    "iam_principals_accessible": <integer count>,
    "data_assets_accessible": {{
      "s3_buckets": <count>,
      "rds_instances": <count>,
      "secrets": <count>,
      "estimated_data_volume": "GB/TB estimate if available"
    }},
    "compute_resources_at_risk": {{
      "ec2_instances": <count>,
      "lambda_functions": <count>,
      "can_deploy_code": true/false
    }},
    "network_infrastructure": {{
      "vpcs_affected": <count>,
      "security_groups_modifiable": <count>,
      "can_disable_logging": true/false
    }}
  }},

  "compromise_timeline": {{
    "initial_access": "<time estimate, e.g., '30 seconds'>",
    "privilege_escalation": "<time estimate>",
    "lateral_movement": "<time estimate>",
    "full_compromise": "<time estimate, e.g., '5-10 minutes'>",
    "confidence": "low | medium | high"
  }},

  "attack_chain_depth": {{
    "hop_count": <integer>,
    "complexity": "low | medium | high",
    "automation_potential": "Can this be fully automated? true/false"
  }},

  "cascading_failures": "What secondary systems would be affected? (e.g., 'CI/CD pipeline compromise → supply chain attack', 'Backup access → ransomware persistence')"
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


# ── Deep IAM Analysis ─────────────────────────────────────────────────────────

def deep_iam_analysis_prompt(
    path_string: str,
    path_nodes: list[dict],
    path_edges: list[dict],
    risk_score: float,
    severity: str,
) -> str:
    """
    Build the user prompt for deep IAM privilege escalation analysis.
    This is a specialized analysis that looks for subtle IAM attack patterns.
    """
    import json
    return f"""You are an IAM security researcher analyzing this AWS attack path for privilege escalation patterns.
This analysis will be published in a peer-reviewed security research paper.

ATTACK PATH:
{path_string}

RISK SCORE: {risk_score}/10  SEVERITY: {severity.upper()}

PATH DETAILS:
{json.dumps(path_nodes, indent=2)}

EDGES (relationships):
{json.dumps(path_edges, indent=2)}

Analyze for these IAM privilege escalation patterns with RESEARCH-GRADE depth:

**Category 1: Policy Attachment/Modification**
- iam:AttachUserPolicy, iam:AttachGroupPolicy, iam:AttachRolePolicy
- iam:PutUserPolicy, iam:PutGroupPolicy, iam:PutRolePolicy
- iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion
- iam:CreatePolicy, iam:DeletePolicyVersion

**Category 2: Role Assumption & Chaining**
- sts:AssumeRole, sts:AssumeRoleWithSAML, sts:AssumeRoleWithWebIdentity
- Trust relationship exploitation
- Role chaining (Role A → Role B → Admin)

**Category 3: Credential Creation/Manipulation**
- iam:CreateAccessKey, iam:CreateLoginProfile, iam:UpdateLoginProfile
- iam:CreateUser, iam:DeleteUser (account takeover)

**Category 4: PassRole + Service Deployment**
- iam:PassRole + ec2:RunInstances (instance profile hijack)
- iam:PassRole + lambda:CreateFunction (code execution with elevated privileges)
- iam:PassRole + glue:CreateDevEndpoint, glue:UpdateDevEndpoint
- iam:PassRole + cloudformation:CreateStack, cloudformation:UpdateStack

**Category 5: Resource-Based Policy Modification**
- s3:PutBucketPolicy, s3:PutBucketAcl
- kms:PutKeyPolicy, kms:CreateGrant
- secretsmanager:PutResourcePolicy

**Category 6: Data Exfiltration Paths**
- s3:GetObject, s3:ListBucket on sensitive buckets
- rds:DescribeDBInstances + rds:CopyDBSnapshot (cross-account snapshot theft)

For EACH technique detected, provide:
1. The EXACT IAM permission(s) required
2. The AWS API call sequence an attacker would make
3. Why this is dangerous in THIS specific context
4. Which MITRE ATT&CK technique it maps to

Respond ONLY with valid JSON:
{{
  "privilege_escalation_detected": true/false,

  "escalation_techniques": [
    {{
      "technique_name": "Descriptive name (e.g., 'Admin Role Attachment via iam:AttachRolePolicy')",
      "category": "Policy Attachment | Role Chaining | Credential Creation | PassRole Abuse | Resource Policy | Data Exfiltration",
      "required_permissions": ["iam:AttachRolePolicy", "sts:AssumeRole"],
      "attack_command": "aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
      "mitre_mapping": {{
        "tactic": "TA0004: Privilege Escalation",
        "technique": "T1078: Valid Accounts",
        "subtechnique": "T1078.001: Cloud Accounts"
      }},
      "severity": "critical | high | medium | low",
      "evidence": "Quote the exact policy statement or trust relationship from the path data",
      "why_dangerous": "Explain why THIS specific configuration is dangerous, not generic statements",
      "real_world_precedent": "Reference a real breach if applicable (e.g., 'Capital One 2019 used similar SSRF + IMDSv1 technique')"
    }}
  ],

  "attack_narrative_enhanced": "Complete attack narrative that weaves together ALL detected techniques into a coherent story. Include:
    - Initial access method
    - Each privilege escalation step with specific API calls
    - Final impact (what can attacker access/do)
    - Estimated time to full compromise (e.g., '5-10 minutes for experienced attacker')",

  "quantitative_risk_assessment": {{
    "base_score": {risk_score},
    "escalation_factor": "1.3x | 1.5x | 1.7x | 2.0x — justify why",
    "escalated_score": "calculated score (capped at 10.0)",
    "justification": "Why this escalation factor? Reference number of escalation techniques, blast radius, etc."
  }},

  "remediation_priority": "immediate | high | normal | low",

  "specific_mitigations": [
    {{
      "mitigation": "Exact IAM policy change",
      "policy_snippet": "{{\\"Effect\\": \\"Deny\\", \\"Action\\": \\"iam:AttachRolePolicy\\", ...}}",
      "breaking_change_risk": "low | medium | high — will this break legitimate apps?",
      "implementation_notes": "Rollout strategy, testing recommendations"
    }}
  ],

  "detection_rules": {{
    "cloudtrail_events": ["AttachRolePolicy", "AssumeRole", "CreateAccessKey"],
    "guardduty_findings": ["PrivilegeEscalation:IAMUser/AssumeRoleAnomaly", "Persistence:IAMUser/AccessKeyAnomaly"],
    "athena_query": "SELECT eventName, userIdentity.arn, eventSource FROM CloudTrail WHERE eventName IN ('AttachRolePolicy', 'AssumeRole') AND eventTime > NOW() - INTERVAL '7' DAY",
    "splunk_query": "index=aws_cloudtrail eventName IN (AttachRolePolicy, AssumeRole) | stats count by userIdentity.arn, sourceIPAddress"
  }}
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
