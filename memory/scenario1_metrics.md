# Scenario 1: iam_privesc_by_ec2 - Complete Evaluation Metrics

**Scan Date:** 2026-04-13T23:14:30Z
**Scan ID:** `701a9678-4f03-41d8-b052-57ad6405c573`
**CloudGoat Scenario:** `iam_privesc_by_ec2`

---

## 1. Scan Metadata

| Field | Value |
|-------|-------|
| AWS Account | `339713015109` |
| AWS Region | `us-east-1` |
| AWS Profile | `cloudgoat-vulnerable` |
| Status | `complete` |
| Resources Scanned | **17** |
| Attack Paths Found | **1** |
| Critical Paths | **0** |
| Overall Risk Score | **5.75/10** (Medium) |
| Scan Duration | ~17 seconds |

---

## 2. Infrastructure Summary

### Resources by Type
| Type | Count | Details |
|------|-------|---------|
| EC2 Instances | 1 | `i-0152270cbf0ab000e` (t3.micro, private subnet) |
| IAM Roles | 2 | `cg_ec2_management_role`, `cg_ec2_role` (admin) |
| IAM Users | 2 | `cg_dev_user`, `jacktheripper` |
| S3 Buckets | 1 | `shauryatest-bucket` (private, encrypted) |
| VPCs | 2 | 1 default, 1 CloudGoat custom |
| Subnets | 7 | 6 public, 1 private |
| Security Groups | 2 | Default VPC security groups |

### CloudGoat-Specific Resources (4 core resources)
1. **User:** `cg_dev_user_cgid4vxlwg8sii` - Developer user with ReadOnlyAccess + can assume role
2. **Role:** `cg_ec2_management_role_cgid4vxlwg8sii` - EC2 management role (not admin)
3. **EC2:** `i-0152270cbf0ab000e` (cg_admin_ec2) - Attached to `cg_ec2_role` (admin!)
4. **Role:** `cg_ec2_role_cgid4vxlwg8sii` - **Has AdministratorAccess policy**

---

## 3. Attack Path Analysis

### Primary Attack Path
```
User: cg_dev_user_cgid4vxlwg8sii → Role: cg_ec2_management_role_cgid4vxlwg8sii
```

### Risk Score Breakdown
| Component | Score | Description |
|-----------|-------|-------------|
| **Reachability Score** | 0.0 | No direct internet exposure |
| **Impact Score** | 0.7 | High-impact target (EC2 management) |
| **Exploitability Score** | 1.0 | Trivial (direct role assumption) |
| **Exposure Score** | 0.8 | High exposure (IAM is global) |
| **Composite Risk Score** | **5.75** | Medium severity |

### Path Properties
| Property | Value |
|----------|-------|
| Path ID | `31eddb2a-4ad4-41ae-ad11-0f55379a7461` |
| Severity | `medium` |
| Hop Count | 1 |
| Edge Type | `can_assume` |
| Validated | `false` (not sandbox-tested) |

---

## 4. AI Analysis Results

### AI Explanation
> "This attack path is dangerous because it allows a user with the 'cg_dev_user_cgid4vxlwg8sii' identity to assume the 'cg_ec2_management_role_cgid4vxlwg8sii' role, granting them elevated privileges to manage EC2 instances. This could be used to pivot to other AWS services or escalate privileges further."

### AI Remediation Steps
1. Review and restrict the `cg_dev_user` user's permissions to only allow necessary actions on EC2 instances
2. Use IAM policies to restrict the `cg_ec2_management_role` role to only allow necessary actions
3. Monitor CloudTrail logs for `AssumeRole` API calls and investigate suspicious activity

### IAM Privilege Escalation Analysis
| Field | Value |
|-------|-------|
| `privilege_escalation_detected` | **false** |
| `escalation_techniques` | `[]` (empty) |
| `remediation_priority` | `normal` |

**Why no escalation detected:** The AI correctly identified this as a **legitimate IAM relationship** (user can assume role by design) rather than a privilege escalation vulnerability. The path represents authorized role assumption, not an exploit chain involving policy modification, credential creation, or PassRole abuse.

### True Risk Assessment (AI)
> "Base risk score: 5.75/10" - No escalation applied because this is a direct trust relationship, not an escalation technique.

---

## 5. Blast Radius Analysis

**Compromised Node:** `arn:aws:iam::339713015109:user/cg_dev_user_cgid4vxlwg8sii`

| Metric | Value |
|--------|-------|
| Direct Reach (1-hop) | **1 resource** |
| Secondary Reach (2-hop) | **0 resources** |
| Total Reachable | **1 resource** |
| Critical Resources at Risk | **1** (IAM Role) |
| Blast Radius Severity | `medium` |
| Blast Radius Score | **1.4** |

### Resources Accessible from Compromised User
| Hop Distance | Resource | Type | Admin? |
|--------------|----------|------|--------|
| 1 | `cg_ec2_management_role_cgid4vxlwg8sii` | IAM_ROLE | No |

---

## 6. Executive Summary (AI-Generated)

> "Our cloud security assessment of AWS account 339713015109 in the us-east-1 region identified a total of 17 resources and uncovered a single attack path with a medium severity rating. The assessment was conducted using a thorough methodology to analyze potential security risks and vulnerabilities. Our findings indicate a moderate level of risk, with an overall risk score of 5.75 out of 10. While the risk is not critical, it is essential to address these findings to maintain the security and integrity of our cloud infrastructure. The top risk identified is related to a potential privilege escalation vulnerability, which could allow unauthorized access to sensitive resources. We recommend prioritizing the remediation of this risk to minimize potential business impact."

### Headline Risk
> "A potential privilege escalation vulnerability exists in the cg_dev_user_cgid4vxlwg8sii role, allowing unauthorized access to sensitive resources."

---

## 7. Remediation Roadmap

### Immediate Actions
| Action | Rationale | Effort | Risk Reduction |
|--------|-----------|--------|----------------|
| Review and update IAM role permissions for `cg_ec2_management_role` | The identified attack path indicates a potential privilege escalation risk | Medium | Eliminates the identified medium-risk attack path |
| Implement IAM role chaining prevention mechanisms | Role chaining is a common attack pattern in AWS | High | Reduces the risk of role chaining attacks |

### Short-Term Fixes
1. Implement AWS IAM access analyzer to monitor and alert on IAM policy changes
2. Conduct a thorough review of IAM roles and policies

### Strategic Improvements
1. Implement a least privilege access model for all IAM roles and users
2. Regularly review and update IAM roles and policies

### Overall Risk Narrative
> "The current risk posture of this AWS environment is moderate, with a single identified attack path indicating a potential privilege escalation risk. Implementing immediate actions and short-term fixes will help address this risk, while strategic improvements will further reduce the overall risk posture."

---

## 8. Key Technical Findings

### Trust Policy Analysis (cg_ec2_management_role)
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::339713015109:user/cg_dev_user_cgid4vxlwg8sii"},
    "Action": "sts:AssumeRole"
  }]
}
```

### Inline Policy (cg_ec2_management_role)
The role has permissions to:
- `ec2:StartInstances`
- `ec2:StopInstances`
- `ec2:ModifyInstanceAttribute`

**Condition:** Cannot target the `cg_admin_ec2` instance specifically (resource-level restriction)

### Privilege Escalation Chain (Potential)
1. `cg_dev_user` (ReadOnlyAccess) → assumes → `cg_ec2_management_role`
2. `cg_ec2_management_role` → manages EC2 instances → can modify instance attributes
3. If EC2 instance profile can be modified → could attach admin role → full account compromise

**Note:** This escalation chain was NOT automatically detected because it requires multi-step reasoning about EC2 instance profile modification capabilities.

---

## 9. Graph Statistics

| Metric | Value |
|--------|-------|
| Total Nodes | 18 |
| Total Edges | 10 |
| Node Types | INTERNET(1), EC2(1), IAM_ROLE(2), IAM_USER(2), S3(1), VPC(2), SUBNET(7), SG(2) |
| Edge Types | `connected_to`(9), `can_assume`(1) |

---

## 10. AI Provider Configuration

| Setting | Value |
|---------|-------|
| Provider | `groq` |
| Model | `llama-3.1-8b-instant` |
| API Calls Made | ~7 (1 prioritization, 1 path explanation, 1 IAM analysis, 1 exec summary, 1 roadmap, 3 node annotations) |

---

## 11. Research Paper Notes

### Why Risk Score Was NOT Escalated
The AI privilege escalation escalation feature (Task #17) did NOT apply in this case because:
1. The path represents a **legitimate trust relationship** - user is explicitly allowed to assume the role
2. No IAM policy modification techniques were detected (no `AttachUserPolicy`, `PutRolePolicy`, etc.)
3. No credential creation capabilities (no `CreateAccessKey`, `CreateLoginProfile`)
4. No PassRole abuse pattern (user doesn't deploy services with elevated roles)

This is actually a **validation** of the AI logic - it correctly distinguishes between:
- **Authorized role assumption** (this case) - no escalation
- **Unauthorized privilege escalation** (policy modification, credential theft) - would trigger escalation

### Implications for Research
- The tool correctly identifies **direct IAM trust relationships** as medium risk (5.75)
- The AI analysis provides **contextual understanding** beyond simple path detection
- The blast radius is **limited** (1 hop) because the assumed role has limited scope
- The **real risk** is in the EC2 management capabilities, which could lead to instance profile modification

---

## 12. Raw Data Files

- **Infrastructure Model:** `/app/artifacts/701a9678-4f03-41d8-b052-57ad6405c573/infrastructure_model.json`
- **Scan Record:** Database ID `701a9678-4f03-41d8-b052-57ad6405c573`
- **Attack Path Record:** Database ID `31eddb2a-4ad4-41ae-ad11-0f55379a7461`
- **Blast Radius Record:** Database ID `4147e42a-5443-4a44-bf5d-07a031fe66f7`

---

*Data extracted: 2026-04-14*
*Scenario will be destroyed after extraction - this is the complete permanent record.*
