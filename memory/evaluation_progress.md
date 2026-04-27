---
name: ICCCNT 2026 Evaluation Progress
description: CloudGoat scenario evaluation progress and methodology for research paper
type: project
---

# CloudGoat Evaluation Progress

**Last Updated:** 2026-04-26

## Completed Scenarios

### Scenario 1: iam_privesc_by_ec2 ✅
- **Date:** 2026-04-14
- **Status:** Complete, destroyed
- **Ground Truth Match:** ✅ True Positive (100%)
- **Detection Accuracy:** 1 TP, 0 FP, 0 FN (100% precision, 100% recall)
- **Key Finding:** IAM privilege escalation via role assumption correctly identified
- **Metrics:** 17 resources, 1 medium severity path (5.75 risk score)

### Scenario 2: ec2_ssrf ✅
- **Date:** 2026-04-19
- **Status:** Complete, destroyed
- **Ground Truth Match:** ✅ True Positive (100%)
- **Detection Accuracy:** 1 TP, 0 FP, 0 FN (100% precision, 100% recall)
- **Key Findings:**
  - Critical internet-facing attack path detected (10.0 risk score)
  - 2 threat actors matched (UNC2904/SolarStorm, APT41)
  - 2 IAM escalation techniques with MITRE mapping
  - Blast radius: 13 resources at risk
- **AI Analysis Time:** 150 seconds (Groq/llama-3.1-8b-instant)

### Scenario 3: cloud_breach_s3 ✅
- **Date:** 2026-04-21
- **Status:** Complete, destroyed
- **Ground Truth Match:** ✅ True Positive (100%)
- **Detection Accuracy:** 3 TP, 0 FP, 0 FN (100% precision, 100% recall)
- **Key Findings:**
  - 3 critical attack paths detected (Internet → EC2 → IAM → S3)
  - 3 threat actors matched (UNC2904, APT41, APT29)
  - 3 IAM escalation techniques: Admin Role Attachment, Role Chaining, S3 Access
  - Full MITRE ATT&CK coverage: 12 tactics (TA0001-TA0012)
  - Blast radius: 17 resources at risk (81% of infrastructure)
  - PCI-DSS compliance impact: Cardholder data bucket exposure
- **AI Analysis Time:** ~6 minutes (full enrichment)

### Scenario 4: lambda_privesc ✅
- **Date:** 2026-04-26
- **Status:** Complete, data gathered
- **Ground Truth Match:** ✅ True Positive (100%)
- **Detection Accuracy:** 4 TP, 0 FP, 0 FN (100% precision, 100% recall)
- **Key Findings:**
  - 4 attack paths detected (2 Critical, 1 High, 1 Medium)
  - Lambda-based privilege escalation: User → Role → Lambda → IAM Modification
  - Multi-hop chain up to 5 hops discovered
  - 2 threat actors matched (UNC2904, APT41)
  - 3 MITRE tactics mapped (TA0001, TA0002, TA0003)
  - Blast radius: 19-23 resources at risk, Lambda code deployment possible
- **AI Analysis Time:** ~90 seconds

## Overall Accuracy (4/4 scenarios COMPLETE)

| Metric | Value |
|--------|-------|
| True Positives | 9 |
| False Positives | 0 |
| False Negatives | 0 |
| Precision | 100% |
| Recall | 100% |
| Ground Truth Match | 4/4 (100%) |

## Next Steps for Paper

1. **Fill Section IV (Evaluation)** in paper_draft.md with complete metrics
2. **Update Abstract** with final numbers (9 paths, 100% accuracy)
3. **Create final tables** for submission
4. **Add Scenario 4 section** to evaluation_metrics.md
5. **Destroy lambda_privesc scenario** after data collection
