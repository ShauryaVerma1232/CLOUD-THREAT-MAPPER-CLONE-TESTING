# Session Context - Threat Mapper Research Project

## Project Goal
Build evaluation data for research paper on automated cloud threat mapping and AI-powered attack path analysis.

## Completed Work

### Scenario 1: iam_privesc_by_ec2 ✅ COMPLETE
- **Deployed:** CloudGoat iam_privesc_by_ec2 scenario
- **Scanned:** 17 resources, 1 attack path identified
- **Attack Path:** `cg_dev_user → cg_ec2_management_role` (direct IAM role assumption)
- **Risk Score:** 5.75/10 (Medium)
- **AI Analysis:** Completed - correctly identified as legitimate trust relationship (no escalation)
- **Blast Radius:** 1 resource reachable, score 1.4
- **Data Saved:** `docs/research/scenario1_metrics.md`
- **Environment:** Cleaned up, ready for next scenario

### UI Improvements (All Complete)
1. **AI Report Display** - Collapsible panel with 3 tabs (Executive Summary, Quick Wins, Priorities)
2. **Risk Score Escalation** - AI applies 1.3x-2.0x multiplier when privilege escalation detected
3. **CloudGoat Filter** - Toggle to show only CloudGoat scenario resources
4. **Attack Path Highlighting** - Visual highlighting with export as PNG for research paper
5. **Auto-highlight** - First (most critical) attack path highlighted on page load

---

## Next Session: Scenario 2 (ec2_ssrf)

### What to Do:
1. **Deploy** CloudGoat `ec2_ssrf` scenario
   ```bash
   cd /path/to/cloudgoat
   cloudgoat deploy ec2_ssrf --profile cloudgoat-vulnerable
   ```

2. **Run Threat Mapper Scan**
   - Use AWS profile: `cloudgoat-vulnerable`
   - Wait for scan to complete

3. **Build Attack Graph**
   - Trigger graph build after scan completes
   - Verify graph shows ec2_ssrf resources

4. **Run AI Analysis**
   - Auto-triggered after graph build
   - Or manually: `POST /ai/analyze/{scan_id}`

5. **Extract All Metrics**
   - Scan metadata (resources, account, region)
   - Attack paths (path strings, scores, severity)
   - AI analysis (explanations, remediation)
   - IAM escalation analysis (if applicable)
   - Blast radius for compromised nodes
   - Executive summary

6. **Save to Research Paper**
   - Save complete metrics to `docs/research/scenario2_metrics.md`
   - Include raw infrastructure model JSON

7. **Destroy Scenario**
   ```bash
   cloudgoat destroy ec2_ssrf --profile cloudgoat-vulnerable
   ```
   - Verify cleanup with Threat Mapper scan

---

## Research Paper Metrics to Collect (Per Scenario)

| Category | Metrics |
|----------|---------|
| **Scan** | Resources scanned, attack paths found, scan duration |
| **Attack Path** | Path string, hop count, all 4 risk scores, severity |
| **AI Analysis** | Explanation, remediation steps, escalation detected (Y/N) |
| **IAM Escalation** | Techniques detected, priority, multiplier applied |
| **Blast Radius** | Direct/secondary reach, critical count, severity score |
| **Executive** | Headline risk, risk rating, key findings |

---

## Current Environment State
- **AWS Profile:** `cloudgoat-vulnerable`
- **Status:** Clean (only default AWS resources + jacktheripper user)
- **Ready for:** Scenario 2 deployment

---

*Last updated: 2026-04-14*
