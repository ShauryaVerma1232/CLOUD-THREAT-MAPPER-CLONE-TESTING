# Project Current State

Last updated: 2026-04-14

---

## Current Milestone

**Milestone:** ICCCNT 2026 Paper Evaluation - Option B Workflow

**Status:** CloudGoat resources cleaned up, ready for isolated scenario testing

**Description:**
Using **Option B: Same Account, Clean Between Scans** workflow for research evaluation:
- `threatmapper-readonly` profile → scans production AWS account (10 baseline resources)
- `cloudgoat-vulnerable` profile → scans CloudGoat scenarios (deployed to same account)
- Workflow: Deploy scenario → scan → analyze → destroy completely → wait for EC2 cleanup (~1hr)

## AWS Profile Configuration

| Profile | Purpose | Resources |
|---------|---------|-----------|
| `threatmapper-readonly` | Production baseline scan | 10 resources (your AWS account) |
| `cloudgoat-vulnerable` | CloudGoat scenario scans | Scenario resources only |

**Note:** Both profiles access the same AWS account (339713015109). Isolation is achieved by destroying CloudGoat resources completely between tests.

---

## CloudGoat CLI Commands (Updated)

| Old Command | New Command |
|-------------|-------------|
| `cloudgoat deploy <scenario>` | `cloudgoat create <scenario>` |
| `cloudgoat deployments list` | `cloudgoat list` |
| `cloudgoat destroy <scenario>` | `cloudgoat destroy <scenario>` |

**Current Commands:**
- `cloudgoat config aws|azure|whitelist|argcomplete [list]`
- `cloudgoat create <scenario>` - Deploy a scenario
- `cloudgoat destroy <scenario>|all` - Destroy scenario(s)
- `cloudgoat list <scenario>|all|azure|aws` - List scenarios
- `cloudgoat help <scenario>|<command>` - Get help

**Note:** Both profiles access the same AWS account (339713015109). Isolation is achieved by destroying CloudGoat resources completely between tests.

---

## Active Modules

| Module | Status | Description |
|--------|--------|-------------|
| AI Tasks | Fixed | INTER_CALL_DELAY increased to 12s, JSON repair added |
| Groq Provider | Active | Llama-3.1-8b-instant (free tier, ~5 RPM limit) |
| Evaluation Pipeline | In Progress | 1/4 scenarios complete |

### Core System Modules

| Module | Status | Description |
|--------|--------|-------------|
| Scanner Engine | Stable | AWS infrastructure enumeration via boto3 |
| Graph Engine | Stable | NetworkX + Neo4j graph storage |
| Detection Engine | Stable | Rule-based attack path discovery |
| Blast Radius | Stable | Multi-hop impact analysis |
| AI Reasoning Layer | Fixed | JSON parsing repaired, rate-limit safe |

---

## Immediate Next Tasks (Tomorrow - Scenario 3: cloud_breach_s3)

1. **Deploy CloudGoat Scenario 3**
   ```bash
   cd ~/cloudgoat
   cloudgoat create cloud_breach_s3 --profile cloudgoat-vulnerable
   ```

2. **Run Threat Mapper Scan**
   - Use UI: Select `cloudgoat-vulnerable` profile → Start Scan
   - Or API:
   ```bash
   curl -X POST http://localhost:18000/scans -H "Content-Type: application/json" \
     -d '{"aws_profile": "cloudgoat-vulnerable", "aws_region": "us-east-1"}'
   ```

3. **Build Attack Graph & Run AI Analysis**
   - Use UI: Click "Build Graph" on completed scan
   - Wait for AI analysis to complete (~2-3 minutes)

4. **Save Evaluation Metrics**
   - Document: resources, nodes, edges, attack paths, AI enrichment metrics
   - Fill in ground truth validation table in docs/research/evaluation_metrics.md

5. **Destroy Scenario After Evaluation**
   ```bash
   cd ~/cloudgoat
   cloudgoat destroy cloud_breach_s3 --profile cloudgoat-vulnerable
   ```

---

## Recent Changes

- **2026-04-19: Scenario 2 (ec2_ssrf) evaluation complete + destroyed**
  - Fixed EC2 scanner to resolve instance profile → IAM role ARN
  - Fixed graph builder to add INTERNET → public resource edges
  - Fixed Neo4j writer to handle INTERNET node across scans
  - Metrics: 22 resources, 1 CRITICAL attack path, 10.0 risk score
  - Ground Truth Validation: 100% match (True Positive)
  - AI Enrichment: 2 threat actors (UNC2904, APT41), 2 IAM techniques, blast radius 13 resources
  - Scenario destroyed successfully, EC2 terminated, IAM roles cleaned up
- 2026-04-14: Resolved Docker port conflicts (ports changed to 18000, 13000, 15432, 17474, 16379)
- 2026-04-14: Scenario 1 evaluation complete, metrics saved to docs/research/evaluation_metrics.md
- 2026-04-13: Fixed AI rate limiting (INTER_CALL_DELAY: 5s → 12s)
- 2026-04-13: Added JSON repair function for malformed LLM output

---

## Evaluation Progress

| Scenario | Deployed | Scanned | Graph Built | AI Analysis | Metrics Saved | Destroyed |
|----------|----------|---------|-------------|-------------|---------------|-----------|
| iam_privesc_by_ec2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ec2_ssrf | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| cloud_breach_s3 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| lambda_privesc | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

**Next:** Deploy Scenario 3 (cloud_breach_s3) for evaluation

---

## Blockers

None. System ready for next scenario.

## Configuration Verified

- ✅ `.env` has correct AWS profile settings
- ✅ `aws_session.py` uses named profiles correctly
- ✅ UI has AWS profile selector for `threatmapper-readonly` and `cloudgoat-vulnerable`
- ✅ CloudGoat CLI installed and accessible via `python -m cloudgoat`
- ✅ AWS CLI v2 installed for Windows (`C:\Program Files\Amazon\AWSCLIV2\aws.exe`)
- ✅ Cleanup scripts created for removing CloudGoat resources between tests

---

# End of Current State
