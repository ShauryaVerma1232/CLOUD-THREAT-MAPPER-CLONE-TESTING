---
name: UI and AI Improvements - April 2026
description: Three key improvements: AI report display, risk score escalation, and CloudGoat environment filter
type: project
---

**Improvements Applied on 2026-04-14:**

## 1. AI Report Display in Graph UI
- Added collapsible AI Report panel with 3 tabs (Executive Summary, Quick Wins, Priorities)
- Accessible via "View AI Report" button in top-right of graph page
- Fetches data from `/ai/summary/{scanId}` endpoint
- Shows headline risk, executive summary, risk narrative, and prioritized remediation actions

## 2. Risk Score Escalation for Privilege Escalation
- AI now applies escalation multiplier when `privilege_escalation_detected=True`
- Multipliers: Critical (2.0x), High (1.7x), Medium (1.5x), Normal (1.3x)
- Final score capped at 10.0
- Severity recalculated after escalation
- Database columns added: `ai_escalation_applied`, `ai_escalation_multiplier`
- Migration: `0004_add_escalation_multiplier_columns.py`

## 3. Mixed Environments Filter
- Added "CloudGoat only" toggle to graph control panel
- Filters out personal AWS resources (jacktheripper, shauryatest-bucket, etc.)
- Recognizes CloudGoat naming patterns: `cg-`, `cg_`, `shepard`, `solus`, `wrex`, `jacktheripper`
- When ON: shows only CloudGoat scenario resources
- When OFF: shows all scanned resources (default behavior)

## Files Modified
- `frontend/src/pages/GraphPage.tsx` - AI report panel, filter toggle, CloudGoat detection
- `worker/app/tasks/ai_tasks.py` - Risk escalation logic, multiplier constants
- `backend/app/models/models.py` - Added escalation columns to AttackPath model
- `backend/alembic/versions/0004_add_escalation_multiplier_columns.py` - Migration

## Testing
- Frontend rebuilt and restarted
- Worker restarted with new escalation logic
- Database migration applied successfully
