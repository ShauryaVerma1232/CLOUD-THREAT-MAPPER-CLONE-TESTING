"""
AI Reasoning Engine

Orchestrates all AI calls for the Threat Mapper platform.
Each public method:
  1. Builds the appropriate prompt
  2. Calls the configured provider
  3. Parses and validates the JSON response
  4. Returns a typed result dict (never raises on AI failure)

Design principle: AI failures are non-fatal.
If the LLM returns malformed output or the API is unavailable,
all methods return a degraded-but-valid result with an error flag.
The pipeline continues without AI annotations.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.ai.providers import AIProvider, get_provider
from app.ai.prompts import (
    SYSTEM_PROMPT,
    path_explanation_prompt,
    prioritization_prompt,
    node_annotation_prompt,
    remediation_roadmap_prompt,
    executive_summary_prompt,
    deep_iam_analysis_prompt,
)

log = structlog.get_logger()

# Token budget per call type
TOKEN_BUDGETS = {
    "path_explanation":    1200,
    "prioritization":      1500,
    "node_annotation":      300,
    "remediation_roadmap":  1800,
    "executive_summary":    1200,
    "deep_iam_analysis":    2000,
}


class AIReasoningEngine:
    """
    Main AI interface for the security reasoning pipeline.
    Instantiate once per task run with a pre-configured provider.
    """

    def __init__(self, provider: AIProvider | None = None):
        self._provider = provider or get_provider()
        log.info("ai_engine.init", provider=self._provider.name)

    # ── Public methods ─────────────────────────────────────────────────────────

    def explain_attack_path(
        self,
        path_string: str,
        path_nodes: list[dict],
        path_edges: list[dict],
        risk_score: float,
        severity: str,
    ) -> dict[str, Any]:
        """
        Generate a full explanation for a single attack path.
        Returns dict with explanation, attack_narrative, remediation_steps, etc.
        """
        prompt = path_explanation_prompt(
            path_string=path_string,
            path_nodes=path_nodes,
            path_edges=path_edges,
            risk_score=risk_score,
            severity=severity,
        )
        result = self._call_with_fallback(
            prompt,
            max_tokens=TOKEN_BUDGETS["path_explanation"],
            call_name="path_explanation",
        )
        return result or {
            "explanation":       "[AI unavailable]",
            "attack_narrative":  "",
            "business_impact":   "",
            "likelihood":        "unknown",
            "remediation_steps": [],
            "detection_signals": "",
            "ai_error":          True,
        }

    def prioritize_paths(self, paths: list[dict]) -> dict[str, Any]:
        """
        Rank attack paths by exploitability and business impact.
        Returns priority_ranking list + executive_summary + top_quick_wins.
        """
        if not paths:
            return {"priority_ranking": [], "executive_summary": "", "top_quick_wins": []}

        prompt = prioritization_prompt(paths)
        result = self._call_with_fallback(
            prompt,
            max_tokens=TOKEN_BUDGETS["prioritization"],
            call_name="prioritization",
        )
        return result or {
            "priority_ranking":  [],
            "executive_summary": "[AI unavailable]",
            "top_quick_wins":    [],
            "ai_error":          True,
        }

    def annotate_node(self, node_type: str, metadata: dict) -> dict[str, Any]:
        """
        Generate a short risk annotation for a single graph node.
        Used to add risk_label and risk_detail to the graph UI.
        """
        prompt = node_annotation_prompt(node_type=node_type, node_metadata=metadata)
        result = self._call_with_fallback(
            prompt,
            max_tokens=TOKEN_BUDGETS["node_annotation"],
            call_name="node_annotation",
        )
        return result or {
            "risk_label":  "Review required",
            "risk_detail": "[AI unavailable]",
            "risk_level":  "info",
            "ai_error":    True,
        }

    def analyze_iam_privilege_escalation(
        self,
        path_string: str,
        path_nodes: list[dict],
        path_edges: list[dict],
        risk_score: float,
        severity: str,
    ) -> dict[str, Any]:
        """
        Deep analysis of IAM privilege escalation patterns in an attack path.
        Looks for subtle patterns like policy attachment, role chaining, PassRole abuse, etc.

        Returns detailed analysis with escalation techniques, enhanced narrative, and specific mitigations.
        """
        prompt = deep_iam_analysis_prompt(
            path_string=path_string,
            path_nodes=path_nodes,
            path_edges=path_edges,
            risk_score=risk_score,
            severity=severity,
        )
        result = self._call_with_fallback(
            prompt,
            max_tokens=2000,  # Larger budget for detailed analysis
            call_name="deep_iam_analysis",
        )
        return result or {
            "privilege_escalation_detected": False,
            "escalation_techniques": [],
            "attack_narrative_enhanced": "",
            "true_risk_assessment": f"Base risk score: {risk_score}/10",
            "remediation_priority": "normal",
            "specific_mitigations": [],
            "ai_error": True,
        }

    def generate_remediation_roadmap(
        self,
        scan_summary: dict,
        top_paths: list[dict],
        test_results: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        Generate a prioritised remediation roadmap.
        """
        prompt = remediation_roadmap_prompt(
            scan_summary=scan_summary,
            top_paths=top_paths,
            test_results=test_results,
        )
        result = self._call_with_fallback(
            prompt,
            max_tokens=TOKEN_BUDGETS["remediation_roadmap"],
            call_name="remediation_roadmap",
        )
        return result or {
            "immediate_actions":      [],
            "short_term_fixes":       [],
            "strategic_improvements": [],
            "overall_risk_narrative": "[AI unavailable]",
            "ai_error":               True,
        }

    def generate_executive_summary(
        self,
        account_id: str,
        region: str,
        resource_count: int,
        attack_path_count: int,
        critical_count: int,
        overall_risk_score: float,
        top_paths: list[dict],
    ) -> dict[str, Any]:
        """Generate executive summary for the security report."""
        prompt = executive_summary_prompt(
            account_id=account_id,
            region=region,
            resource_count=resource_count,
            attack_path_count=attack_path_count,
            critical_count=critical_count,
            overall_risk_score=overall_risk_score,
            top_paths=top_paths,
        )
        result = self._call_with_fallback(
            prompt,
            max_tokens=TOKEN_BUDGETS["executive_summary"],
            call_name="executive_summary",
        )
        return result or {
            "executive_summary": "[AI unavailable]",
            "headline_risk":     "Assessment complete — AI summary unavailable",
            "risk_rating":       "Unknown",
            "key_metrics":       {},
            "ai_error":          True,
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _call_with_fallback(
        self,
        user_prompt: str,
        max_tokens: int,
        call_name: str,
    ) -> dict | None:
        """
        Call the provider and parse JSON response.
        Returns None on any failure (caller provides fallback).
        Implements exponential backoff for rate limit errors.
        """
        for attempt in range(3):
            try:
                raw = self._provider.complete(
                    system=SYSTEM_PROMPT,
                    user=user_prompt,
                    max_tokens=max_tokens,
                )
                parsed = _parse_json_response(raw)
                log.info(
                    "ai_engine.call_success",
                    call=call_name,
                    provider=self._provider.name,
                    attempt=attempt + 1,
                )
                return parsed

            except json.JSONDecodeError as e:
                log.warning(
                    "ai_engine.json_parse_error",
                    call=call_name, attempt=attempt + 1, error=str(e)
                )
                return None   # Don't retry JSON errors

            except Exception as e:
                err_str = str(e).lower()
                is_rate_limit = any(
                    kw in err_str
                    for kw in ("rate_limit", "429", "throttl", "overloaded")
                )
                log.warning(
                    "ai_engine.call_error",
                    call=call_name,
                    attempt=attempt + 1,
                    error=str(e),
                    is_rate_limit=is_rate_limit,
                )
                if is_rate_limit and attempt < 2:
                    wait = 2 ** (attempt + 2)   # 4s, 8s
                    log.info("ai_engine.rate_limit_backoff", wait_seconds=wait)
                    time.sleep(wait)
                    continue
                return None   # Give up after 3 attempts

        return None


def _parse_json_response(raw: str) -> dict:
    """
    Extract and parse a JSON object from a raw LLM response.
    Handles cases where the model wraps JSON in markdown code fences.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip()
    cleaned = cleaned.rstrip("`").strip()

    # Try direct parse first
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        log.debug("json_parse.initial_error", error=str(e), raw_length=len(raw))

    # Try to find the first {...} block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as e:
            log.debug("json_parse.regex_extract_error", error=str(e))

    # Fix common JSON issues: trailing commas, unquoted keys, single quotes
    fixed = _fix_common_json_issues(cleaned)
    if fixed != cleaned:
        try:
            return json.loads(fixed)
        except json.JSONDecodeError as e:
            log.debug("json_parse.fixed_still_invalid", error=str(e))

    raise json.JSONDecodeError("No valid JSON object found after repairs", cleaned, 0)


def _fix_common_json_issues(text: str) -> str:
    """
    Attempt to fix common JSON formatting issues from LLM output.
    """
    import re as regex

    # Remove trailing commas before } or ]
    fixed = regex.sub(r",(\s*[}\]])", r"\1", text)

    # Replace single quotes with double quotes (simple case)
    # Only if it doesn't break the JSON structure
    if "'" in fixed and '"' not in fixed:
        fixed = fixed.replace("'", '"')

    # Fix unquoted boolean/null values that might have weird casing
    fixed = regex.sub(r":\s*(True|False|None)\s*([,}\]])",
                      lambda m: f": {m.group(1).lower()}{m.group(2)}",
                      fixed, flags=regex.IGNORECASE)

    return fixed
