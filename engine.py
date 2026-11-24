"""Deterministic Evaluation Engine & Read-Only Local Pilot Scanner for Sprint 3.

Niche 3: Stalled AI Pilot to Working Workflow Rescue (Typically 2-3 Weeks), Port 9103.
100% local, local-only, read-only structural diagnostics. Never transmits or
persists raw prompts, secrets, or proprietary source code.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

SIGNAL_ROUTING_RULES = {
    k: []
    for k in (
        "unclassified_pii_or_secrets",
        "overprivileged_agent_or_db_roles",
        "vector_or_saas_exposure",
        "shadow_ai_unapproved_tools",
        "audit_logging_or_retention_gap",
        "regulatory_or_policy_drift",
        "hallucination_or_ungrounded_output",
        "missing_observability_or_hitl",
        "broken_rag_schema_or_data_hygiene",
        "manual_csv_reconciliation_bottleneck",
        "unstructured_pdf_or_doc_intake",
        "multi_cloud_config_or_telemetry_sprawl",
    )
}


CAPSULE_VERSION = "1.0"
NICHE_ID = 3
NICHE_SLUG = "sprint-3-pilot-rescue"
NICHE_TITLE = "Stalled AI Pilot to Working Workflow Rescue (Typically 2-3 Weeks)"

TRUTHY_STRINGS = {"true", "yes", "1", "y", "pass", "ok", "grounded"}
FALSY_STRINGS = {"false", "no", "0", "n", "fail", "ungrounded", ""}
HEALTHY_FAILURE_TYPES = {"", "none", "ok", "pass", "healthy", "success", "null"}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "coverage",
}
CODE_EXTENSIONS = {".py", ".ts", ".js", ".mjs"}
DATA_EXTENSIONS = {".json", ".jsonl"}

# Regex patterns for read-only structural inspection (no prompt text capture)
LLM_CALL_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("OpenAI Chat/Responses", re.compile(r"\b(chat\.completions\.create|responses\.create|ChatOpenAI|AsyncOpenAI|OpenAI\s*\()")),
    ("Anthropic Messages", re.compile(r"\b(messages\.create|ChatAnthropic|Anthropic\s*\()")),
    ("Gemini / Vertex AI", re.compile(r"\b(generate_content|generateContent|GenerativeModel|ChatVertexAI)\b")),
    ("Agent / Chain Framework", re.compile(r"\b(AgentExecutor|StateGraph|Crew\s*\(|LLMChain|RetrievalQA| litellm\.completion| ollama\.chat|InvokeModel)\b")),
    ("Direct LLM HTTP Endpoint", re.compile(r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|/v1/chat/completions)")),
]

SCHEMA_GUARD_PATTERN = re.compile(
    r"\b(BaseModel|TypeAdapter|pydantic|zod|z\.object|ajv|valibot|jsonschema|with_structured_output|response_format|generateObject|instructor)\b"
)
FRAGILE_PARSE_PATTERN = re.compile(
    r"(json\.loads\s*\(|JSON\.parse\s*\(|re\.search\s*\(\s*r?['\"]\\?\{|split\s*\(\s*['\"]```)"
)
TIMEOUT_RETRY_PATTERN = re.compile(
    r"\b(timeout\s*=|timeout\s*:|AbortController|AbortSignal\.timeout|tenacity|@retry|max_retries|backoff|pRetry|p-retry)\b"
)
DETERMINISTIC_CHECK_PATTERN = re.compile(
    r"\b(def\s+(?:verify|validate|check|critic|reconcile|assert)_\w+|function\s+(?:verify|validate|check|critic|reconcile)\w*|critic_gate|quote_grounding|grounding_check)\b"
)
FALLBACK_HANDLER_PATTERN = re.compile(
    r"\b(human_review|escalate_to_human|escalation_queue|dead_letter|dlq|fallback_handler|review_queue|hitl)\b"
)
SILENT_SWALLOW_PY_PATTERN = re.compile(r"except(?:\s+\w[\w\s,().]*)?\s*:\s*\n\s*(?:pass|\.\.\.)\b")
SILENT_SWALLOW_JS_PATTERN = re.compile(r"catch\s*\([^)]*\)\s*\{\s*(?:console\.(?:log|warn)\([^)]*\)\s*;?\s*)?\}")
RETRIEVAL_CALL_PATTERN = re.compile(
    r"\b(pinecone|chromadb|qdrant|weaviate|pgvector|faiss|similarity_search|vector_store|\.execute\s*\(\s*f['\"]SELECT\b|SELECT\s+\*\s+FROM)\b",
    re.IGNORECASE,
)
RAW_SQL_INTERP_PATTERN = re.compile(
    r"(\.execute\s*\(\s*f['\"]|`\s*SELECT\s+[^`]*\$\{|SELECT\s+\*\s+FROM)",
    re.IGNORECASE,
)


def _norm_bool(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    s = str(val or "").strip().lower()
    if s in TRUTHY_STRINGS:
        return True
    if s in FALSY_STRINGS:
        return False
    return default


def parse_traces_csv(csv_text: str) -> Dict[str, Any]:
    """Parse optional sanitized failure traces CSV text into structural metrics."""
    text = (csv_text or "").strip()
    if not text:
        return {
            "trace_count": 0,
            "failed_count": 0,
            "ungrounded_count": 0,
            "unhandled_count": 0,
            "high_latency_count": 0,
            "rag_or_schema_failures": 0,
            "timeout_or_silent_failures": 0,
            "parse_or_edge_failures": 0,
            "error_rate_pct": None,
            "ungrounded_rate_pct": None,
            "rows": [],
        }

    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return {
            "trace_count": 0,
            "failed_count": 0,
            "ungrounded_count": 0,
            "unhandled_count": 0,
            "high_latency_count": 0,
            "rag_or_schema_failures": 0,
            "timeout_or_silent_failures": 0,
            "parse_or_edge_failures": 0,
            "error_rate_pct": None,
            "ungrounded_rate_pct": None,
            "rows": [],
        }

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows: List[Dict[str, Any]] = []
    failed_count = 0
    ungrounded_count = 0
    unhandled_count = 0
    high_latency_count = 0
    rag_or_schema_failures = 0
    timeout_or_silent_failures = 0
    parse_or_edge_failures = 0

    for raw in reader:
        if not raw:
            continue
        norm = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
        trace_id = norm.get("trace_id", "")
        step_name = norm.get("step_name", "")
        if not trace_id and not step_name:
            continue

        failure_type = norm.get("failure_type", "none").lower()
        grounded = _norm_bool(norm.get("grounded_in_source", "true"), default=True)
        handled = _norm_bool(norm.get("handled_gracefully", "true"), default=True)
        try:
            latency_ms = int(float(norm.get("latency_ms", "0") or 0))
        except ValueError:
            latency_ms = 0

        is_failed = (failure_type not in HEALTHY_FAILURE_TYPES) or (not grounded)
        if not grounded:
            ungrounded_count += 1
        if is_failed:
            failed_count += 1
            if not handled:
                unhandled_count += 1
        if latency_ms >= 5000:
            high_latency_count += 1

        if any(tok in failure_type for tok in ("rag", "stale", "vector", "pk", "join", "schema", "sql", "duplicate")):
            rag_or_schema_failures += 1
        if any(tok in failure_type for tok in ("timeout", "silent", "webhook", "retry", "500", "502", "504", "rate")):
            timeout_or_silent_failures += 1
        if any(tok in failure_type for tok in ("json", "regex", "parse", "schema", "edge", "format")):
            parse_or_edge_failures += 1

        rows.append(
            {
                "trace_id": trace_id or f"TRC-{len(rows) + 1}",
                "step_name": step_name or "unnamed_step",
                "failure_type": failure_type or "none",
                "grounded_in_source": grounded,
                "latency_ms": latency_ms,
                "handled_gracefully": handled,
                "is_failed": is_failed,
            }
        )

    total = len(rows)
    return {
        "trace_count": total,
        "failed_count": failed_count,
        "ungrounded_count": ungrounded_count,
        "unhandled_count": unhandled_count,
        "high_latency_count": high_latency_count,
        "rag_or_schema_failures": rag_or_schema_failures,
        "timeout_or_silent_failures": timeout_or_silent_failures,
        "parse_or_edge_failures": parse_or_edge_failures,
        "error_rate_pct": round((failed_count * 100.0) / total) if total > 0 else None,
        "ungrounded_rate_pct": round((ungrounded_count * 100.0) / total) if total > 0 else None,
        "rows": rows,
    }


def parse_stages_csv(csv_text: str) -> Dict[str, Any]:
    """Parse optional workflow stage definitions CSV text into structural hop metrics."""
    text = (csv_text or "").strip()
    if not text:
        return {
            "stage_count": 0,
            "missing_schema_count": 0,
            "unverified_hops": 0,
            "missing_fallback_count": 0,
            "has_doc_intake_stage": False,
            "has_raw_db_or_rag_stage": False,
            "rows": [],
        }

    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return {
            "stage_count": 0,
            "missing_schema_count": 0,
            "unverified_hops": 0,
            "missing_fallback_count": 0,
            "has_doc_intake_stage": False,
            "has_raw_db_or_rag_stage": False,
            "rows": [],
        }

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows: List[Dict[str, Any]] = []
    missing_schema_count = 0
    unverified_hops = 0
    missing_fallback_count = 0
    has_doc_intake_stage = False
    has_raw_db_or_rag_stage = False

    for raw in reader:
        if not raw:
            continue
        norm = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
        stage_name = norm.get("stage_name", "")
        input_source = norm.get("input_source", "")
        if not stage_name and not input_source:
            continue

        has_schema = _norm_bool(norm.get("has_json_schema", "false"), default=False)
        has_check = _norm_bool(norm.get("has_deterministic_check", "false"), default=False)
        has_fallback = _norm_bool(norm.get("has_human_fallback", "false"), default=False)

        if not has_schema:
            missing_schema_count += 1
        if not has_check:
            unverified_hops += 1
        if not has_fallback:
            missing_fallback_count += 1

        combined = f"{stage_name} {input_source}".lower()
        if any(tok in combined for tok in ("pdf", "ocr", "scan", "invoice", "attachment", "doc")):
            has_doc_intake_stage = True
        if any(tok in combined for tok in ("raw_sql", "vector", "pinecone", "rag", "uncleaned", "staging")):
            has_raw_db_or_rag_stage = True

        rows.append(
            {
                "stage_order": norm.get("stage_order", str(len(rows) + 1)),
                "stage_name": stage_name or f"stage_{len(rows) + 1}",
                "input_source": input_source or "unspecified",
                "has_json_schema": has_schema,
                "has_deterministic_check": has_check,
                "has_human_fallback": has_fallback,
            }
        )

    return {
        "stage_count": len(rows),
        "missing_schema_count": missing_schema_count,
        "unverified_hops": unverified_hops,
        "missing_fallback_count": missing_fallback_count,
        "has_doc_intake_stage": has_doc_intake_stage,
        "has_raw_db_or_rag_stage": has_raw_db_or_rag_stage,
        "rows": rows,
    }


def evaluate_intake(payload: Dict[str, Any], mode: str = "production") -> Dict[str, Any]:
    """Deterministically evaluate a Sprint 3 AI Pilot Rescue intake payload.

    Matches the exact client-side JavaScript formula in `client-assessment.html`.
    All `prospect` fields (`company_name`, `contact_name`, `contact_email`) are optional.
    """
    raw_prospect = payload.get("prospect") or {}
    raw_inputs = payload.get("inputs") or payload

    prospect = {
        "company_name": str(raw_prospect.get("company_name") or "").strip(),
        "contact_name": str(raw_prospect.get("contact_name") or "").strip(),
        "contact_email": str(raw_prospect.get("contact_email") or "").strip(),
        "industry": str(raw_prospect.get("industry") or "general").strip() or "general",
        "team_size": str(raw_prospect.get("team_size") or "50-250").strip() or "50-250",
    }

    symptoms_raw = raw_inputs.get("failure_symptoms") or []
    if isinstance(symptoms_raw, str):
        symptoms = [s.strip() for s in symptoms_raw.split(",") if s.strip()]
    else:
        symptoms = [str(s).strip() for s in symptoms_raw if str(s).strip()]

    inputs = {
        "workflow_name": str(raw_inputs.get("workflow_name") or "Untitled AI Workflow Pilot").strip() or "Untitled AI Workflow Pilot",
        "current_stage": str(raw_inputs.get("current_stage") or "stalled_internal_pilot").strip(),
        "failure_symptoms": symptoms,
        "output_validation": str(raw_inputs.get("output_validation") or "free_text_or_regex_only").strip(),
        "retrieval_hygiene": str(raw_inputs.get("retrieval_hygiene") or "raw_docs_or_uncleaned_db").strip(),
        "human_in_the_loop": str(raw_inputs.get("human_in_the_loop") or "none_all_or_nothing").strip(),
        "observability_and_retries": str(raw_inputs.get("observability_and_retries") or "console_logs_only").strip(),
        "traces_csv_text": str(raw_inputs.get("traces_csv_text") or ""),
        "stages_csv_text": str(raw_inputs.get("stages_csv_text") or ""),
    }

    symptom_set = set(inputs["failure_symptoms"])
    trace_stats = parse_traces_csv(inputs["traces_csv_text"])
    stage_stats = parse_stages_csv(inputs["stages_csv_text"])

    # 1. Output Contracts & Grounding Critic (0-25)
    validation_base_map = {
        "none_raw_completion": 17,
        "free_text_or_regex_only": 14,
        "json_schema_no_critic": 8,
        "schema_plus_deterministic_critic": 2,
    }
    dim_critic = validation_base_map.get(inputs["output_validation"], 14)
    if "hallucinated_facts_or_numbers" in symptom_set:
        dim_critic += 4
    if "breaks_on_edge_cases" in symptom_set:
        dim_critic += 2
    if (trace_stats["ungrounded_rate_pct"] or 0) >= 15:
        dim_critic += 2
    dim_critic = min(25, dim_critic)

    # 2. Retrieval & Upstream Schema Hygiene (0-20)
    retrieval_base_map = {
        "raw_docs_or_uncleaned_db": 13,
        "basic_chunking_stale_sync": 9,
        "curated_views_partial_lineage": 4,
        "governed_freshness_and_pk": 1,
    }
    dim_retrieval = retrieval_base_map.get(inputs["retrieval_hygiene"], 13)
    if "bad_rag_or_stale_data" in symptom_set or trace_stats["rag_or_schema_failures"] > 0:
        dim_retrieval += 4
    if "overprivileged_db_or_pii_leak" in symptom_set or stage_stats["has_raw_db_or_rag_stage"]:
        dim_retrieval += 2
    dim_retrieval = min(20, dim_retrieval)

    # 3. Human-in-the-Loop & Escalation Design (0-20)
    hitl_base_map = {
        "none_all_or_nothing": 13,
        "ad_hoc_slack_or_email": 8,
        "confidence_gated_queue": 2,
    }
    dim_hitl = hitl_base_map.get(inputs["human_in_the_loop"], 13)
    if stage_stats["stage_count"] > 0 and stage_stats["missing_fallback_count"] == stage_stats["stage_count"]:
        dim_hitl += 3
    elif stage_stats["missing_fallback_count"] > 0:
        dim_hitl += 2
    if inputs["current_stage"] in {"flaky_production_workflow", "stalled_internal_pilot"} and inputs["human_in_the_loop"] != "confidence_gated_queue":
        dim_hitl += 2
    dim_hitl = min(20, dim_hitl)

    # 4. Observability, Retry Shield & SLA Alerting (0-20)
    obs_base_map = {
        "console_logs_only": 13,
        "basic_apm_no_evals": 8,
        "traced_bounded_sla_alerted": 2,
    }
    dim_obs = obs_base_map.get(inputs["observability_and_retries"], 13)
    if "silent_production_errors" in symptom_set or trace_stats["unhandled_count"] > 0:
        dim_obs += 4
    if trace_stats["high_latency_count"] > 0 or trace_stats["timeout_or_silent_failures"] > 0:
        dim_obs += 2
    dim_obs = min(20, dim_obs)

    # 5. Empirical Trace & Multi-Hop Chain Complexity (0-15)
    if trace_stats["trace_count"] > 0:
        err_ratio = trace_stats["failed_count"] / trace_stats["trace_count"]
        unhandled_ratio = trace_stats["unhandled_count"] / trace_stats["trace_count"]
        trace_pts = min(9, int(round(err_ratio * 12.0 + unhandled_ratio * 6.0)))
    else:
        trace_pts = min(5, len(symptom_set))

    if stage_stats["stage_count"] > 0:
        unv_ratio = stage_stats["unverified_hops"] / stage_stats["stage_count"]
        noschema_ratio = stage_stats["missing_schema_count"] / stage_stats["stage_count"]
        stage_pts = min(6, int(round(unv_ratio * 4.0 + noschema_ratio * 2.0)))
    else:
        stage_pts = 3 if "breaks_on_edge_cases" in symptom_set else (2 if inputs["output_validation"] != "schema_plus_deterministic_critic" else 0)

    dim_empirical = min(15, trace_pts + stage_pts)

    headline_score = max(0, min(100, dim_critic + dim_retrieval + dim_hitl + dim_obs + dim_empirical))

    if headline_score >= 80 or (
        headline_score >= 70
        and (
            len(symptom_set) >= 4
            or stage_stats["stage_count"] >= 5
            or "unstructured_pdf_or_doc_mess" in symptom_set
        )
    ):
        estimated_sprint_days = "5-7 Weeks (Phased) · Phase 1: 1-Week Triage · Phase 2: 4-6 Weeks (~160-240 hrs at 40 hrs/wk)"
    elif headline_score >= 60:
        estimated_sprint_days = "3-5 Weeks · ~120-200 hrs (at 40 hrs/wk)"
    elif headline_score >= 35:
        estimated_sprint_days = "2-3 Weeks · ~80-120 hrs (at 40 hrs/wk)"
    else:
        estimated_sprint_days = "1-2 Weeks · ~40-80 hrs (at 40 hrs/wk)"

    if headline_score >= 85:
        severity_tier = "CRITICAL"
        score_label = f"High Priority Gaps ({headline_score}/100 Checklist Score)"
    elif headline_score >= 65:
        severity_tier = "HIGH"
        score_label = f"Notable Safeguard Gaps ({headline_score}/100 Checklist Score)"
    elif headline_score >= 40:
        severity_tier = "MODERATE"
        score_label = f"Moderate Safeguard Gaps ({headline_score}/100 Checklist Score)"
    else:
        severity_tier = "LOW"
        score_label = f"Low Checklist Exposure ({headline_score}/100 Checklist Score)"

    if stage_stats["stage_count"] > 0:
        unverified_hops_display = f"{stage_stats['unverified_hops']} of {stage_stats['stage_count']}"
    else:
        unverified_hops_display = "Not Provided"

    if trace_stats["trace_count"] > 0:
        trace_error_display = f"{trace_stats['error_rate_pct']}% ({trace_stats['failed_count']}/{trace_stats['trace_count']})"
    else:
        trace_error_display = "No Logs Uploaded"

    key_metrics = [
        {"label": "Checklist Score", "value": f"{headline_score} / 100"},
        {"label": "Unchecked Steps (CSV/Scan)", "value": unverified_hops_display},
        {"label": "Error Rate in Uploaded Logs", "value": trace_error_display},
        {"label": "Estimated Effort", "value": estimated_sprint_days},
    ]

    failure_taxonomy = [
        {
            "axis": "Output Format & Fact-Checking",
            "risk_points": dim_critic,
            "max_points": 25,
            "status": "CRITICAL" if dim_critic >= 18 else ("ELEVATED" if dim_critic >= 10 else "HEALTHY"),
        },
        {
            "axis": "Cleanliness of Lookup Data",
            "risk_points": dim_retrieval,
            "max_points": 20,
            "status": "CRITICAL" if dim_retrieval >= 15 else ("ELEVATED" if dim_retrieval >= 8 else "HEALTHY"),
        },
        {
            "axis": "Human Review Fallback",
            "risk_points": dim_hitl,
            "max_points": 20,
            "status": "CRITICAL" if dim_hitl >= 14 else ("ELEVATED" if dim_hitl >= 8 else "HEALTHY"),
        },
        {
            "axis": "Error Logs, Timeouts & Retries",
            "risk_points": dim_obs,
            "max_points": 20,
            "status": "CRITICAL" if dim_obs >= 14 else ("ELEVATED" if dim_obs >= 8 else "HEALTHY"),
        },
        {
            "axis": "Workflow Complexity & Logged Errors",
            "risk_points": dim_empirical,
            "max_points": 15,
            "status": "CRITICAL" if dim_empirical >= 10 else ("ELEVATED" if dim_empirical >= 5 else "HEALTHY"),
        },
    ]

    top_findings: List[Dict[str, str]] = []

    if (
        inputs["output_validation"] != "schema_plus_deterministic_critic"
        or "hallucinated_facts_or_numbers" in symptom_set
        or (trace_stats["ungrounded_count"] > 0)
    ):
        ungrounded_note = (
            f" ({trace_stats['ungrounded_rate_pct']}% of uploaded log entries contained unverified claims or numbers)"
            if trace_stats["trace_count"] > 0 and trace_stats["ungrounded_count"] > 0
            else ""
        )
        hop_note = (
            f" across {stage_stats['unverified_hops']} of {stage_stats['stage_count']} listed workflow steps"
            if stage_stats["stage_count"] > 0
            else ""
        )
        top_findings.append(
            {
                "id": "PR-01",
                "severity": "CRITICAL" if dim_critic >= 16 else "HIGH",
                "title": "AI Outputs Pass Through Without Code-Level Fact & Format Checks",
                "detail": (
                    f"Outputs currently rely on '{inputs['output_validation']}'{hop_note}{ungrounded_note}. "
                    "Without strict output field validation and a code check that verifies IDs, prices, and source quotes, "
                    "made-up values flow straight into your business tools."
                ),
                "client_next_step": (
                    "Require strict field formats (JSON schema) at each step and add a code check that compares every output ID, number, and quote against your real records."
                ),
            }
        )

    if (
        inputs["retrieval_hygiene"] in {"raw_docs_or_uncleaned_db", "basic_chunking_stale_sync"}
        or "bad_rag_or_stale_data" in symptom_set
        or trace_stats["rag_or_schema_failures"] > 0
    ):
        rag_note = (
            f" ({trace_stats['rag_or_schema_failures']} uploaded log entries failed due to outdated or duplicate lookup data)"
            if trace_stats["rag_or_schema_failures"] > 0
            else ""
        )
        top_findings.append(
            {
                "id": "PR-02",
                "severity": "HIGH" if dim_retrieval >= 13 else "MODERATE",
                "title": "AI Searches Messy, Outdated, or Duplicate Source Data",
                "detail": (
                    f"Data cleanliness is marked '{inputs['retrieval_hygiene']}'{rag_note}. "
                    "Feeding uncleaned folders, duplicate rows, or outdated product records into an AI prompt produces confident wrong answers no matter which model you use."
                ),
                "client_next_step": (
                    "Create clean read-only database views with unique IDs and freshness timestamps before passing data into the AI step."
                ),
            }
        )

    if (
        inputs["human_in_the_loop"] != "confidence_gated_queue"
        or (stage_stats["stage_count"] > 0 and stage_stats["missing_fallback_count"] > 0)
    ):
        top_findings.append(
            {
                "id": "PR-03",
                "severity": "HIGH" if dim_hitl >= 14 else "MODERATE",
                "title": "All-or-Nothing Workflow With No Human Review Queue",
                "detail": (
                    f"Human fallback is marked '{inputs['human_in_the_loop']}'. When an unusual case or mismatch happens, "
                    "there is no hold queue, forcing your team to either pause the whole tool or double-check every single output by hand."
                ),
                "client_next_step": (
                    "Let verified items pass automatically and hold uncertain or mismatched items in a clear human approve/edit/reject queue."
                ),
            }
        )

    if (
        inputs["observability_and_retries"] != "traced_bounded_sla_alerted"
        or "silent_production_errors" in symptom_set
        or trace_stats["unhandled_count"] > 0
    ):
        unhandled_note = (
            f" ({trace_stats['unhandled_count']} failed runs were not caught cleanly; "
            f"{trace_stats['high_latency_count']} took longer than 5 seconds)"
            if trace_stats["trace_count"] > 0 and (trace_stats["unhandled_count"] > 0 or trace_stats["high_latency_count"] > 0)
            else ""
        )
        top_findings.append(
            {
                "id": "PR-04",
                "severity": "CRITICAL" if trace_stats["unhandled_count"] >= 3 or "silent_production_errors" in symptom_set else "MODERATE",
                "title": "Silent Timeouts, Uncapped Retries, or Missing Step Logs",
                "detail": (
                    f"Error tracking is marked '{inputs['observability_and_retries']}'{unhandled_note}. "
                    "Hidden errors, missing timeouts, and blind retries cause dropped updates or unexpected API bills."
                ),
                "client_next_step": (
                    "Add clear timeouts on every API call, cap retries, quarantine bad inputs for review, and alert your team when errors spike."
                ),
            }
        )

    if "unstructured_pdf_or_doc_mess" in symptom_set or stage_stats["has_doc_intake_stage"]:
        top_findings.append(
            {
                "id": "PR-05",
                "severity": "MODERATE",
                "title": "Messy PDFs, Scans, or Email Attachments Break Downstream Steps",
                "detail": (
                    "Incoming PDFs, tables, or attachments are read directly inside a long prompt without first checking whether all required fields were extracted cleanly."
                ),
                "client_next_step": (
                    "Separate document reading into its own first step with required field checks, and send unreadable scans to a person before running business rules."
                ),
            }
        )

    if "overprivileged_db_or_pii_leak" in symptom_set:
        top_findings.append(
            {
                "id": "PR-06",
                "severity": "HIGH",
                "title": "AI Connects With Broad Database Rights or Unmasked Private Info",
                "detail": (
                    "The pilot uses read/write database logins or sees raw private customer/staff fields it does not need, blocking security approval."
                ),
                "client_next_step": (
                    "Switch the AI to a restricted read-only login with masked private columns, and handle any database writes in standard tested code."
                ),
            }
        )

    if not top_findings:
        top_findings.append(
            {
                "id": "PR-00",
                "severity": "LOW",
                "title": "Core Safeguards Are in Place",
                "detail": (
                    "Format checks, clean lookup views, human review queues, and step-by-step error logs are already active."
                ),
                "client_next_step": (
                    "Save a set of past tricky examples as an automated test check before rolling out updates."
                ),
            }
        )

    safe_to_deploy_checklist = [
        {
            "step": 1,
            "category": "Saved Test Cases",
            "item": "Save 25–50 real-world tricky examples so you can test changes automatically before going live.",
            "status": "READY" if trace_stats["trace_count"] >= 20 else "ACTION_REQUIRED",
        },
        {
            "step": 2,
            "category": "Strict Output Format",
            "item": "Require every AI step to return a strict, predictable data format (JSON schema) instead of loose text.",
            "status": (
                "READY"
                if inputs["output_validation"] in {"json_schema_no_critic", "schema_plus_deterministic_critic"}
                and stage_stats["missing_schema_count"] == 0
                else "ACTION_REQUIRED"
            ),
        },
        {
            "step": 3,
            "category": "Code Fact-Check",
            "item": "Check AI-generated IDs, product codes, math, and quotes in regular code against your source records before acting.",
            "status": (
                "READY"
                if inputs["output_validation"] == "schema_plus_deterministic_critic" and stage_stats["unverified_hops"] == 0
                else "ACTION_REQUIRED"
            ),
        },
        {
            "step": 4,
            "category": "Clean Lookup Data",
            "item": "Confirm unique IDs, up-to-date timestamps, and clean read-only views on all databases and document folders.",
            "status": "READY" if inputs["retrieval_hygiene"] == "governed_freshness_and_pk" else "ACTION_REQUIRED",
        },
        {
            "step": 5,
            "category": "Human Review Queue",
            "item": "Send uncertain answers and failed checks to a simple human approve/reject queue instead of failing silently.",
            "status": "READY" if inputs["human_in_the_loop"] == "confidence_gated_queue" else "ACTION_REQUIRED",
        },
        {
            "step": 6,
            "category": "Timeouts & Retry Caps",
            "item": "Set clear time limits and retry caps on every AI and webhook call, with alerts if errors spike.",
            "status": "READY" if inputs["observability_and_retries"] == "traced_bounded_sla_alerted" else "ACTION_REQUIRED",
        },
    ]

    # Emit only registered diagnostic signal keys
    candidate_signals: List[str] = []
    if (
        inputs["output_validation"] != "schema_plus_deterministic_critic"
        or "hallucinated_facts_or_numbers" in symptom_set
        or "breaks_on_edge_cases" in symptom_set
        or trace_stats["ungrounded_count"] > 0
        or stage_stats["unverified_hops"] > 0
    ):
        candidate_signals.append("hallucination_or_ungrounded_output")

    if (
        inputs["retrieval_hygiene"] in {"raw_docs_or_uncleaned_db", "basic_chunking_stale_sync"}
        or "bad_rag_or_stale_data" in symptom_set
        or trace_stats["rag_or_schema_failures"] > 0
        or stage_stats["has_raw_db_or_rag_stage"]
    ):
        candidate_signals.append("broken_rag_schema_or_data_hygiene")

    if (
        inputs["human_in_the_loop"] != "confidence_gated_queue"
        or inputs["observability_and_retries"] != "traced_bounded_sla_alerted"
        or "silent_production_errors" in symptom_set
        or trace_stats["unhandled_count"] > 0
        or stage_stats["missing_fallback_count"] > 0
    ):
        candidate_signals.append("missing_observability_or_hitl")

    if "unstructured_pdf_or_doc_mess" in symptom_set:
        candidate_signals.append("unstructured_pdf_or_doc_intake")

    if "overprivileged_db_or_pii_leak" in symptom_set:
        candidate_signals.append("overprivileged_agent_or_db_roles")
        candidate_signals.append("unclassified_pii_or_secrets")

    routing_signals = [sig for sig in candidate_signals if sig in SIGNAL_ROUTING_RULES]

    return {
        "capsule_version": CAPSULE_VERSION,
        "niche_id": NICHE_ID,
        "niche_slug": NICHE_SLUG,
        "niche_title": NICHE_TITLE,
        "mode": mode if mode in {"production", "demo"} else "production",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "prospect": prospect,
        "inputs": inputs,
        "client_assessment": {
            "headline_score": headline_score,
            "score_label": score_label,
            "severity_tier": severity_tier,
            "estimated_sprint_days": estimated_sprint_days,
            "key_metrics": key_metrics,
            "failure_taxonomy": failure_taxonomy,
            "top_findings": top_findings,
            "safe_to_deploy_checklist": safe_to_deploy_checklist,
        },
        "routing_signals": routing_signals,
    }


def _inspect_code_file(content: str, rel_path: str, ext: str) -> Dict[str, Any]:
    lines = content.splitlines()
    active_lines: List[str] = []
    llm_sites: List[Dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        is_comment = (stripped.startswith("#") if ext == ".py" else stripped.startswith("//"))
        if is_comment:
            continue
        active_lines.append(line)
        for label, pat in LLM_CALL_PATTERNS:
            if pat.search(line):
                llm_sites.append({"line": idx, "kind": label})
                break

    active_code = "\n".join(active_lines)
    has_schema = bool(SCHEMA_GUARD_PATTERN.search(active_code))
    has_fragile_parse = bool(FRAGILE_PARSE_PATTERN.search(active_code))
    has_timeout_or_retry = bool(TIMEOUT_RETRY_PATTERN.search(active_code))
    has_deterministic_check = bool(DETERMINISTIC_CHECK_PATTERN.search(active_code))
    has_fallback_queue = bool(FALLBACK_HANDLER_PATTERN.search(active_code))
    has_retrieval_calls = bool(RETRIEVAL_CALL_PATTERN.search(active_code))
    has_raw_sql_interp = bool(RAW_SQL_INTERP_PATTERN.search(active_code))

    silent_swallow = bool(
        SILENT_SWALLOW_PY_PATTERN.search(active_code) if ext == ".py" else SILENT_SWALLOW_JS_PATTERN.search(active_code)
    )
    has_try_catch = (
        ("try:" in active_code and "except" in active_code)
        if ext == ".py"
        else ("try" in active_code and "catch" in active_code)
    )

    risk = 0
    hotspots: List[str] = []
    fix_hints: List[str] = []

    if llm_sites:
        if not has_schema:
            risk += 28
            hotspots.append("No Pydantic/Zod Schema")
            fix_hints.append("Enforce typed structured output (Pydantic BaseModel / Zod / JSON Schema) on LLM responses.")
        if has_fragile_parse and not has_schema:
            risk += 14
            hotspots.append("Fragile JSON/Regex Parse")
            fix_hints.append("Replace raw json.loads / JSON.parse / regex extraction with schema-validated structured outputs.")
        if not has_deterministic_check:
            risk += 20
            hotspots.append("No Deterministic Critic")
            fix_hints.append("Add a deterministic verification step checking IDs, numbers, and source grounding before downstream calls.")
        if not has_timeout_or_retry:
            risk += 18
            hotspots.append("Missing Timeout / Bounded Retry")
            fix_hints.append("Set explicit request timeouts and bounded exponential backoff on every model/webhook call.")
        if not has_fallback_queue:
            risk += 10
            hotspots.append("No HITL Escalation Fallback")
            fix_hints.append("Route validation failures or low-confidence responses into a human review/dead-letter queue.")

    if silent_swallow:
        risk += 18
        hotspots.append("Silent Exception Swallow")
        fix_hints.append("Eliminate bare except/pass or console-only catch blocks that hide runtime failures.")

    if has_retrieval_calls and has_raw_sql_interp:
        risk += 22
        hotspots.append("Uncleaned SELECT * / Interpolated SQL")
        fix_hints.append("Replace SELECT * and string-interpolated SQL with parameterized, primary-key-deduped read views.")
    elif has_retrieval_calls and not has_deterministic_check:
        risk += 10
        hotspots.append("Unverified RAG / Vector Lookup")
        fix_hints.append("Filter retrieved chunks by freshness metadata and verify grounding after synthesis.")

    risk = min(100, risk)
    if risk >= 70:
        severity = "CRITICAL"
    elif risk >= 45:
        severity = "HIGH"
    elif risk >= 20:
        severity = "MODERATE"
    else:
        severity = "LOW"

    return {
        "path": rel_path,
        "file_type": "code",
        "extension": ext,
        "line_count": len(lines),
        "llm_call_count": len(llm_sites),
        "llm_call_sites": llm_sites[:15],
        "guards": {
            "schema_validation": has_schema,
            "timeouts_or_retries": has_timeout_or_retry,
            "deterministic_verification": has_deterministic_check,
            "error_handler_present": has_try_catch and not silent_swallow,
            "human_fallback_queue": has_fallback_queue,
        },
        "retrieval_detected": has_retrieval_calls,
        "raw_sql_or_select_star": has_raw_sql_interp,
        "fragile_json_parse": has_fragile_parse,
        "silent_exception_swallow": silent_swallow,
        "fragility_score": risk,
        "severity": severity,
        "hotspots": hotspots,
        "fix_hints": fix_hints,
    }


def _extract_trace_records_from_data(content: str, rel_path: str, ext: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Inspect .json or .jsonl trace/log files safely without retaining prompt/message strings."""
    records: List[Dict[str, Any]] = []
    if ext == ".jsonl":
        for line in content.splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError:
                continue
    else:
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                records = [x for x in parsed if isinstance(x, dict)]
            elif isinstance(parsed, dict):
                for key in ("traces", "events", "runs", "spans", "items", "logs"):
                    if isinstance(parsed.get(key), list):
                        records = [x for x in parsed[key] if isinstance(x, dict)]
                        break
        except json.JSONDecodeError:
            records = []

    trace_like_keys = {
        "trace_id",
        "span_id",
        "run_id",
        "step_name",
        "latency_ms",
        "duration_ms",
        "failure_type",
        "grounded_in_source",
        "finish_reason",
        "error",
    }
    valid_traces: List[Dict[str, Any]] = []
    for idx, rec in enumerate(records, start=1):
        if not (set(rec.keys()) & trace_like_keys):
            continue
        tid = str(rec.get("trace_id") or rec.get("run_id") or rec.get("span_id") or f"SCAN-{idx}")[:40]
        step = str(rec.get("step_name") or rec.get("step") or rec.get("stage") or rec.get("name") or Path(rel_path).stem)[:48]
        status_str = str(rec.get("status") or "").lower()
        err_val = rec.get("failure_type") or rec.get("error_type") or ("runtime_error" if rec.get("error") else "")
        if not err_val and status_str in {"error", "failed", "timeout"}:
            err_val = status_str
        failure_type = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(err_val or "none").lower())[:40] or "none"

        grounded_raw = rec.get("grounded_in_source", rec.get("grounded", True))
        grounded = _norm_bool(grounded_raw, default=True)
        handled_raw = rec.get("handled_gracefully", rec.get("handled", failure_type in HEALTHY_FAILURE_TYPES))
        handled = _norm_bool(handled_raw, default=(failure_type in HEALTHY_FAILURE_TYPES))

        lat_raw = rec.get("latency_ms", rec.get("duration_ms", 0))
        try:
            latency_ms = int(float(lat_raw or 0))
        except (TypeError, ValueError):
            latency_ms = 0

        valid_traces.append(
            {
                "trace_id": tid,
                "step_name": step,
                "failure_type": failure_type,
                "grounded_in_source": grounded,
                "latency_ms": latency_ms,
                "handled_gracefully": handled,
            }
        )

    total = len(valid_traces)
    failed = sum(1 for r in valid_traces if r["failure_type"] not in HEALTHY_FAILURE_TYPES or not r["grounded_in_source"])
    ungrounded = sum(1 for r in valid_traces if not r["grounded_in_source"])
    high_lat = sum(1 for r in valid_traces if r["latency_ms"] >= 5000)

    risk = 0
    hotspots: List[str] = []
    if total > 0:
        err_pct = round(100.0 * failed / total)
        if err_pct >= 25:
            risk += 55
            hotspots.append(f"{err_pct}% Trace Failure Rate ({failed}/{total})")
        elif failed > 0:
            risk += 25
            hotspots.append(f"{failed} Failed Trace(s)")
        if ungrounded > 0:
            risk += 25
            hotspots.append(f"{ungrounded} Ungrounded Output(s)")
        if high_lat > 0:
            risk += 15
            hotspots.append(f"{high_lat} Slow/Timeout Trace(s) >=5s")

    risk = min(100, risk)
    severity = "CRITICAL" if risk >= 70 else ("HIGH" if risk >= 45 else ("MODERATE" if risk >= 20 else "LOW"))

    file_report = {
        "path": rel_path,
        "file_type": "trace_data",
        "extension": ext,
        "line_count": len(content.splitlines()),
        "trace_records_found": total,
        "failed_traces": failed,
        "ungrounded_traces": ungrounded,
        "high_latency_traces": high_lat,
        "fragility_score": risk,
        "severity": severity,
        "hotspots": hotspots,
        "fix_hints": (
            ["Replay these captured failure traces automatically as a Day-1 golden regression benchmark."]
            if failed > 0
            else []
        ),
    }
    return file_report, valid_traces


def scan_local_directory(path: str, max_files: int = 400) -> Dict[str, Any]:
    """Read-only structural scan of a local AI pilot directory or file.

    Inspects `.py`, `.ts`, `.js`, `.mjs`, `.json`, `.jsonl` files locally to map LLM call sites,
    schema validation, timeouts/retries, deterministic checks, error handlers, and trace logs.
    Never captures or outputs raw prompt text, secrets, or source code snippets.
    """
    raw_path = (path or "").strip()
    if not raw_path:
        raise ValueError("Please provide a local directory or file path to scan.")

    target = Path(raw_path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Local path not found: {target}")

    root_dir = target if target.is_dir() else target.parent
    candidate_files: List[Path] = []

    if target.is_file():
        if target.suffix.lower() in (CODE_EXTENSIONS | DATA_EXTENSIONS):
            candidate_files.append(target)
    else:
        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in (CODE_EXTENSIONS | DATA_EXTENSIONS):
                    candidate_files.append(fpath)
                    if len(candidate_files) >= max_files:
                        break
            if len(candidate_files) >= max_files:
                break

    code_files: List[Dict[str, Any]] = []
    trace_files: List[Dict[str, Any]] = []
    collected_traces: List[Dict[str, Any]] = []

    for fpath in candidate_files:
        ext = fpath.suffix.lower()
        try:
            if fpath.stat().st_size > 2_000_000:
                continue
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(fpath.relative_to(root_dir)).replace("\\", "/")
        if ext in CODE_EXTENSIONS:
            code_files.append(_inspect_code_file(content, rel_path, ext))
        elif ext in DATA_EXTENSIONS:
            f_rep, traces = _extract_trace_records_from_data(content, rel_path, ext)
            if f_rep["trace_records_found"] > 0:
                trace_files.append(f_rep)
                collected_traces.extend(traces)

    relevant_code = [
        f
        for f in code_files
        if f["llm_call_count"] > 0 or f["retrieval_detected"] or f["fragility_score"] > 0
    ]
    all_inspected = sorted(
        relevant_code + trace_files,
        key=lambda x: (-x["fragility_score"], x["path"]),
    )
    other_clean_code = [f for f in code_files if f not in relevant_code]

    total_llm_calls = sum(f["llm_call_count"] for f in code_files)
    llm_files = [f for f in code_files if f["llm_call_count"] > 0]
    unguarded_schema_files = [f for f in llm_files if not f["guards"]["schema_validation"]]
    unguarded_timeout_files = [f for f in llm_files if not f["guards"]["timeouts_or_retries"]]
    unguarded_critic_files = [f for f in llm_files if not f["guards"]["deterministic_verification"]]
    silent_swallow_files = [f for f in code_files if f["silent_exception_swallow"]]
    raw_sql_files = [f for f in code_files if f["raw_sql_or_select_star"]]

    # Synthesize sanitized stage & trace CSVs so user can populate the assessment with 1 click
    stage_rows = ["stage_order,stage_name,input_source,has_json_schema,has_deterministic_check,has_human_fallback"]
    workflow_stage_candidates = [f for f in code_files if f["llm_call_count"] > 0 or f["retrieval_detected"]]
    for idx, cf in enumerate(workflow_stage_candidates[:12], start=1):
        sname = re.sub(r"[^a-zA-Z0-9_.-]", "_", Path(cf["path"]).stem)[:40]
        src = (
            "raw_sql_and_vector_store"
            if cf["raw_sql_or_select_star"]
            else ("vector_or_db_lookup" if cf["retrieval_detected"] else "llm_prompt_step")
        )
        g = cf["guards"]
        stage_rows.append(
            f"{idx},{sname},{src},{str(g['schema_validation']).lower()},"
            f"{str(g['deterministic_verification']).lower()},{str(g['human_fallback_queue']).lower()}"
        )
    synthesized_stages_csv = "\n".join(stage_rows) if len(stage_rows) > 1 else ""

    trace_rows = ["trace_id,step_name,failure_type,grounded_in_source,latency_ms,handled_gracefully"]
    for tr in collected_traces[:100]:
        trace_rows.append(
            f"{tr['trace_id']},{tr['step_name']},{tr['failure_type']},"
            f"{str(tr['grounded_in_source']).lower()},{tr['latency_ms']},{str(tr['handled_gracefully']).lower()}"
        )
    synthesized_traces_csv = "\n".join(trace_rows) if len(trace_rows) > 1 else ""

    # Infer suggested form inputs from structural scan
    inferred_symptoms: List[str] = []
    if unguarded_critic_files or any(not t["grounded_in_source"] for t in collected_traces):
        inferred_symptoms.append("hallucinated_facts_or_numbers")
    if unguarded_schema_files or any(f["fragile_json_parse"] for f in code_files):
        inferred_symptoms.append("breaks_on_edge_cases")
    if raw_sql_files or any(f["retrieval_detected"] for f in code_files):
        inferred_symptoms.append("bad_rag_or_stale_data")
    if unguarded_timeout_files or silent_swallow_files:
        inferred_symptoms.append("silent_production_errors")

    if llm_files and all(f["guards"]["schema_validation"] and f["guards"]["deterministic_verification"] for f in llm_files):
        suggested_validation = "schema_plus_deterministic_critic"
    elif llm_files and all(f["guards"]["schema_validation"] for f in llm_files):
        suggested_validation = "json_schema_no_critic"
    elif any(f["fragile_json_parse"] for f in llm_files):
        suggested_validation = "free_text_or_regex_only"
    else:
        suggested_validation = "none_raw_completion" if llm_files else "free_text_or_regex_only"

    suggested_retrieval = (
        "raw_docs_or_uncleaned_db"
        if raw_sql_files
        else ("basic_chunking_stale_sync" if any(f["retrieval_detected"] for f in code_files) else "curated_views_partial_lineage")
    )
    suggested_hitl = (
        "confidence_gated_queue"
        if (llm_files and all(f["guards"]["human_fallback_queue"] for f in llm_files))
        else "none_all_or_nothing"
    )
    suggested_obs = (
        "traced_bounded_sla_alerted"
        if (llm_files and not unguarded_timeout_files and not silent_swallow_files)
        else "console_logs_only"
    )

    return {
        "scanned_root": str(root_dir),
        "scanned_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "zero_prompt_capture": True,
        "summary": {
            "files_scanned": len(code_files) + len(trace_files),
            "code_files_scanned": len(code_files),
            "trace_files_scanned": len(trace_files),
            "total_llm_call_sites": total_llm_calls,
            "files_missing_schema": len(unguarded_schema_files),
            "files_missing_timeouts": len(unguarded_timeout_files),
            "files_missing_critic": len(unguarded_critic_files),
            "files_with_silent_swallow": len(silent_swallow_files),
            "trace_events_parsed": len(collected_traces),
        },
        "files": all_inspected + other_clean_code[:20],
        "suggested_inputs": {
            "workflow_name": f"{root_dir.name} AI Workflow",
            "current_stage": "stalled_internal_pilot",
            "failure_symptoms": inferred_symptoms,
            "output_validation": suggested_validation,
            "retrieval_hygiene": suggested_retrieval,
            "human_in_the_loop": suggested_hitl,
            "observability_and_retries": suggested_obs,
            "stages_csv_text": synthesized_stages_csv,
            "traces_csv_text": synthesized_traces_csv,
        },
    }


def render_markdown_report(capsule: Dict[str, Any]) -> str:
    """Render a printable Hardened Workflow Rescue Blueprint (client-safe by default)."""
    prospect = capsule.get("prospect") or {}
    inputs = capsule.get("inputs") or {}
    ca = capsule.get("client_assessment") or {}

    org_label = prospect.get("company_name") or "Local Engineering Workspace"
    lines: List[str] = [
        f"# Hardened AI Workflow Rescue Blueprint: {inputs.get('workflow_name', 'AI Workflow')}",
        "",
        f"- **Workspace / Organization:** {org_label}",
        f"- **Generated At:** {capsule.get('generated_at', '')}",
        f"- **Assessment Mode:** `{capsule.get('mode', 'production')}`",
        f"- **Headline Score:** **{ca.get('score_label', '')}**",
        f"- **Severity Tier:** `{ca.get('severity_tier', '')}` | **Estimated Cutover Window:** `{ca.get('estimated_sprint_days', '')}`",
        "",
        "## 1. Key Diagnostic Metrics",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
    ]
    for m in ca.get("key_metrics") or []:
        lines.append(f"| {m.get('label', '')} | **{m.get('value', '')}** |")

    if ca.get("failure_taxonomy"):
        lines.extend(
            [
                "",
                "## 2. Failure-Mode Risk Breakdown",
                "",
                "| Failure Axis | Risk Contribution | Status |",
                "| :--- | :--- | :--- |",
            ]
        )
        for ax in ca["failure_taxonomy"]:
            lines.append(f"| {ax['axis']} | `{ax['risk_points']} / {ax['max_points']}` | **{ax['status']}** |")

    lines.extend(["", "## 3. Root-Cause Findings & Architectural Fixes", ""])
    for idx, f in enumerate(ca.get("top_findings") or [], start=1):
        lines.extend(
            [
                f"### {idx}. [{f.get('severity', 'INFO')}] {f.get('title', '')} (`{f.get('id', '')}`)",
                f"- **Why It Breaks:** {f.get('detail', '')}",
                f"- **Engineering Remediation:** {f.get('client_next_step', '')}",
                "",
            ]
        )

    lines.extend(
        [
            "## 4. Safe-to-Deploy Rescue Checklist (1–2 Week Plan)",
            "",
            "| Step | Category | Status | Action Item |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )
    for item in ca.get("safe_to_deploy_checklist") or []:
        lines.append(
            f"| {item.get('step')} | **{item.get('category')}** | `{item.get('status')}` | {item.get('item')} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "> **Fixing it in-house?** Everything above is yours to keep. "
            "Want us to harden and ship this workflow (typically 2–3 weeks, scoped upfront)? Export a sanitized structural capsule "
            "(`varinull-capsule-sprint3.json`, zero prompts or proprietary source code) if you decide to call VARINULL.",
        ]
    )

    return "\n".join(lines).strip() + "\n"
