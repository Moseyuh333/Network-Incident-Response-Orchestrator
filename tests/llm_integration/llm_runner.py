"""Shared helper that calls the IncidentResponseAgent for a scenario.

Encapsulates the boilerplate (instantiate the agent, build the context,
time the call, parse the result) so the runner can stay focused on
assertions.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.agents.incident_response_agent import IncidentResponseAgent
from app.core.config import Settings
from app.core.paths import PI_DIR
from app.llm.providers import GoogleGenAIProvider
from app.schemas.incident import LLMOutputSchema


@dataclass
class LLMAnalysis:
    """Result of asking the LLM to analyse one incident context."""

    available: bool
    latency_seconds: float
    provider: str
    model: str
    fallback_reason: str | None
    parsed: LLMOutputSchema | None
    raw_text: str
    error: str | None = None
    assertions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "latency_seconds": round(self.latency_seconds, 3),
            "provider": self.provider,
            "model": self.model,
            "fallback_reason": self.fallback_reason,
            "error": self.error,
            "parsed": self.parsed.model_dump() if self.parsed else None,
            "raw_text_preview": self.raw_text[:1000] if self.raw_text else "",
            "raw_text_len": len(self.raw_text),
            "assertions": self.assertions,
        }


def _build_context(scenario_id: str, expected_type: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Build the same context shape the agent would see in production.

    The full pipeline passes in a much richer context (events, findings,
    related incidents). For unit-test purposes we keep it minimal but
    faithful to the fields the prompt actually references.
    """
    return {
        "task": f"Analyse the {expected_type} incident and recommend safe response actions.",
        "selected_skill": {"id": expected_type.lower().replace(" ", "_"), "name": expected_type},
        "available_tools": [
            {"name": "get_incident"},
            {"name": "list_findings"},
            {"name": "propose_response_action"},
        ],
        "tool_results": {},
        "classification": {
            "label": expected_type,
            "severity": evidence.get("severity", "medium"),
            "confidence": evidence.get("confidence", 0.5),
        },
        "incident": evidence,
        "mitre_attack": [],
        "containment_actions": [],
    }


def _make_provider_with_bigger_budget(provider: GoogleGenAIProvider) -> GoogleGenAIProvider:
    """Return a copy of *provider* with a higher max_output_tokens budget.

    The default ``LLM_MAX_TOKENS=1024`` in the project's .env is too tight for
    the full LLMOutputSchema (summary + incident_type + severity + confidence
    + reasoning + MITRE list + recommended_actions + report). 1024 tokens
    reliably truncates the JSON mid-string, which fails schema validation.

    For tests only, raise the budget so we exercise the full happy path.
    """
    boosted = GoogleGenAIProvider(Settings(
        llm_provider=provider.config.llm_provider,
        llm_api_key=provider.config.llm_api_key,
        google_api_key=provider.config.google_api_key,
        llm_model=provider.config.llm_model,
        llm_max_tokens=4096,
    ))
    return boosted


def run_llm_for_scenario(
    scenario_id: str,
    expected_type: str,
    evidence: dict[str, Any],
    *,
    provider: GoogleGenAIProvider | None = None,
    pi_dir: Path = PI_DIR,
) -> LLMAnalysis:
    """Run the LLM agent over a single scenario's evidence and return the result.

    Always returns an `LLMAnalysis`; never raises. If the LLM call fails
    (network, 503, schema validation) the failure is recorded on the
    returned object so the runner can still print something useful.
    """
    provider = provider or GoogleGenAIProvider()
    # Use a higher max_output_tokens budget so the full LLMOutputSchema fits
    # in one response. See ``_make_provider_with_bigger_budget`` for why.
    provider = _make_provider_with_bigger_budget(provider)
    agent = IncidentResponseAgent(pi_dir, provider=provider)
    context = _build_context(scenario_id, expected_type, evidence)
    started = time.monotonic()
    try:
        result = agent.analyze(context)
    except Exception as exc:
        return LLMAnalysis(
            available=False,
            latency_seconds=time.monotonic() - started,
            provider=provider.provider_name,
            model=provider.model,
            fallback_reason=None,
            parsed=None,
            raw_text="",
            error=f"{type(exc).__name__}: {exc}",
        )
    latency = time.monotonic() - started

    # ``agent.analyze`` already parses the LLM JSON internally and returns
    # the structured fields directly (summary, incident_type, severity,
    # confidence, reasoning_summary, mitre_mapping, recommended_actions,
    # report). There is no ``text`` key. Build an LLMOutputSchema from
    # those fields so the test assertions have something to inspect.
    parsed: LLMOutputSchema | None = None
    if result.get("available"):
        try:
            parsed = LLMOutputSchema.model_validate({
                "summary": result.get("summary", ""),
                "incident_type": result.get("incident_type", ""),
                "severity": result.get("severity", "medium"),
                "confidence": result.get("confidence", 0.0),
                "reasoning_summary": result.get("reasoning_summary", ""),
                "mitre_mapping": result.get("mitre_mapping", []),
                "recommended_actions": result.get("recommended_actions", []),
                "report": result.get("report", ""),
            })
        except ValidationError as exc:
            return LLMAnalysis(
                available=True,
                latency_seconds=latency,
                provider=result.get("provider", ""),
                model=result.get("model", ""),
                fallback_reason=result.get("fallback_reason"),
                parsed=None,
                raw_text=json.dumps({k: v for k, v in result.items() if k != "available"}, default=str),
                error=f"LLMOutputSchema validation: {exc}",
            )
        except Exception as exc:
            return LLMAnalysis(
                available=True,
                latency_seconds=latency,
                provider=result.get("provider", ""),
                model=result.get("model", ""),
                fallback_reason=result.get("fallback_reason"),
                parsed=None,
                raw_text=json.dumps({k: v for k, v in result.items() if k != "available"}, default=str),
                error=f"Parse error ({type(exc).__name__}): {exc}",
            )

    return LLMAnalysis(
        available=result.get("available", False),
        latency_seconds=latency,
        provider=result.get("provider", ""),
        model=result.get("model", ""),
        fallback_reason=result.get("fallback_reason"),
        parsed=parsed,
        raw_text=json.dumps({k: v for k, v in result.items() if k != "available"}, default=str),
    )
