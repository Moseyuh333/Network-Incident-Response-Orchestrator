"""Agent runtime for LLM-assisted network incident response."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.llm.providers import GoogleGenAIProvider
from app.schemas.incident import LLMOutputSchema


class IncidentResponseAgent:
    """Load Pi agent assets, ask an LLM for structured triage, and fallback safely."""

    def __init__(
        self,
        pi_dir: Path,
        provider: GoogleGenAIProvider | None = None,
    ) -> None:
        self.pi_dir = pi_dir
        self.provider = provider or GoogleGenAIProvider()

    def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        """Return normalized LLM analysis for a pipeline context."""
        prompt = self.build_prompt(context)
        result = self.provider.generate_json(prompt, LLMOutputSchema.model_json_schema())
        if result.available and result.text:
            try:
                parsed = LLMOutputSchema.model_validate_json(result.text)
                return {
                    "available": True,
                    "provider": result.provider,
                    "model": result.model,
                    **parsed.model_dump(),
                }
            except (ValidationError, ValueError) as exc:
                return self._fallback_analysis(
                    context,
                    provider=result.provider,
                    model=result.model,
                    reason=f"LLM returned invalid JSON: {exc}",
                )
        return self._fallback_analysis(
            context,
            provider=result.provider,
            model=result.model,
            reason=result.fallback_reason or "LLM response was empty",
        )

    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build the agent prompt from Pi assets and incident evidence."""
        sections = {
            "system_prompt": self._read_asset("prompts/system_prompt.md"),
            "agent_contract": self._read_asset("agents/agent.md"),
            "skill": self._read_asset("skills/SKILL.md"),
            "chain": self._read_asset("chains/chain.md"),
            "incident_context": json.dumps(context, indent=2, ensure_ascii=False, default=str),
            "required_json_schema": json.dumps(
                LLMOutputSchema.model_json_schema(),
                indent=2,
                ensure_ascii=False,
            ),
        }
        return "\n\n".join(f"## {name}\n{body}" for name, body in sections.items())

    def _read_asset(self, relative_path: str) -> str:
        path = self.pi_dir / relative_path
        if not path.exists():
            return f"(Asset {relative_path} not found)"
        return path.read_text(encoding="utf-8")


    @staticmethod
    def _fallback_analysis(
        context: dict[str, Any],
        provider: str,
        model: str,
        reason: str,
    ) -> dict[str, Any]:
        classification = context["classification"]
        mitre = context.get("mitre_attack", [])
        actions = context.get("containment_actions", [])
        label = classification["label"]
        severity = classification["severity"]
        confidence = classification["confidence"]
        summary = f"{label} incident assessed at {severity} severity with {confidence} confidence."
        report = "\n".join(
            [
                "# LLM Fallback Incident Analysis",
                "",
                summary,
                "",
                "The automated rule pipeline produced this analysis because the LLM provider was unavailable.",
            ]
        )
        return {
            "available": False,
            "provider": provider,
            "model": model,
            "fallback_reason": reason,
            "summary": summary,
            "incident_type": label,
            "severity": severity,
            "confidence": confidence,
            "reasoning_summary": "Rule-based fallback used existing findings, MITRE mapping, and safe containment actions.",
            "mitre_mapping": [
                {
                    "tactic": item.get("tactic", ""),
                    "technique": item.get("name", ""),
                    "technique_id": item.get("technique", ""),
                }
                for item in mitre
            ],
            "recommended_actions": [
                {"action": action, "risk": "low", "requires_human_approval": True}
                for action in actions
            ],
            "report": report,
        }
