from __future__ import annotations

from pathlib import Path

from app.agents.incident_response_agent import IncidentResponseAgent
from app.llm.providers import LLMResult
from scripts.run_pipeline import OutputPaths, permission_gate, run_pipeline


ROOT = Path(__file__).resolve().parents[1]
PI_DIR = ROOT / ".pi"


class OfflineProvider:
    provider_name = "offline-test"
    model = "offline"

    def generate_json(self, prompt: str, response_schema: dict):
        return LLMResult(
            available=False,
            provider=self.provider_name,
            model=self.model,
            fallback_reason="offline test provider",
        )


def test_agent_prompt_includes_pi_assets_and_incident_context() -> None:
    agent = IncidentResponseAgent(PI_DIR, provider=OfflineProvider())
    prompt = agent.build_prompt(
        {
            "alert": {"alert_id": "ALERT-TEST-001"},
            "stage_1": {"logs": {"findings": []}},
            "classification": {"label": "Web Attack", "severity": "high", "confidence": 0.9},
            "mitre_attack": [],
            "containment_actions": ["simulate_notify_admin"],
        }
    )

    assert "System Prompt - Incident Response Orchestrator" in prompt
    assert "network-ir-orchestration" in prompt
    assert "ALERT-TEST-001" in prompt
    assert "required_json_schema" in prompt


def test_pipeline_uses_llm_fallback_and_writes_to_output_dir(tmp_path) -> None:
    agent = IncidentResponseAgent(PI_DIR, provider=OfflineProvider())

    triage = run_pipeline(
        PI_DIR / "data" / "sample_alert.json",
        output_dir=tmp_path,
        agent=agent,
    )

    assert triage["classification"]["label"] == "Web Attack"
    assert triage["mitre_attack"]
    assert triage["containment"]["permission_gate"]
    assert triage["llm_analysis"]["available"] is False
    assert triage["llm_analysis"]["provider"] == "offline-test"
    assert (tmp_path / "triage" / "incident_triage.json").exists()
    assert (tmp_path / "reports" / "ket_qua.md").exists()


def test_permission_gate_blocks_real_actions(tmp_path) -> None:
    decisions = permission_gate(
        ["block_ip", "simulate_notify_admin"],
        OutputPaths.from_base(tmp_path),
    )

    assert decisions[0]["decision"] == "blocked"
    assert decisions[1]["decision"] == "allowed"
