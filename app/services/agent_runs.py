"""Persistent agent run orchestration."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.agents.incident_response_agent import IncidentResponseAgent
from app.agents.tools import AgentToolRuntime
from app.core.json import jsonable
from app.models.incident import AgentRun, Incident
from app.services.ingestion import audit
from app.skills.registry import SkillRegistry


def run_agent_for_incident(
    session: Session,
    incident_id: int,
    task: str,
    pi_dir: Path,
    max_tool_calls: int | None = None,
) -> AgentRun:
    """Run a bounded incident response agent and persist the full run."""
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise ValueError(f"incident {incident_id} not found")

    skill_registry = SkillRegistry(pi_dir / "skills")
    skill = skill_registry.select(task, incident.incident_type)
    allowed_tools = skill.allowed_tools if skill and skill.allowed_tools else AgentToolRuntime.default_tool_names()
    call_budget = min(max_tool_calls or (skill.max_tool_calls if skill else 5), 10)

    agent_run = AgentRun(incident_id=incident.id, task=task)
    session.add(agent_run)
    session.commit()
    session.refresh(agent_run)

    runtime = AgentToolRuntime(session, allowed_tools)
    tool_results: dict[str, Any] = {}
    try:
        planned_calls = _planned_tool_calls(incident, task)
        for tool_name, arguments in planned_calls[:call_budget]:
            if tool_name not in allowed_tools:
                continue
            tool_results[tool_name] = runtime.call(agent_run, tool_name, arguments)

        analysis_context = _agent_context(incident, task, skill, runtime.list_tools(), tool_results)
        analysis = IncidentResponseAgent(pi_dir).analyze(analysis_context)
        before = incident.model_dump()
        incident.llm_summary = analysis.get("summary")
        incident.llm_report = analysis.get("report")
        incident.recommended_actions = analysis.get("recommended_actions") or incident.recommended_actions
        incident.mitre_mapping = analysis.get("mitre_mapping") or incident.mitre_mapping
        incident.updated_at = datetime.utcnow()
        session.add(incident)

        agent_run.provider = str(analysis.get("provider") or "")
        agent_run.model = str(analysis.get("model") or "")
        agent_run.status = "completed"
        agent_run.ended_at = datetime.utcnow()
        agent_run.final_response = json.dumps(jsonable(analysis), ensure_ascii=False)
        agent_run.usage_metadata = {
            "selected_skill": skill.id if skill else None,
            "tool_calls_planned": len(planned_calls),
            "tool_calls_budget": call_budget,
            "tool_results": {name: _summarize_tool_payload(payload) for name, payload in tool_results.items()},
        }
        session.add(agent_run)
        session.commit()
        session.refresh(agent_run)
        audit(session, "agent", "agent.run", "incident", incident.public_id, before, incident.model_dump())
        return agent_run
    except Exception as exc:
        agent_run.status = "failed"
        agent_run.error = str(exc)
        agent_run.ended_at = datetime.utcnow()
        session.add(agent_run)
        session.commit()
        raise


def _planned_tool_calls(incident: Incident, task: str) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = [
        ("get_incident", {"incident_id": incident.id}),
        ("list_findings", {"incident_id": incident.id}),
        ("list_related_events", {"incident_id": incident.id, "limit": 50}),
        ("list_actions", {"incident_id": incident.id}),
    ]
    task_text = task.lower()
    if any(term in task_text for term in ("contain", "block", "cach ly", "chan", "ngan chan")) and incident.source_ip:
        calls.append(
            (
                "propose_response_action",
                {
                    "incident_id": incident.id,
                    "action_type": "simulate_block_ip",
                    "arguments": {"ip": incident.source_ip},
                },
            )
        )
    return calls


def _agent_context(
    incident: Incident,
    task: str,
    skill: Any,
    tools: list[dict[str, Any]],
    tool_results: dict[str, Any],
) -> dict[str, Any]:
    return {
        "task": task,
        "selected_skill": skill.model_dump() if skill else None,
        "available_tools": tools,
        "tool_results": jsonable(tool_results),
        "classification": {
            "label": incident.incident_type,
            "severity": incident.severity,
            "confidence": incident.confidence,
        },
        "incident": jsonable(incident.model_dump()),
        "mitre_attack": incident.mitre_mapping or [],
        "containment_actions": incident.recommended_actions or [],
    }


def _summarize_tool_payload(payload: dict[str, Any]) -> Any:
    if "events" in payload:
        return {"events": len(payload["events"])}
    if "findings" in payload:
        return {"findings": len(payload["findings"])}
    if "actions" in payload:
        return {"actions": len(payload["actions"])}
    if "action" in payload:
        return {"action_id": payload["action"].get("id"), "status": payload["action"].get("status")}
    return "ok"
