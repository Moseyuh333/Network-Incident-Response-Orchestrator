"""Bounded tool runtime for incident response agents."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlmodel import Session, select

from app.models.event import Event
from app.models.incident import AgentRun, Finding, Incident, ResponseAction, ToolCall
from app.services.actions import propose_action
from app.services.ingestion import _jsonable


class AgentToolRuntime:
    """Execute allowlisted agent tools and persist every call."""

    def __init__(self, session: Session, allowed_tools: list[str] | None = None) -> None:
        self.session = session
        self.allowed_tools = set(allowed_tools or self.default_tool_names())
        self._tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "get_incident": self._get_incident,
            "list_related_events": self._list_related_events,
            "list_findings": self._list_findings,
            "list_actions": self._list_actions,
            "propose_response_action": self._propose_response_action,
        }

    @staticmethod
    def default_tool_names() -> list[str]:
        return [
            "get_incident",
            "list_related_events",
            "list_findings",
            "list_actions",
            "propose_response_action",
        ]

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "risk_level": "low" if name == "propose_response_action" else "read_only",
                "approval_required": name == "propose_response_action",
            }
            for name in self.default_tool_names()
            if name in self.allowed_tools
        ]

    def call(self, agent_run: AgentRun, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if agent_run.id is None:
            raise ValueError("agent run must be persisted before tool execution")
        risk = "low" if tool_name == "propose_response_action" else "read_only"
        approval_required = tool_name == "propose_response_action"
        call = ToolCall(
            agent_run_id=agent_run.id,
            tool_name=tool_name,
            sanitized_arguments=_jsonable(arguments),
            risk_level=risk,
            approval_required=approval_required,
        )
        self.session.add(call)
        self.session.commit()
        self.session.refresh(call)

        try:
            if tool_name not in self.allowed_tools:
                raise ValueError(f"tool {tool_name!r} is not allowed for this skill")
            if tool_name not in self._tools:
                raise ValueError(f"unknown tool {tool_name!r}")
            result = self._tools[tool_name](arguments)
            call.status = "completed"
            call.result_summary = _summarize_result(result)
            call.ended_at = datetime.utcnow()
            self.session.add(call)
            self.session.commit()
            return result
        except Exception as exc:
            call.status = "failed"
            call.error = str(exc)
            call.ended_at = datetime.utcnow()
            self.session.add(call)
            self.session.commit()
            raise

    def _get_incident(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident = self._incident(arguments)
        return _jsonable(incident.model_dump())

    def _list_related_events(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident = self._incident(arguments)
        statement = select(Event).order_by(Event.timestamp.desc()).limit(int(arguments.get("limit", 50)))
        filters = []
        if incident.source_ip:
            filters.append(Event.source_ip == incident.source_ip)
        if incident.destination_ip:
            filters.append(Event.destination_ip == incident.destination_ip)
        for item in filters:
            statement = statement.where(item)
        events = self.session.exec(statement).all()
        return {"events": [_jsonable(event.model_dump()) for event in events]}

    def _list_findings(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident = self._incident(arguments)
        findings = self.session.exec(
            select(Finding).where(Finding.incident_id == incident.id).order_by(Finding.created_at.desc())
        ).all()
        return {"findings": [_jsonable(finding.model_dump()) for finding in findings]}

    def _list_actions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident = self._incident(arguments)
        actions = self.session.exec(
            select(ResponseAction)
            .where(ResponseAction.incident_id == incident.id)
            .order_by(ResponseAction.created_at.desc())
        ).all()
        return {"actions": [_jsonable(action.model_dump()) for action in actions]}

    def _propose_response_action(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident = self._incident(arguments)
        action = propose_action(
            self.session,
            incident.id,
            str(arguments["action_type"]),
            arguments.get("arguments") or {},
            proposed_by="agent",
        )
        return {"action": _jsonable(action.model_dump())}

    def _incident(self, arguments: dict[str, Any]) -> Incident:
        incident_id = arguments.get("incident_id")
        if not isinstance(incident_id, int):
            raise ValueError("incident_id must be an integer")
        incident = self.session.get(Incident, incident_id)
        if incident is None:
            raise ValueError(f"incident {incident_id} not found")
        return incident


def _summarize_result(result: dict[str, Any]) -> str:
    if "events" in result:
        return f"{len(result['events'])} related events"
    if "findings" in result:
        return f"{len(result['findings'])} findings"
    if "actions" in result:
        return f"{len(result['actions'])} actions"
    if "action" in result:
        action = result["action"]
        return f"proposed action {action.get('id')} in state {action.get('status')}"
    return "completed"
