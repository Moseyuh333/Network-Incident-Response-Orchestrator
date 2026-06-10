"""Versioned REST API for the Network IR Orchestrator."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlmodel import Session, func, select

from app.db.session import engine, get_session
from app.collectors.suricata import parse_eve_file
from app.collectors.zeek import parse_zeek_file
from app.incidents.lifecycle import transition_incident
from app.models.event import Event
from app.models.incident import AgentRun, AuditEntry, Finding, Incident, ResponseAction
from app.plugins.registry import PluginRegistry
from app.schemas.event import BulkEventsRequest, EventCreate, EventResponse
from app.services.actions import approve_action, execute_action, propose_action, rollback_action
from app.services.agent_runs import run_agent_for_incident
from app.core.paths import PI_DIR
from app.services.ingestion import ingest_event, process_events
from app.skills.registry import SkillRegistry

router = APIRouter(prefix="/api/v1", tags=["v1"])
skill_registry = SkillRegistry(PI_DIR / "skills")
plugin_registry = PluginRegistry(PI_DIR / "plugins")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/components")
def health_components() -> dict[str, Any]:
    return {"database": "ok", "detectors": "ok", "response_mode": "simulation"}


@router.post("/events", response_model=EventResponse)
def create_event(payload: EventCreate, session: Annotated[Session, Depends(get_session)]) -> Event:
    event = ingest_event(session, payload)
    process_events(session, [event])
    return event


@router.post("/events/bulk")
def create_events(payload: BulkEventsRequest, session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    events = [ingest_event(session, item) for item in payload.events]
    incidents = process_events(session, events)
    return {
        "ingested": len(events),
        "incidents": [incident.public_id for incident in incidents],
    }


@router.post("/events/import/suricata")
def import_suricata(payload: dict[str, str], session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    events = [ingest_event(session, item) for item in parse_eve_file(Path(payload["path"]))]
    incidents = process_events(session, events)
    return {"ingested": len(events), "incidents": [incident.public_id for incident in incidents]}


@router.post("/events/import/zeek")
def import_zeek(payload: dict[str, str], session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    events = [
        ingest_event(session, item)
        for item in parse_zeek_file(Path(payload["path"]), payload.get("log_type", "conn"))
    ]
    incidents = process_events(session, events)
    return {"ingested": len(events), "incidents": [incident.public_id for incident in incidents]}


@router.get("/events", response_model=list[EventResponse])
def list_events(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    source_ip: str | None = None,
    destination_ip: str | None = None,
) -> list[Event]:
    statement = select(Event).order_by(Event.timestamp.desc()).offset(offset).limit(limit)
    if source_ip:
        statement = statement.where(Event.source_ip == source_ip)
    if destination_ip:
        statement = statement.where(Event.destination_ip == destination_ip)
    return list(session.exec(statement).all())


@router.get("/events/{event_id}", response_model=EventResponse)
def get_event(event_id: int, session: Annotated[Session, Depends(get_session)]) -> Event:
    return session.get(Event, event_id)


@router.get("/incidents")
def list_incidents(session: Annotated[Session, Depends(get_session)]) -> list[Incident]:
    return list(session.exec(select(Incident).order_by(Incident.updated_at.desc())).all())


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, session: Annotated[Session, Depends(get_session)]) -> Incident | None:
    return session.get(Incident, incident_id)


@router.post("/incidents/{incident_id}/agent/run")
def run_incident_agent(
    incident_id: int,
    payload: dict[str, Any],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    try:
        agent_run = run_agent_for_incident(
            session,
            incident_id,
            str(payload.get("task") or "Analyze this incident and recommend safe response actions."),
            PI_DIR,
            payload.get("max_tool_calls"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _agent_run_dict(agent_run)


@router.get("/agent/runs")
def list_agent_runs(session: Annotated[Session, Depends(get_session)]) -> list[dict[str, Any]]:
    return [
        _agent_run_dict(agent_run)
        for agent_run in session.exec(select(AgentRun).order_by(AgentRun.started_at.desc()).limit(100)).all()
    ]


@router.post("/incidents/{incident_id}/status")
def set_incident_status(
    incident_id: int,
    payload: dict[str, str],
    session: Annotated[Session, Depends(get_session)],
) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        return transition_incident(session, incident, payload["status"], payload.get("actor", "operator"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/actions")
def list_actions(session: Annotated[Session, Depends(get_session)]) -> list[ResponseAction]:
    return [
        _action_dict(action)
        for action in session.exec(select(ResponseAction).order_by(ResponseAction.created_at.desc())).all()
    ]


@router.post("/incidents/{incident_id}/actions")
def create_action(
    incident_id: int,
    payload: dict[str, Any],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    action = propose_action(
        session,
        incident_id,
        str(payload["action_type"]),
        payload.get("arguments") or {},
        proposed_by=str(payload.get("proposed_by") or "agent"),
    )
    return _action_dict(action)


@router.get("/actions/{action_id}")
def get_action(action_id: int, session: Annotated[Session, Depends(get_session)]) -> dict[str, Any] | None:
    action = session.get(ResponseAction, action_id)
    return _action_dict(action) if action else None


@router.post("/actions/{action_id}/approve")
def approve(action_id: int, session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return _action_dict(approve_action(session, action))


@router.post("/actions/{action_id}/execute")
def execute(action_id: int, session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return _action_dict(execute_action(session, action))


@router.post("/actions/{action_id}/rollback")
def rollback(action_id: int, session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return _action_dict(rollback_action(session, action))


@router.get("/dashboard/stats")
def dashboard_stats(session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    return _dashboard_stats(session)


@router.get("/live/snapshot")
def live_snapshot(session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    return _live_snapshot(session)


@router.get("/live/events")
async def live_events() -> StreamingResponse:
    async def event_stream():
        while True:
            with Session(engine) as session:
                payload = json.dumps(_live_snapshot(session), default=str)
            yield f"event: snapshot\ndata: {payload}\n\n"
            await asyncio.sleep(5)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _dashboard_stats(session: Session) -> dict[str, Any]:
    since = datetime.utcnow() - timedelta(hours=24)
    total_events = session.exec(select(func.count(Event.id))).one()
    events_last_24h = session.exec(select(func.count(Event.id)).where(Event.timestamp >= since)).one()
    total_incidents = session.exec(select(func.count(Incident.id))).one()
    open_incidents = session.exec(select(func.count(Incident.id)).where(Incident.status != "closed")).one()
    pending_actions = session.exec(
        select(func.count(ResponseAction.id)).where(ResponseAction.status == "awaiting_approval")
    ).one()
    findings = session.exec(select(func.count(Finding.id))).one()
    audits = session.exec(select(func.count(AuditEntry.id))).one()
    return {
        "total_events": total_events,
        "events_last_24h": events_last_24h,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "pending_approvals": pending_actions,
        "findings": findings,
        "audit_entries": audits,
    }


def _live_snapshot(session: Session) -> dict[str, Any]:
    incidents = session.exec(select(Incident).order_by(Incident.updated_at.desc()).limit(25)).all()
    actions = session.exec(select(ResponseAction).order_by(ResponseAction.created_at.desc()).limit(25)).all()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "stats": _dashboard_stats(session),
        "incidents": [incident.model_dump(mode="json") for incident in incidents],
        "actions": [_action_dict(action) for action in actions],
    }


def _action_dict(action: ResponseAction) -> dict[str, Any]:
    return {
        "id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "plugin": action.plugin,
        "arguments": action.arguments,
        "risk": action.risk,
        "status": action.status,
        "simulated": action.simulated,
        "requires_approval": action.requires_approval,
        "proposed_by": action.proposed_by,
        "approved_by": action.approved_by,
        "approval_timestamp": action.approval_timestamp.isoformat() if action.approval_timestamp else None,
        "result": action.result,
        "verification_result": action.verification_result,
        "rollback_data": action.rollback_data,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "updated_at": action.updated_at.isoformat() if action.updated_at else None,
    }


def _agent_run_dict(agent_run: AgentRun) -> dict[str, Any]:
    return {
        "id": agent_run.id,
        "incident_id": agent_run.incident_id,
        "task": agent_run.task,
        "provider": agent_run.provider,
        "model": agent_run.model,
        "status": agent_run.status,
        "started_at": agent_run.started_at.isoformat() if agent_run.started_at else None,
        "ended_at": agent_run.ended_at.isoformat() if agent_run.ended_at else None,
        "final_response": agent_run.final_response,
        "error": agent_run.error,
        "usage_metadata": agent_run.usage_metadata,
    }


@router.get("/skills")
def list_skills() -> list[dict[str, Any]]:
    return skill_registry.list()


@router.post("/skills/{name}/validate")
def validate_skill(name: str) -> dict[str, Any]:
    return skill_registry.validate(name)


@router.post("/skills/{name}/enable")
def enable_skill(name: str) -> dict[str, Any]:
    return skill_registry.set_enabled(name, True)


@router.post("/skills/{name}/disable")
def disable_skill(name: str) -> dict[str, Any]:
    return skill_registry.set_enabled(name, False)


@router.get("/plugins")
def list_plugins() -> list[dict[str, Any]]:
    return plugin_registry.list()


@router.post("/plugins/{name}/validate")
def validate_plugin(name: str) -> dict[str, Any]:
    return plugin_registry.validate(name)


@router.post("/plugins/{name}/enable")
def enable_plugin(name: str) -> dict[str, Any]:
    return plugin_registry.set_enabled(name, True)


@router.post("/plugins/{name}/disable")
def disable_plugin(name: str) -> dict[str, Any]:
    return plugin_registry.set_enabled(name, False)
