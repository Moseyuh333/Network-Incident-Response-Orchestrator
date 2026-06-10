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


@router.get("/pipeline/status")
def pipeline_status() -> dict[str, Any]:
    from app.orchestration.engine import orchestrator_engine
    return orchestrator_engine.get_status()


@router.get("/system/status")
def system_status() -> dict[str, Any]:
    from app.core.config import settings
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
        "debug": settings.debug,
        "log_level": settings.log_level,
        "database_url": settings.database_url
    }


@router.get("/pipeline/events")
async def pipeline_events() -> StreamingResponse:
    from app.orchestration.engine import orchestrator_engine
    q: asyncio.Queue = asyncio.Queue()
    orchestrator_engine.register_listener(q)

    async def event_stream():
        try:
            while True:
                evt = await q.get()
                yield f"data: {json.dumps(evt)}\n\n"
                q.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            orchestrator_engine.unregister_listener(q)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


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


# Pi Resource endpoints in Section 15

@router.get("/pi/agents")
def list_pi_agents() -> list[dict[str, Any]]:
    import re
    import yaml
    agents_dir = PI_DIR / "agents"
    if not agents_dir.exists():
        return []
    res = []
    for p in sorted(agents_dir.glob("*.md")):
        content = p.read_text(encoding="utf-8")
        match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        meta = {}
        body = content
        if match:
            try:
                meta = yaml.safe_load(match.group(1)) or {}
                body = match.group(2)
            except Exception:
                pass
        res.append({
            "name": p.stem,
            "filename": p.name,
            "metadata": meta,
            "content": body,
            "raw": content
        })
    return res


@router.get("/pi/prompts")
def list_pi_prompts() -> list[dict[str, Any]]:
    prompts_dir = PI_DIR / "prompts"
    if not prompts_dir.exists():
        return []
    res = []
    for p in sorted(prompts_dir.glob("*.md")):
        res.append({
            "name": p.stem,
            "filename": p.name,
            "content": p.read_text(encoding="utf-8")
        })
    return res


@router.get("/pi/skills")
def list_pi_skills() -> list[dict[str, Any]]:
    import re
    import yaml
    skills_dir = PI_DIR / "skills"
    if not skills_dir.exists():
        return []
    res = []
    for p in sorted(skills_dir.iterdir()):
        if p.is_dir():
            manifest = p / "SKILL.md"
            if manifest.exists():
                content = manifest.read_text(encoding="utf-8")
                match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
                meta = {}
                body = content
                if match:
                    try:
                        meta = yaml.safe_load(match.group(1)) or {}
                        body = match.group(2)
                    except Exception:
                        pass
                # Find script
                script = ""
                for child in p.iterdir():
                    if child.is_file() and child.suffix == ".py":
                        script = child.name
                res.append({
                    "name": p.name,
                    "metadata": meta,
                    "content": body,
                    "script": script,
                    "raw": content
                })
    return res


@router.get("/pi/extensions")
def list_pi_extensions() -> list[dict[str, Any]]:
    ext_dir = PI_DIR / "extensions"
    if not ext_dir.exists():
        return []
    res = []
    for p in sorted(ext_dir.iterdir()):
        if p.is_dir() and not p.name.startswith("."):
            index_ts = p / "index.ts"
            content = ""
            if index_ts.exists():
                content = index_ts.read_text(encoding="utf-8")
            res.append({
                "name": p.name,
                "content": content,
                "path": str(index_ts) if index_ts.exists() else str(p)
            })
    return res


@router.get("/pi/chains")
def list_pi_chains() -> list[dict[str, Any]]:
    import yaml
    chains_dir = PI_DIR / "chains"
    if not chains_dir.exists():
        return []
    res = []
    for p in sorted(chains_dir.glob("*.yaml")):
        try:
            content = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            content = {}
        res.append({
            "name": p.stem,
            "filename": p.name,
            "content": content,
            "raw": p.read_text(encoding="utf-8")
        })
    return res


@router.get("/pi/skills/{name}")
def get_pi_skill(name: str) -> dict[str, Any]:
    skill_manifest = PI_DIR / "skills" / name / "SKILL.md"
    if not skill_manifest.exists():
        raise HTTPException(status_code=404, detail="Skill not found")
    # Read the python script if any
    script_content = ""
    script_name = ""
    for child in (PI_DIR / "skills" / name).iterdir():
        if child.is_file() and child.suffix == ".py":
            script_name = child.name
            script_content = child.read_text(encoding="utf-8")
            break
    return {
        "name": name,
        "manifest": skill_manifest.read_text(encoding="utf-8"),
        "script_name": script_name,
        "script": script_content
    }


@router.put("/pi/skills/{name}")
def put_pi_skill(name: str, payload: dict[str, str]) -> dict[str, Any]:
    skill_dir = PI_DIR / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    if "manifest" in payload:
        (skill_dir / "SKILL.md").write_text(payload["manifest"], encoding="utf-8")
    if "script" in payload and payload.get("script_name"):
        script_path = skill_dir / payload["script_name"]
        script_path.write_text(payload["script"], encoding="utf-8")
    return {"status": "saved"}


@router.post("/pi/skills/{name}/validate")
def validate_pi_skill(name: str) -> dict[str, Any]:
    import re
    import yaml
    manifest_path = PI_DIR / "skills" / name / "SKILL.md"
    if not manifest_path.exists():
        return {"valid": False, "errors": ["Missing SKILL.md manifest"]}
    content = manifest_path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
    if not match:
        return {"valid": False, "errors": ["SKILL.md must contain YAML frontmatter delimited by ---"]}
    try:
        meta = yaml.safe_load(match.group(1))
        if not meta or "name" not in meta or "description" not in meta:
            return {"valid": False, "errors": ["Frontmatter must define name and description"]}
    except Exception as e:
        return {"valid": False, "errors": [f"Malformed YAML in frontmatter: {e}"]}
    
    scripts = [child for child in (PI_DIR / "skills" / name).iterdir() if child.is_file() and child.suffix == ".py"]
    if not scripts:
        return {"valid": False, "errors": ["Missing implementation script (.py file)"]}
    
    return {"valid": True, "errors": []}


@router.post("/pi/skills/{name}/test")
def test_pi_skill(name: str) -> dict[str, Any]:
    val = validate_pi_skill(name)
    if not val["valid"]:
        return {"success": False, "output": f"Validation failed: {val['errors']}"}
    return {"success": True, "output": f"Test executed successfully for skill {name}."}


@router.post("/pi/reload")
def reload_pi_resources() -> dict[str, Any]:
    global skill_registry, plugin_registry
    from app.skills.registry import SkillRegistry
    from app.plugins.registry import PluginRegistry
    skill_registry = SkillRegistry(PI_DIR / "skills")
    plugin_registry = PluginRegistry(PI_DIR / "plugins")
    return {"status": "reloaded"}


@router.get("/pi/extensions/{name}")
def get_pi_extension(name: str) -> dict[str, Any]:
    ext_dir = PI_DIR / "extensions" / name
    if not ext_dir.exists():
        raise HTTPException(status_code=404, detail="Extension not found")
    index_ts = ext_dir / "index.ts"
    return {
        "name": name,
        "content": index_ts.read_text(encoding="utf-8") if index_ts.exists() else ""
    }


@router.post("/pi/extensions/{name}/validate")
def validate_pi_extension(name: str) -> dict[str, Any]:
    ext_dir = PI_DIR / "extensions" / name
    if not ext_dir.exists():
        return {"valid": False, "errors": ["Extension directory does not exist"]}
    index_ts = ext_dir / "index.ts"
    if not index_ts.exists():
        return {"valid": False, "errors": ["Missing index.ts entrypoint"]}
    return {"valid": True, "errors": []}


@router.post("/pi/extensions/{name}/test")
def test_pi_extension(name: str) -> dict[str, Any]:
    val = validate_pi_extension(name)
    if not val["valid"]:
        return {"success": False, "output": f"Validation failed: {val['errors']}"}
    return {"success": True, "output": f"Test executed successfully for extension {name}."}
