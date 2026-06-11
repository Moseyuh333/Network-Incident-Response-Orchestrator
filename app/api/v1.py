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
from app.core.config import settings
from app.services.actions import approve_action, execute_action, propose_action, reject_action, rollback_action
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


@router.post("/actions/{action_id}/reject")
def reject(action_id: int, session: Annotated[Session, Depends(get_session)]) -> dict[str, Any]:
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return _action_dict(reject_action(session, action))


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
    safe_name = _safe_resource_name(name)
    skill_manifest = PI_DIR / "skills" / safe_name / "SKILL.md"
    if not skill_manifest.exists():
        raise HTTPException(status_code=404, detail="Skill not found")
    # Read the python script if any
    script_content = ""
    script_name = ""
    for child in (PI_DIR / "skills" / safe_name).iterdir():
        if child.is_file() and child.suffix == ".py":
            script_name = child.name
            script_content = child.read_text(encoding="utf-8")
            break
    return {
        "name": safe_name,
        "manifest": skill_manifest.read_text(encoding="utf-8"),
        "script_name": script_name,
        "script": script_content
    }


@router.put("/pi/skills/{name}")
def put_pi_skill(name: str, payload: dict[str, str]) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    skill_dir = PI_DIR / "skills" / safe_name
    skill_dir.mkdir(parents=True, exist_ok=True)
    if "manifest" in payload:
        (skill_dir / "SKILL.md").write_text(payload["manifest"], encoding="utf-8")
    if "script" in payload and payload.get("script_name"):
        script_path = skill_dir / payload["script_name"]
        script_path.write_text(payload["script"], encoding="utf-8")
    return {"status": "saved", "name": safe_name}


@router.post("/pi/skills/{name}/validate")
def validate_pi_skill(name: str) -> dict[str, Any]:
    import re
    import yaml
    safe_name = _safe_resource_name(name)
    manifest_path = PI_DIR / "skills" / safe_name / "SKILL.md"
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
    
    scripts = [child for child in (PI_DIR / "skills" / safe_name).iterdir() if child.is_file() and child.suffix == ".py"]
    if not scripts:
        return {"valid": False, "errors": ["Missing implementation script (.py file)"]}
    
    return {"valid": True, "errors": []}


@router.post("/pi/skills/{name}/test")
def test_pi_skill(name: str) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    val = validate_pi_skill(name)
    if not val["valid"]:
        return {"success": False, "output": f"Validation failed: {val['errors']}"}
    return {"success": True, "output": f"Test executed successfully for skill {safe_name}."}


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
    safe_name = _safe_resource_name(name)
    ext_dir = PI_DIR / "extensions" / safe_name
    if not ext_dir.exists():
        raise HTTPException(status_code=404, detail="Extension not found")
    index_ts = ext_dir / "index.ts"
    return {
        "name": safe_name,
        "content": index_ts.read_text(encoding="utf-8") if index_ts.exists() else ""
    }


@router.post("/pi/extensions/{name}/validate")
def validate_pi_extension(name: str) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    ext_dir = PI_DIR / "extensions" / safe_name
    if not ext_dir.exists():
        return {"valid": False, "errors": ["Extension directory does not exist"]}
    index_ts = ext_dir / "index.ts"
    if not index_ts.exists():
        return {"valid": False, "errors": ["Missing index.ts entrypoint"]}
    return {"valid": True, "errors": []}


@router.post("/pi/extensions/{name}/test")
def test_pi_extension(name: str) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    val = validate_pi_extension(name)
    if not val["valid"]:
        return {"success": False, "output": f"Validation failed: {val['errors']}"}
    return {"success": True, "output": f"Test executed successfully for extension {safe_name}."}


@router.get("/pi/runtime")
def pi_runtime() -> dict[str, Any]:
    pi_cli = Path("node_modules") / ".bin" / "pi.cmd"
    pi_package = Path("node_modules") / "@earendil-works" / "pi-coding-agent" / "package.json"
    installed = pi_cli.exists() or pi_package.exists()
    return {
        "name": "Pi Coding Agent",
        "repo": "https://github.com/earendil-works/pi",
        "mode": "installed-local-cli" if installed else "local-compatible-runtime",
        "asset_root": str(PI_DIR),
        "cli": str(pi_cli) if pi_cli.exists() else "npx pi",
        "installed": installed,
        "packages": [
            "@earendil-works/pi-coding-agent",
            "@earendil-works/pi-agent-core",
            "@earendil-works/pi-ai",
            "@earendil-works/pi-tui",
        ],
        "note": "The console reads and writes Pi-style local agents, skills, extensions, and chains under .pi, then reloads them for the local incident-response runtime. The official Pi CLI is available through npx pi when installed.",
    }


@router.get("/config/llm")
def get_llm_config() -> dict[str, Any]:
    return _llm_config_response()


@router.put("/config/llm")
def put_llm_config(payload: dict[str, str]) -> dict[str, Any]:
    provider = (payload.get("provider") or settings.llm_provider or "google").strip().lower()
    model = (payload.get("model") or settings.effective_llm_model).strip()
    api_key = (payload.get("api_key") or "").strip()
    updates = {"LLM_PROVIDER": provider, "LLM_MODEL": model}
    if provider in {"google", "gemini"}:
        updates["LLM_MODEL_GOOGLE"] = model
        updates["LLM_MODEL_GEMINI"] = model
        if api_key:
            updates["GOOGLE_API_KEY"] = api_key
    if api_key:
        updates["LLM_API_KEY"] = api_key
    _update_env_file(updates)
    settings.llm_provider = provider
    settings.llm_model = model
    if provider in {"google", "gemini"}:
        settings.llm_model_google = model
        settings.llm_model_gemini = model
        if api_key:
            settings.google_api_key = api_key
    if api_key:
        settings.llm_api_key = api_key
    return _llm_config_response(saved=True)


@router.put("/pi/agents/{name}")
def put_pi_agent(name: str, payload: dict[str, str]) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    agents_dir = PI_DIR / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    (agents_dir / f"{safe_name}.md").write_text(payload.get("raw", ""), encoding="utf-8")
    return {"status": "saved", "name": safe_name}


@router.put("/pi/extensions/{name}")
def put_pi_extension(name: str, payload: dict[str, str]) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    ext_dir = PI_DIR / "extensions" / safe_name
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "index.ts").write_text(payload.get("content", ""), encoding="utf-8")
    return {"status": "saved", "name": safe_name}


@router.put("/pi/chains/{name}")
def put_pi_chain(name: str, payload: dict[str, str]) -> dict[str, Any]:
    safe_name = _safe_resource_name(name)
    chains_dir = PI_DIR / "chains"
    chains_dir.mkdir(parents=True, exist_ok=True)
    (chains_dir / f"{safe_name}.yaml").write_text(payload.get("raw", ""), encoding="utf-8")
    return {"status": "saved", "name": safe_name}


@router.post("/pi/generate")
def generate_pi_resource(payload: dict[str, str]) -> dict[str, Any]:
    kind = payload.get("kind")
    name = payload.get("name")
    prompt_text = payload.get("prompt")

    if not kind or not name or not prompt_text:
        raise HTTPException(status_code=400, detail="kind, name, and prompt are required")

    safe_name = _safe_resource_name(name)

    from app.llm.providers import GoogleGenAIProvider
    provider = GoogleGenAIProvider()
    if not provider.is_configured:
        raise HTTPException(status_code=400, detail="LLM provider is not configured. Please set the API key in Settings.")

    prompt = f"""You are a senior cybersecurity automation engineer and Pi Coding Agent.
Generate a local Pi '{kind}' resource named '{safe_name}' for the Network Incident Response Orchestrator.
Operator Request: {prompt_text}

Instructions:
1. Generate the requested resource (agent, skill, extension, or chain) following the standard Pi structure.
2. If creating or modifying a 'skill', provide both a 'manifest' (SKILL.md content starting with '---' frontmatter) and a 'script' (the executable python code containing 'def run(context):').
3. If creating or modifying an 'agent', provide the full 'manifest' (starting with YAML frontmatter like 'role: ...' and then markdown description).
4. If creating or modifying an 'extension', provide the TypeScript hook 'content' (e.g. implementing 'beforeToolCall' or similar hooks).
5. If creating or modifying a 'chain', provide the YAML 'raw' configuration defining the DAG execution steps.
6. Return a valid JSON response matching the schema.
"""

    res = provider.generate_json(prompt, {
        "type": "object",
        "properties": {
            "explanation": {"type": "string"},
            "resource_type": {"type": "string", "enum": ["agent", "skill", "extension", "chain"]},
            "resource_name": {"type": "string"},
            "manifest": {"type": "string"},
            "script": {"type": "string"},
            "content": {"type": "string"},
            "raw": {"type": "string"}
        },
        "required": ["explanation", "resource_type", "resource_name"]
    })

    if not res.available or not res.text:
        raise HTTPException(status_code=500, detail=f"LLM generation failed: {res.fallback_reason or 'empty response'}")

    try:
        parsed = json.loads(res.text)
        res_type = parsed.get("resource_type")
        explanation = parsed.get("explanation", "")

        saved_files = []

        if res_type == "agent":
            manifest = parsed.get("manifest") or ""
            target_dir = PI_DIR / "agents"
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / f"{safe_name}.md"
            target_file.write_text(manifest, encoding="utf-8")
            saved_files.append(str(target_file))

        elif res_type == "skill":
            manifest = parsed.get("manifest") or ""
            script = parsed.get("script") or ""
            target_dir = PI_DIR / "skills" / safe_name
            target_dir.mkdir(parents=True, exist_ok=True)

            manifest_file = target_dir / "SKILL.md"
            manifest_file.write_text(manifest, encoding="utf-8")
            saved_files.append(str(manifest_file))

            script_name = f"{safe_name.replace('-', '_')}.py"
            script_file = target_dir / script_name
            script_file.write_text(script, encoding="utf-8")
            saved_files.append(str(script_file))

        elif res_type == "extension":
            content = parsed.get("content") or ""
            target_dir = PI_DIR / "extensions" / safe_name
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / "index.ts"
            target_file.write_text(content, encoding="utf-8")
            saved_files.append(str(target_file))

        elif res_type == "chain":
            raw = parsed.get("raw") or ""
            target_dir = PI_DIR / "chains"
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / f"{safe_name}.yaml"
            target_file.write_text(raw, encoding="utf-8")
            saved_files.append(str(target_file))

        # reload
        global skill_registry, plugin_registry
        from app.skills.registry import SkillRegistry
        from app.plugins.registry import PluginRegistry
        skill_registry = SkillRegistry(PI_DIR / "skills")
        plugin_registry = PluginRegistry(PI_DIR / "plugins")

        return {
            "status": "success",
            "explanation": explanation,
            "resource_type": res_type,
            "resource_name": safe_name,
            "saved_files": [str(Path(f).relative_to(PI_DIR.parent)) for f in saved_files]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse and save LLM output: {e}. Raw response: {res.text}")



def _safe_resource_name(name: str) -> str:
    safe = Path(name).name.strip().replace(" ", "-")
    if not safe or safe in {".", ".."} or any(part in safe for part in ("/", "\\")):
        raise HTTPException(status_code=400, detail="invalid resource name")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(ch not in allowed for ch in safe):
        raise HTTPException(status_code=400, detail="resource name may only contain letters, numbers, dot, underscore, and dash")
    return safe.removesuffix(".md").removesuffix(".yaml").removesuffix(".yml")


def _llm_config_response(saved: bool = False) -> dict[str, Any]:
    configured = bool(settings.llm_api_key or settings.google_api_key)
    response = {
        "provider": settings.llm_provider,
        "model": settings.effective_llm_model,
        "configured": configured,
        "key_present": configured,
        "saved": saved,
        "pi_repo": "https://github.com/earendil-works/pi",
    }
    return response


def _update_env_file(updates: dict[str, str]) -> None:
    env_path = Path(".env")
    clean_updates = {key: value.replace("\r", "").replace("\n", "") for key, value in updates.items()}
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    seen: set[str] = set()
    next_lines: list[str] = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            next_lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in clean_updates:
            next_lines.append(f"{key}={clean_updates[key]}")
            seen.add(key)
        else:
            next_lines.append(line)
    for key, value in clean_updates.items():
        if key not in seen:
            next_lines.append(f"{key}={value}")
    env_path.write_text("\n".join(next_lines) + "\n", encoding="utf-8")
