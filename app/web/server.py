"""FastAPI web console for controlling the Pi incident response agent."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.config import settings
from app.core.paths import DATA_DIR, PI_DIR
from app.api.v1 import router as v1_router
from app.db.session import create_db_and_tables, engine
from app.models.incident import Incident
from app.services.agent_runs import run_agent_for_incident
from scripts.run_pipeline import run_pipeline

STATIC_DIR = Path(__file__).resolve().parent / "static"
FRONTEND_DIST_DIR = Path(__file__).resolve().parents[2] / "ui" / "dist"
RUNTIME_DIR = PI_DIR / "runtime" / "web"
RUNS_DIR = RUNTIME_DIR / "runs"
PLUGIN_DIR = PI_DIR / "plugins"
SKILL_DIR = PI_DIR / "skills"


class AnalyzePayload(BaseModel):
    """Request body for launching an agent-backed incident analysis."""

    command: str = Field(default="Analyze the current alert and generate response guidance.")
    alert: dict[str, Any] | None = None
    use_sample: bool = True


class CommandPayload(BaseModel):
    """Natural-language operator command body."""

    command: str = Field(..., min_length=1, max_length=2000)
    alert: dict[str, Any] | None = None


class ResourcePayload(BaseModel):
    """Editable local skill/plugin payload."""

    name: str = Field(..., min_length=1, max_length=80)
    content: str = Field(default="", max_length=50000)


def create_app() -> FastAPI:
    """Create the FastAPI app used by uvicorn and tests."""
    create_db_and_tables()
    app = FastAPI(title="Network Incident Response Orchestrator")
    app.include_router(v1_router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    if FRONTEND_DIST_DIR.exists():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST_DIR / "assets"), name="frontend-assets")

    from app.orchestration.engine import orchestrator_engine
    from app.collectors.listeners import NetworkListeners

    listeners = NetworkListeners(
        host=settings.listener_host,
        tcp_port=settings.tcp_listener_port,
        udp_port=settings.udp_listener_port,
    )

    @app.on_event("startup")
    async def startup_event():
        orchestrator_engine.start()
        if settings.enable_tcp_listener or settings.enable_udp_listener:
            await listeners.start()

    @app.on_event("shutdown")
    async def shutdown_event():
        await orchestrator_engine.stop()
        if settings.enable_tcp_listener or settings.enable_udp_listener:
            await listeners.stop()

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        frontend_index = FRONTEND_DIST_DIR / "index.html"
        if frontend_index.exists():
            return HTMLResponse(frontend_index.read_text(encoding="utf-8"))
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return {
            "app": settings.app_name,
            "version": settings.app_version,
            "llm": {
                "provider": settings.llm_provider,
                "model": settings.effective_llm_model,
                "configured": bool(settings.llm_api_key or settings.google_api_key),
            },
            "sample_alert": _read_json(DATA_DIR / "sample_alert.json"),
            "latest_run": _latest_run(),
            "resources": _resource_index(),
        }

    @app.post("/api/analyze")
    def analyze(payload: AnalyzePayload) -> dict[str, Any]:
        alert_path = _materialize_alert(payload.alert, payload.use_sample)
        run_dir = _new_run_dir()
        triage = run_pipeline(alert_path, output_dir=run_dir)
        _write_command_log(run_dir, payload.command)
        return _run_response(run_dir, triage)

    @app.post("/api/command")
    def command(payload: CommandPayload) -> dict[str, Any]:
        return _handle_chat_command(payload.command, payload.alert)

    @app.post("/api/chat")
    def chat(payload: CommandPayload) -> dict[str, Any]:
        return _handle_chat_command(payload.command, payload.alert)

    @app.get("/api/resources")
    def resources() -> dict[str, Any]:
        return _resource_index()

    @app.get("/api/resources/{kind}/{name}")
    def read_resource(kind: str, name: str) -> dict[str, str]:
        path = _resource_path(kind, name)
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"{kind} resource not found")
        return {"kind": kind, "name": name, "content": path.read_text(encoding="utf-8")}

    @app.put("/api/resources/{kind}/{name}")
    def write_resource(kind: str, name: str, payload: ResourcePayload) -> dict[str, str]:
        path = _resource_path(kind, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload.content, encoding="utf-8")
        return {"kind": kind, "name": name, "path": str(path)}

    @app.get("/api/runs/latest")
    def latest_run() -> dict[str, Any]:
        latest = _latest_run()
        if not latest:
            raise HTTPException(status_code=404, detail="No run exists yet.")
        return latest

    return app


def _handle_chat_command(command: str, alert: dict[str, Any] | None) -> dict[str, Any]:
    normalized = command.strip().lower()
    agent_response = _try_handle_agent_command(command)
    if agent_response:
        return agent_response
    if any(token in normalized for token in ("run", "analyze", "triage", "phan tich", "phân tích")):
        alert_path = _materialize_alert(alert, use_sample=alert is None)
        run_dir = _new_run_dir()
        triage = run_pipeline(alert_path, output_dir=run_dir)
        _write_command_log(run_dir, command)
        return {
            "mode": "analysis",
            "assistant": _analysis_reply(triage),
            **_run_response(run_dir, triage),
        }
    if any(token in normalized for token in ("skill", "plugin")):
        return {
            "mode": "resources",
            "assistant": "Loaded local Pi skills and plugins. Select one in the workspace editor to view or modify it.",
            "resources": _resource_index(),
        }
    latest = _latest_run()
    if latest:
        latest["mode"] = "read_latest"
        latest["assistant"] = "I found the latest run. Use the report, evidence, and logs panels for details."
        return latest
    return {
        "mode": "chat",
        "assistant": "Tell me to analyze or triage the current alert. You can also add or modify skills/plugins from the workspace panel.",
    }


def _try_handle_agent_command(command: str) -> dict[str, Any] | None:
    normalized = command.lower()
    if "agent" not in normalized and "incident" not in normalized:
        return None
    match = re.search(r"incident\s+#?(\d+)", normalized)
    with Session(engine) as session:
        if not match:
            incidents = session.exec(select(Incident).order_by(Incident.updated_at.desc()).limit(5)).all()
            return {
                "mode": "agent",
                "assistant": "Choose an incident id, for example: agent incident 3 contain source.",
                "incidents": [
                    {
                        "id": incident.id,
                        "public_id": incident.public_id,
                        "title": incident.title,
                        "status": incident.status,
                        "severity": incident.severity,
                    }
                    for incident in incidents
                ],
            }
        incident_id = int(match.group(1))
        try:
            agent_run = run_agent_for_incident(session, incident_id, command, PI_DIR)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "mode": "agent",
            "assistant": _agent_run_reply(agent_run),
            "agent_run": {
                "id": agent_run.id,
                "incident_id": agent_run.incident_id,
                "status": agent_run.status,
                "provider": agent_run.provider,
                "model": agent_run.model,
                "usage_metadata": agent_run.usage_metadata,
            },
        }


def _agent_run_reply(agent_run: Any) -> str:
    metadata = agent_run.usage_metadata or {}
    selected_skill = metadata.get("selected_skill") or "default"
    tool_summary = metadata.get("tool_results") or {}
    proposed = tool_summary.get("propose_response_action")
    tail = ""
    if proposed:
        tail = f" Proposed action {proposed.get('action_id')} is waiting for approval."
    return (
        f"Agent run {agent_run.id} completed with skill {selected_skill}. "
        f"Provider: {agent_run.provider or 'fallback'}, model: {agent_run.model or 'n/a'}.{tail}"
    )


def _analysis_reply(triage: dict[str, Any]) -> str:
    classification = triage["classification"]
    llm = triage["llm_analysis"]
    status = "live LLM" if llm.get("available") else "fallback"
    return (
        f"Completed analysis using {status}. "
        f"Classification: {classification['label']} / {classification['severity']} "
        f"with confidence {classification['confidence']}."
    )


def _resource_index() -> dict[str, list[dict[str, str]]]:
    return {
        "skills": _list_resources(SKILL_DIR, default_name="SKILL.md"),
        "plugins": _list_resources(PLUGIN_DIR, default_name=""),
    }


def _list_resources(directory: Path, default_name: str) -> list[dict[str, str]]:
    resources: list[dict[str, str]] = []
    if default_name and (directory / default_name).exists():
        resources.append({"name": default_name, "path": str(directory / default_name)})
    if directory.exists():
        for path in sorted(directory.iterdir()):
            if (
                path.is_file()
                and path.name != default_name
                and path.suffix.lower() in {".md", ".json", ".yaml", ".yml"}
            ):
                resources.append({"name": path.name, "path": str(path)})
    return resources


def _resource_path(kind: str, name: str) -> Path:
    safe_name = Path(name).name
    if safe_name != name or not safe_name:
        raise HTTPException(status_code=400, detail="invalid resource name")
    if kind == "skills":
        return SKILL_DIR / safe_name
    if kind == "plugins":
        return PLUGIN_DIR / safe_name
    raise HTTPException(status_code=400, detail="kind must be skills or plugins")


def _now_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _new_run_dir() -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = RUNS_DIR / _now_slug()
    suffix = 1
    while run_dir.exists():
        suffix += 1
        run_dir = RUNS_DIR / f"{_now_slug()}-{suffix}"
    run_dir.mkdir(parents=True)
    return run_dir


def _materialize_alert(alert: dict[str, Any] | None, use_sample: bool) -> Path:
    if alert is None and use_sample:
        return DATA_DIR / "sample_alert.json"
    if alert is None:
        raise HTTPException(status_code=400, detail="alert is required when use_sample is false")
    alerts_dir = RUNTIME_DIR / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    alert_path = alerts_dir / f"alert-{_now_slug()}.json"
    alert_path.write_text(json.dumps(alert, indent=2, ensure_ascii=False), encoding="utf-8")
    return alert_path


def _write_command_log(run_dir: Path, command: str) -> None:
    log_path = run_dir / "logs" / "operator_command.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(command.strip() + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text_if_exists(path: Path, limit: int = 20000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    return text[-limit:]


def _run_response(run_dir: Path, triage: dict[str, Any]) -> dict[str, Any]:
    report_path = run_dir / "reports" / "ket_qua.md"
    audit_path = run_dir / "logs" / "audit.log"
    permission_path = run_dir / "logs" / "permission_gate.log"
    return {
        "run_dir": str(run_dir),
        "triage": triage,
        "report": _read_text_if_exists(report_path),
        "audit_log": _read_text_if_exists(audit_path),
        "permission_log": _read_text_if_exists(permission_path),
    }


def _latest_run() -> dict[str, Any] | None:
    if not RUNS_DIR.exists():
        return None
    candidates = sorted((path for path in RUNS_DIR.iterdir() if path.is_dir()), reverse=True)
    for run_dir in candidates:
        triage_path = run_dir / "triage" / "incident_triage.json"
        if triage_path.exists():
            return _run_response(run_dir, _read_json(triage_path))
    return None


app = create_app()


def run_web() -> None:
    """Start the local web console."""
    uvicorn.run("app.web.server:app", host="127.0.0.1", port=8000, reload=False)
