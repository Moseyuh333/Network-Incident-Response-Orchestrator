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
from app.core.paths import DATA_DIR, PI_DIR, ROOT
from app.api.v1 import router as v1_router
from app.db.session import create_db_and_tables, engine
from app.models.incident import Incident
from app.services.agent_runs import run_agent_for_incident
from scripts.run_pipeline import run_pipeline

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
    frontend_assets = FRONTEND_DIST_DIR / "assets"
    if frontend_assets.exists():
        app.mount("/assets", StaticFiles(directory=frontend_assets), name="frontend-assets")

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
        raise HTTPException(
            status_code=503,
            detail=(
                "Frontend bundle not built. Run `cd ui && npm install && npm run build` "
                "to generate ui/dist/index.html."
            ),
        )

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


# ---------------------------------------------------------------------------
# Chat command routing
# ---------------------------------------------------------------------------

def _handle_chat_command(command: str, alert: dict[str, Any] | None) -> dict[str, Any]:
    normalized = command.strip().lower()

    # 1. AI resource management triggers (create/modify agent/skill/extension/chain)
    if any(token in normalized for token in ("create", "make", "modify", "generate", "add", "write", "tạo", "sửa", "viết", "thêm")):
        if any(res_token in normalized for res_token in ("agent", "skill", "extension", "chain", "phương thức", "luồng")):
            resource_res = _handle_resource_generation(command)
            if resource_res:
                return resource_res

    # 2. Explicit agent / incident commands
    agent_response = _try_handle_agent_command(command)
    if agent_response:
        return agent_response

    # 3. Pipeline analysis keywords
    analysis_keywords = (
        "run", "analyze", "triage", "phan tich", "phân tích", 
        "sự cố", "tấn công", "tình huống", "truy vết", "điều tra", 
        "investigate", "attack", "incident", "threat", "containment",
        "phản ứng", "đối phó"
    )
    if any(token in normalized for token in analysis_keywords):
        alert_path = _materialize_alert(alert, use_sample=alert is None)
        run_dir = _new_run_dir()
        triage = run_pipeline(alert_path, output_dir=run_dir)
        _write_command_log(run_dir, command)
        return {
            "mode": "analysis",
            "assistant": _analysis_reply(triage),
            **_run_response(run_dir, triage),
        }

    # 4. Skill / plugin browsing
    if any(token in normalized for token in ("skill", "plugin")):
        return {
            "mode": "resources",
            "assistant": "Loaded local Pi skills and plugins. Select one in the workspace editor to view or modify it.",
            "resources": _resource_index(),
        }

    # 5. Direct Conversational LLM Response (For free-form questions, help, chatting)
    from app.llm.providers import GoogleGenAIProvider
    provider = GoogleGenAIProvider()
    if provider.is_configured:
        res = provider.generate(command)
        if res.available and res.text:
            return {
                "mode": "chat",
                "assistant": res.text,
            }
        else:
            return {
                "mode": "chat",
                "assistant": f"LLM Chat Error: {res.fallback_reason or 'empty response'}",
            }

    # 6. Fallback if provider is not configured but local incidents exist
    with Session(engine) as session:
        latest_incident = session.exec(
            select(Incident).order_by(Incident.updated_at.desc()).limit(1)
        ).first()
        if latest_incident:
            try:
                agent_run = run_agent_for_incident(
                    session, latest_incident.id, command, PI_DIR
                )
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
            except Exception as exc:
                return {
                    "mode": "chat",
                    "assistant": f"Agent error: {exc}. Try setting the Gemini API key in Settings.",
                }

    return {
        "mode": "chat",
        "assistant": "LLM provider is not configured. Please go to Settings and enter your Gemini API Key.",
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


# ---------------------------------------------------------------------------
# Reply formatters
# ---------------------------------------------------------------------------

def _agent_run_reply(agent_run: Any) -> str:
    metadata = agent_run.usage_metadata or {}
    selected_skill = metadata.get("selected_skill") or "default"
    tool_summary = metadata.get("tool_results") or {}
    proposed = tool_summary.get("propose_response_action")
    tail = ""
    if proposed:
        tail = f" Proposed action {proposed.get('action_id')} is waiting for approval."

    summary = ""
    reasoning = ""
    report = ""
    if agent_run.final_response:
        try:
            data = json.loads(agent_run.final_response)
            summary = data.get("summary") or ""
            reasoning = data.get("reasoning_summary") or ""
            report = data.get("report") or ""
        except Exception:
            pass

    parts = [
        f"Agent run {agent_run.id} completed with skill {selected_skill}.",
        f"Provider: {agent_run.provider or 'fallback'}, model: {agent_run.model or 'n/a'}.{tail}"
    ]
    if summary:
        parts.append(f"\n[SUMMARY]\n{summary}")
    if reasoning:
        parts.append(f"\n[REASONING SUMMARY]\n{reasoning}")
    if report:
        lines = report.strip().split("\n")
        short_report = "\n".join(lines[:8])
        if len(lines) > 8:
            short_report += "\n... (Go to the INCIDENTS tab to read the full executive report)"
        parts.append(f"\n[EXECUTIVE REPORT]\n{short_report}")

    return "\n".join(parts)


def _analysis_reply(triage: dict[str, Any]) -> str:
    classification = triage["classification"]
    llm = triage["llm_analysis"]
    status = "live LLM" if llm.get("available") else "fallback"
    return (
        f"Completed analysis using {status}. "
        f"Classification: {classification['label']} / {classification['severity']} "
        f"with confidence {classification['confidence']}."
    )


# ---------------------------------------------------------------------------
# Resource helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Pipeline run helpers
# ---------------------------------------------------------------------------

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
    
    # Ensure alert_id is always present
    if "alert_id" not in alert:
        alert = dict(alert)
        alert["alert_id"] = f"ALT-{_now_slug().upper()}"
        
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



def _safe_resource_name(name: str) -> str:
    safe = Path(name).name.strip().replace(" ", "-")
    if not safe or safe in {".", ".."} or any(part in safe for part in ("/", "\\")):
        raise ValueError("invalid resource name")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(ch not in allowed for ch in safe):
        raise ValueError("resource name may only contain letters, numbers, dot, underscore, and dash")
    return safe


def _handle_resource_generation(command: str) -> dict[str, Any] | None:
    from app.llm.providers import GoogleGenAIProvider

    provider = GoogleGenAIProvider()
    if not provider.is_configured:
        return {
            "mode": "chat",
            "assistant": "LLM API Key is not configured. Please set your API key in settings first.",
        }

    normalized = command.lower()
    existing_context = []

    # Read existing resources if mentioned in the prompt
    # 1. Skills
    skills_dir = PI_DIR / "skills"
    if skills_dir.exists():
        for folder in skills_dir.iterdir():
            if folder.is_dir() and folder.name.lower() in normalized:
                manifest_path = folder / "SKILL.md"
                if manifest_path.exists():
                    existing_context.append(f"Skill '{folder.name}' Manifest (SKILL.md):\n{manifest_path.read_text(encoding='utf-8')}")
                for script_path in folder.glob("*.py"):
                    existing_context.append(f"Skill '{folder.name}' Script ({script_path.name}):\n{script_path.read_text(encoding='utf-8')}")

    # 2. Agents
    agents_dir = PI_DIR / "agents"
    if agents_dir.exists():
        for p in agents_dir.glob("*.md"):
            if p.stem.lower() in normalized:
                existing_context.append(f"Agent '{p.stem}':\n{p.read_text(encoding='utf-8')}")

    # 3. Extensions
    ext_dir = PI_DIR / "extensions"
    if ext_dir.exists():
        for folder in ext_dir.iterdir():
            if folder.is_dir() and folder.name.lower() in normalized:
                index_ts = folder / "index.ts"
                if index_ts.exists():
                    existing_context.append(f"Extension '{folder.name}' (index.ts):\n{index_ts.read_text(encoding='utf-8')}")

    # 4. Chains
    chains_dir = PI_DIR / "chains"
    if chains_dir.exists():
        for p in chains_dir.glob("*.yaml"):
            if p.stem.lower() in normalized:
                existing_context.append(f"Chain '{p.stem}':\n{p.read_text(encoding='utf-8')}")

    existing_str = "\n\n".join(existing_context) if existing_context else "None"

    prompt = f"""You are a senior cybersecurity automation engineer and Pi Coding Agent.
The operator wants to manage (create or modify) local Pi resources for the Network Incident Response Orchestrator.
Operator Request: {command}

Existing Resources Mentioned in Request:
{existing_str}

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
        return {
            "mode": "chat",
            "assistant": f"Failed to generate resource using LLM: {res.fallback_reason or 'No response'}",
        }

    try:
        parsed = json.loads(res.text)
        res_type = parsed.get("resource_type")
        res_name = _safe_resource_name(parsed.get("resource_name"))
        explanation = parsed.get("explanation", "")

        saved_files = []

        if res_type == "agent":
            manifest = parsed.get("manifest") or ""
            target_dir = PI_DIR / "agents"
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / f"{res_name}.md"
            target_file.write_text(manifest, encoding="utf-8")
            saved_files.append(str(target_file))

        elif res_type == "skill":
            manifest = parsed.get("manifest") or ""
            script = parsed.get("script") or ""
            target_dir = PI_DIR / "skills" / res_name
            target_dir.mkdir(parents=True, exist_ok=True)

            manifest_file = target_dir / "SKILL.md"
            manifest_file.write_text(manifest, encoding="utf-8")
            saved_files.append(str(manifest_file))

            script_name = f"{res_name.replace('-', '_')}.py"
            script_file = target_dir / script_name
            script_file.write_text(script, encoding="utf-8")
            saved_files.append(str(script_file))

        elif res_type == "extension":
            content = parsed.get("content") or ""
            target_dir = PI_DIR / "extensions" / res_name
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / "index.ts"
            target_file.write_text(content, encoding="utf-8")
            saved_files.append(str(target_file))

        elif res_type == "chain":
            raw = parsed.get("raw") or ""
            target_dir = PI_DIR / "chains"
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / f"{res_name}.yaml"
            target_file.write_text(raw, encoding="utf-8")
            saved_files.append(str(target_file))

        saved_str = "\n".join(f"- {Path(f).relative_to(ROOT)}" for f in saved_files)
        return {
            "mode": "chat",
            "assistant": f"### 🛠️ Resource Generated & Imported!\n\n**Action**: {explanation}\n**Type**: {res_type.upper()}\n**Name**: {res_name}\n\n**Saved Files**:\n{saved_str}\n\nPi runtime reloaded successfully. The new resource is now active in the system.",
            "resources": _resource_index()
        }

    except Exception as exc:
        return {
            "mode": "chat",
            "assistant": f"Failed to save and import generated resource: {exc}\n\nRaw LLM response:\n```json\n{res.text}\n```",
        }


app = create_app()



def run_web() -> None:
    """Start the local web console."""
    uvicorn.run("app.web.server:app", host="127.0.0.1", port=8000, reload=False)
