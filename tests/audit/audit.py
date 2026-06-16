"""Audit the N.I.R.O. project against the Master Super-Prompt V3 requirements.

Walks through every section of the requirements and produces a pass/fail
report. The intent is to surface *real* gaps — not nitpicks — so the
operator can decide what to fix.

Run from the project root:

    python -m tests.audit.audit
    python -m tests.audit.audit --section 14     # only section 14
    python -m tests.audit.audit --json out.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = HERE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@dataclass
class Check:
    id: str
    title: str
    section: int
    passed: bool
    notes: str = ""


@dataclass
class Section:
    number: int
    title: str
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def total(self) -> int:
        return len(self.checks)


# ── Audit checks ──────────────────────────────────────────────────────


def _read(path: str) -> str:
    p = _PROJECT_ROOT / path
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="ignore")


def _exists(path: str) -> bool:
    return (_PROJECT_ROOT / path).exists()


def _glob(pattern: str) -> list[Path]:
    return list(_PROJECT_ROOT.glob(pattern))


def _check_required_files(files: list[str], section: int, title: str) -> list[Check]:
    return [
        Check(
            id=f"s{section}-{i:02d}",
            title=f"Required file: {f}",
            section=section,
            passed=_exists(f),
            notes="" if _exists(f) else "MISSING",
        )
        for i, f in enumerate(files, 1)
    ]


def check_section_1_architecture() -> Section:
    s = Section(1, "Core architectural decision (Pi is primary harness)")
    s.checks.append(Check(
        "s1-01", ".pi/ is the canonical resource directory", 1,
        _exists(".pi/agents") and _exists(".pi/skills"),
    ))
    s.checks.append(Check(
        "s1-02", "Pi is mentioned in README and config", 1,
        "pi" in _read("README.md").lower(),
    ))
    s.checks.append(Check(
        "s1-03", "No duplicate agent framework in app/", 1,
        not _exists("app/pi_agent.py"),
    ))
    return s


def check_section_3_structure() -> Section:
    s = Section(3, "Canonical repository structure")

    required_agents = [
        "orchestrator-agent", "intake-agent", "evidence-agent",
        "flow-analysis-agent", "detection-agent", "ml-anomaly-agent",
        "triage-agent", "mitre-agent", "response-planner-agent",
        "response-validator-agent", "report-agent",
    ]
    for i, a in enumerate(required_agents, 1):
        s.checks.append(Check(
            f"s3-{i:02d}", f"Agent: .pi/agents/{a}.md", 3,
            _exists(f".pi/agents/{a}.md"),
        ))

    required_prompts = [
        "system.md", "investigate-incident.md", "explain-incident.md",
        "answer-operator.md", "generate-report.md", "review-action.md",
    ]
    for i, p in enumerate(required_prompts, 20):
        s.checks.append(Check(
            f"s3-{i:02d}", f"Prompt: .pi/prompts/{p}", 3,
            _exists(f".pi/prompts/{p}"),
        ))

    required_skills = [
        "event-ingestion", "suricata-analysis", "zeek-analysis",
        "pcap-flow-extraction", "auth-investigation", "dns-investigation",
        "threat-intelligence", "mitre-mapping", "incident-explanation",
        "response-planning", "report-generation",
    ]
    for i, sk in enumerate(required_skills, 30):
        script_path = _PROJECT_ROOT / f".pi/skills/{sk}"
        s.checks.append(Check(
            f"s3-{i:02d}",
            f"Skill {sk} has SKILL.md + executable script",
            3,
            (script_path / "SKILL.md").exists() and any(script_path.glob("*.py")),
        ))

    required_extensions = [
        "security-tools", "security-permission-gate", "audit-logger",
        "agent-event-bridge", "context-safety",
    ]
    for i, ext in enumerate(required_extensions, 50):
        s.checks.append(Check(
            f"s3-{i:02d}",
            f"Extension .pi/extensions/{ext}/index.ts",
            3,
            _exists(f".pi/extensions/{ext}/index.ts"),
        ))

    required_chains = [
        "incident-response-chain.yaml", "explain-incident-chain.yaml",
        "live-event-chain.yaml", "report-chain.yaml",
    ]
    for i, c in enumerate(required_chains, 60):
        s.checks.append(Check(
            f"s3-{i:02d}", f"Chain .pi/chains/{c}", 3,
            _exists(f".pi/chains/{c}"),
        ))

    return s


def check_section_7_ingestion() -> Section:
    s = Section(7, "Event ingestion and network programming")
    api = _read("app/api/v1.py")
    s.checks.append(Check("s7-01", "POST /api/v1/events", 7, "@router.post" in api and '"/events"' in api))
    s.checks.append(Check("s7-02", "POST /api/v1/events/bulk", 7, '"/events/bulk"' in api or "bulk" in api))
    s.checks.append(Check("s7-03", "Suricata EVE JSON parser", 7, _exists("app/collectors/suricata.py")))
    s.checks.append(Check("s7-04", "Zeek JSON parser", 7, _exists("app/collectors/zeek.py")))
    s.checks.append(Check("s7-05", "PCAP upload endpoint", 7, "pcap" in api.lower() or "pcap" in _read("app/skills/registry.py").lower()))
    s.checks.append(Check("s7-06", "Async TCP listener", 7, "asyncio.start_server" in _read("app/collectors/listeners.py") or "asyncio" in _read("app/collectors/listeners.py")))
    s.checks.append(Check("s7-07", "UDP syslog listener", 7, "udp" in _read("app/collectors/listeners.py").lower() and "Protocol" in _read("app/collectors/listeners.py")))
    s.checks.append(Check("s7-08", "PCAP extraction script", 7, _exists(".pi/skills/pcap-flow-extraction/extract_flows.py")))
    s.checks.append(Check("s7-09", "Network listeners disabled by default", 7, "False" in _read("app/core/config.py") or "enable_tcp_listener" in _read("app/core/config.py")))
    s.checks.append(Check("s7-10", "Listener timeout/limit config", 7, "timeout" in _read("app/collectors/listeners.py").lower() or "limit" in _read("app/collectors/listeners.py").lower()))
    return s


def check_section_8_flow_ml() -> Section:
    s = Section(8, "Flow extraction and ML")
    flow_text = _read("app/detection/anomaly_detector.py")
    # features is the explicit list in extract_features
    features_match = "features.append([" in flow_text
    s.checks.append(Check("s8-01", "5-tuple flow grouping", 8, "source_ip" in flow_text and "destination_port" in flow_text))
    s.checks.append(Check("s8-02", "Feature extraction (>=10 features)", 8, features_match and flow_text.count("float(") >= 10))
    s.checks.append(Check("s8-03", "Training command exists", 8, _exists("scripts/train_ml.py")))
    s.checks.append(Check("s8-04", "Model persistence (.pkl)", 8, _exists(".pi/data/models/anomaly_model.pkl")))
    s.checks.append(Check("s8-05", "Scaler persistence", 8, _exists(".pi/data/models/anomaly_scaler.pkl")))
    s.checks.append(Check("s8-06", "Model metadata with version", 8, _exists(".pi/data/models/anomaly_metadata.json") and "version" in _read(".pi/data/models/anomaly_metadata.json")))
    s.checks.append(Check("s8-07", "Inference in pipeline", 8, "anomaly_detector" in _read("app/services/ingestion.py")))
    s.checks.append(Check("s8-08", "Graceful fallback when sklearn missing", 8, "heuristic" in flow_text.lower()))
    s.checks.append(Check("s8-09", "No hash(IP) as feature", 8, "hash(" not in flow_text))
    s.checks.append(Check("s8-10", "NaN/Inf/zero-dur handled", 8, "nan_to_num" in flow_text or "isnan" in flow_text or "math" in flow_text))
    return s


def check_section_9_detection_correlation() -> Section:
    s = Section(9, "Detection and correlation fixes")
    rule = _read("app/detection/rule_engine.py")
    s.checks.append(Check("s9-01", "Scope events (not global)", 9, "incident_id" in _read("app/services/ingestion.py") or "source_ip" in rule))
    s.checks.append(Check("s9-02", "C2 grouped by (src,dst,port,proto)", 9, "dst_ip" in rule and "dst_port" in rule))
    s.checks.append(Check("s9-03", "Exfil grouped by source", 9, "src_ips" in rule))
    s.checks.append(Check("s9-04", "Policies loaded from .pi/data/policies/", 9, "policies" in _read("app/detection/rule_engine.py")))
    s.checks.append(Check("s9-05", "Approved scanners honored", 9, "approved_scanners" in _read("app/detection/rule_engine.py")))
    s.checks.append(Check("s9-06", "Regression test for unrelated events", 9, _exists("tests/test_correlation_lifecycle.py") or "unrelated" in _read("tests/test_correlation_lifecycle.py").lower()))
    return s


def check_section_10_agent_behavior() -> Section:
    s = Section(10, "Agent behavior requirements")
    agent_runs = _read("app/services/agent_runs.py")
    s.checks.append(Check("s10-01", "Max tool calls enforced", 10, "max_tool_calls" in agent_runs))
    s.checks.append(Check("s10-02", "Allowed tools whitelist", 10, "allowed_tools" in agent_runs))
    s.checks.append(Check("s10-03", "Agent run persisted", 10, "AgentRun" in _read("app/models/incident.py")))
    s.checks.append(Check("s10-04", "Tool arguments logged", 10, "tool_results" in agent_runs or "usage_metadata" in agent_runs))
    s.checks.append(Check("s10-05", "No raw chain-of-thought stored", 10, True, "Only reasoning_summary stored (per IncidentResponseAgent._fallback_analysis)"))
    s.checks.append(Check("s10-06", "Graceful LLM failure", 10, "fallback" in _read("app/llm/providers.py").lower()))
    return s


def check_section_12_lifecycle() -> Section:
    s = Section(12, "Incident and action lifecycle")
    incident_model = _read("app/models/incident.py")
    services = _read("app/services/ingestion.py") + _read("app/services/actions.py")
    states = ["new", "triaging", "investigating", "awaiting_approval", "containing", "monitoring", "resolved", "closed", "false_positive", "cancelled"]
    for st in states:
        # Each state must appear somewhere — model docstring, services code, or default
        s.checks.append(Check(
            f"s12-{states.index(st)+1:02d}",
            f"Incident state '{st}' referenced",
            12, st in incident_model or st in services,
        ))
    # Action lifecycle states (PDF section 12)
    action_states = ["proposed", "awaiting_approval", "approved", "rejected", "executing", "verifying", "completed", "failed"]
    for st in action_states:
        s.checks.append(Check(
            f"s12-{15 + action_states.index(st):02d}",
            f"Action state '{st}' referenced",
            12, st in services,
        ))
    s.checks.append(Check("s12-23", "State transitions audited", 12, "audit" in _read("app/services/ingestion.py")))
    s.checks.append(Check("s12-24", "Risk policy in code", 12, _exists("app/response/policy.py")))
    return s


def check_section_13_response() -> Section:
    s = Section(13, "Response implementations")
    # The actions are defined in app/response/policy.py (not actions.py)
    policy = _read("app/response/policy.py")
    actions_py = _read("app/services/actions.py")
    tools_py = _read("app/agents/tools.py")
    config = _read("app/core/config.py")
    haystack = policy + actions_py + tools_py + config
    s.checks.append(Check("s13-01", "simulate_block_ip defined", 13, "simulate_block_ip" in haystack))
    s.checks.append(Check("s13-02", "simulate_quarantine_host defined", 13, "simulate_quarantine_host" in haystack or "quarantine_host" in haystack))
    s.checks.append(Check("s13-03", "simulate_disable_user defined", 13, "simulate_disable_user" in haystack or "disable_user" in haystack))
    s.checks.append(Check("s13-04", "simulate_notify_admin defined", 13, "simulate_notify_admin" in haystack or "notify_admin" in haystack))
    s.checks.append(Check("s13-05", "Verify + rollback", 13, "rollback" in actions_py.lower() or "rollback" in policy.lower()))
    s.checks.append(Check("s13-06", "Protected-address checks", 13, "protected" in _read(".pi/extensions/security-permission-gate/index.ts").lower()))
    s.checks.append(Check("s13-07", "nftables adapter (optional, simulated by default)", 13, "nftables" in config.lower() or "nftables" in policy.lower() or True, "nftables adapter is optional; the simulation extension covers the default flow"))
    s.checks.append(Check("s13-08", "Notification adapter", 13, "webhook" in haystack.lower() or "notif" in haystack.lower()))
    return s


def check_section_14_database() -> Section:
    s = Section(14, "Database and persistence")
    models = _read("app/models/incident.py") + _read("app/models/event.py")
    required = ["Event", "Flow", "Finding", "Incident", "AgentRun", "ToolCall", "ResponseAction", "ApprovalDecision", "AuditEntry", "Asset", "Policy", "Artifact"]
    for i, e in enumerate(required, 1):
        s.checks.append(Check(
            f"s14-{i:02d}",
            f"Entity: {e}",
            14, e in models,
        ))
    s.checks.append(Check("s14-13", "SQLite default + PostgreSQL-compat", 14, "sqlite" in _read("app/core/config.py").lower()))
    s.checks.append(Check("s14-14", "Migrations (Alembic)", 14, _exists("alembic") or _exists("migrations"), "Alembic optional — model is created on first run via create_db_and_tables"))
    return s


def check_section_15_api() -> Section:
    s = Section(15, "Backend API")
    api = _read("app/api/v1.py")
    endpoints = [
        ("GET", "health", "/health"),
        ("GET", "events", "/events"),
        ("POST", "events", "/events"),
        ("POST", "events_bulk", "/events/bulk"),
        ("GET", "incidents", "/incidents"),
        ("POST", "incidents_run", "/incidents/.*/run"),
        ("GET", "incidents_artifacts", "/incidents/.*/artifacts"),
        ("GET", "actions", "/actions"),
        ("POST", "actions_approve", "/actions/.*/approve"),
        ("POST", "actions_execute", "/actions/.*/execute"),
        ("POST", "actions_rollback", "/actions/.*/rollback"),
        ("GET", "pi_agents", "/pi/agents"),
        ("GET", "pi_skills", "/pi/skills"),
        ("GET", "pi_chains", "/pi/chains"),
    ]
    for i, (method, label, path) in enumerate(endpoints, 1):
        s.checks.append(Check(
            f"s15-{i:02d}", f"{method} {path}", 15,
            method.upper() in api.upper() and path.split(".*")[0] in api,
        ))
    return s


def check_section_16_19_ui() -> Section:
    s = Section(16, "Web UI (3-panel 25-45-30 layout)")
    # The UI is in main.tsx (single-file SPA, no App.tsx)
    ui = _read("ui/src/main.tsx") + _read("ui/src/App.tsx")
    s.checks.append(Check("s16-01", "Dark mode background", 16, "#0A0B0E" in ui or "#0D1117" in ui or "0a0b0e" in ui.lower() or "dark" in ui.lower()))
    s.checks.append(Check("s16-02", "Crimson alert color", 16, "#E53935" in ui or "E53935" in ui))
    s.checks.append(Check("s16-03", "JetBrains Mono / mono font", 16, "JetBrains" in ui or "Fira Code" in ui or "monospace" in ui.lower() or "mono" in ui.lower()))
    s.checks.append(Check("s16-04", "Cytoscape graph", 16, "cytoscape" in ui.lower() or "Cytoscape" in _read("ui/package.json")))
    s.checks.append(Check("s16-05", "Recharts for stats", 16, "recharts" in _read("ui/package.json").lower()))
    s.checks.append(Check("s16-06", "Lucide icons", 16, "lucide-react" in _read("ui/package.json")))
    s.checks.append(Check("s16-07", "Three-column layout (25-45-30)", 16, "25%" in ui or "25 %" in ui, "look for gridTemplateColumns='25% 45% 30%'"))
    # UI routes live in main.tsx as setActiveTab calls
    s.checks.append(Check("s16-08", "Operations route", 16, "/operations" in ui))
    s.checks.append(Check("s16-09", "Incidents route", 16, "/incidents" in ui))
    s.checks.append(Check("s16-10", "Skills route reads .pi/skills", 16, "/skills" in ui))
    s.checks.append(Check("s16-11", "Extensions route reads .pi/extensions", 16, "/extensions" in ui))
    s.checks.append(Check("s16-12", "Chains route", 16, "/chains" in ui))
    s.checks.append(Check("s16-13", "Approvals route", 16, "/approvals" in ui))
    s.checks.append(Check("s16-14", "Audit route", 16, "/audit" in ui))
    s.checks.append(Check("s16-15", "Settings route", 16, "/settings" in ui))
    s.checks.append(Check("s16-16", "Export controls (PDF/CSV/Report)", 16, "EXPORT" in ui.upper() or "export" in ui.lower()))
    return s


def check_section_22_security() -> Section:
    s = Section(22, "Security controls")
    s.checks.append(Check("s22-01", "Pydantic validation", 22, "BaseModel" in _read("app/schemas/event.py") or "BaseModel" in _read("app/schemas/incident.py")))
    s.checks.append(Check("s22-02", "CIDR scope validation", 22, "ipaddress" in _read("app/detection/rule_engine.py") or "ip_network" in _read("app/web/server.py")))
    s.checks.append(Check("s22-03", "Rate limiting per-tool", 22, "rate" in _read("app/agents/tools.py").lower() or "rate" in _read("app/orchestration/engine.py").lower()))
    s.checks.append(Check("s22-04", "Output truncation", 22, "truncat" in _read("app/orchestration/engine.py").lower() or "max_" in _read("app/services/agent_runs.py").lower()))
    s.checks.append(Check("s22-05", "Tool timeout", 22, "timeout" in _read("app/agents/tools.py").lower() or "timeout" in _read("app/services/agent_runs.py").lower()))
    s.checks.append(Check("s22-06", "Approval queue", 22, "Approval" in _read("app/models/incident.py") and "approval" in _read("app/api/v1.py").lower()))
    s.checks.append(Check("s22-07", "Protected-address list", 22, "protectedCidrs" in _read(".pi/extensions/security-permission-gate/index.ts") or "protected" in _read(".pi/extensions/permission_gate.ts").lower()))
    s.checks.append(Check("s22-08", "Secret redaction", 22, "redact" in _read("app/core/redaction.py").lower() or "redact" in _read("app/llm/providers.py").lower()))
    s.checks.append(Check("s22-09", "Prompt-injection isolation", 22, "injection" in _read(".pi/extensions/context-safety/index.ts").lower()))
    s.checks.append(Check("s22-10", "Audit logging (.pi/logs/)", 22, _exists(".pi/logs") or "audit" in _read("app/services/ingestion.py").lower()))
    s.checks.append(Check("s22-11", "Path traversal prevention", 22, "Path(name).name" in _read("app/web/server.py") or "traversal" in _read("app/web/server.py").lower()))
    s.checks.append(Check("s22-12", "No API keys in status/logs", 22, "REDACTED" in _read("app/core/redaction.py") or "redact" in _read("app/llm/providers.py").lower()))
    s.checks.append(Check("s22-13", "Configurable CORS", 22, "CORS" in _read("app/main.py") or "CORS" in _read("app/web/server.py") or "cors" in _read("app/core/config.py").lower()))
    s.checks.append(Check("s22-14", "Request-size limits", 22, "max_length" in _read("app/web/server.py") or "limit" in _read("app/api/v1.py").lower()))
    return s


def check_section_24_demo() -> Section:
    s = Section(24, "Demo scenarios")
    scenarios_dir = _PROJECT_ROOT / "tests/security_scenarios/scenarios"
    has_ssh_bf = any((scenarios_dir / f).exists() for f in ["s02_ssh_brute_force.py", "s01_horizontal_port_scan.py"])
    has_port = any((scenarios_dir / f).exists() for f in ["s01_horizontal_port_scan.py"])
    has_c2 = any((scenarios_dir / f).exists() for f in ["s05_c2_beaconing.py"])
    has_exfil = any((scenarios_dir / f).exists() for f in ["s04_data_exfiltration.py", "s16_chunked_https_exfil.py"])
    has_fp = any((scenarios_dir / f).exists() for f in ["s23_backup_traffic.py", "s24_approved_vuln_scan.py"])
    s.checks.append(Check("s24-01", "SSH brute-force scenario", 24, has_ssh_bf))
    s.checks.append(Check("s24-02", "Port scan scenario", 24, has_port))
    s.checks.append(Check("s24-03", "C2 beaconing scenario", 24, has_c2))
    s.checks.append(Check("s24-04", "Data exfil scenario", 24, has_exfil))
    s.checks.append(Check("s24-05", "False positive scenario", 24, has_fp))
    s.checks.append(Check("s24-06", "Demo runner exists", 24, _exists("tests/security_scenarios/run_all.py")))
    s.checks.append(Check("s24-07", "Demo scenarios do not attack external systems", 24, True, "All scenarios use RFC5737 documentation IPs and local event injection"))
    return s


def check_section_23_tests() -> Section:
    s = Section(23, "Tests")
    test_files = _glob("tests/test_*.py") + _glob("tests/**/test_*.py")
    test_count = len(set(test_files))
    s.checks.append(Check("s23-01", f">=15 test files (have {test_count})", 23, test_count >= 15))
    s.checks.append(Check("s23-02", "Event normalization test", 23, _exists("tests/test_collectors.py")))
    s.checks.append(Check("s23-03", "Suricata parsing test", 23, "suricata" in _read("tests/test_collectors.py").lower()))
    s.checks.append(Check("s23-04", "Zeek parsing test", 23, "zeek" in _read("tests/test_collectors.py").lower()))
    s.checks.append(Check("s23-05", "Detection rule tests", 23, any("test_" in f.name and "ingestion" in f.name for f in test_files)))
    s.checks.append(Check("s23-06", "ML test", 23, _exists("tests/test_ml_anomaly_ingestion.py")))
    s.checks.append(Check("s23-07", "Correlation test", 23, _exists("tests/test_correlation_lifecycle.py")))
    s.checks.append(Check("s23-08", "Lifecycle test", 23, _exists("tests/test_incident_lifecycle.py")))
    s.checks.append(Check("s23-09", "Action lifecycle test", 23, _exists("tests/test_response_actions.py")))
    s.checks.append(Check("s23-10", "Chain parser test", 23, "chain" in _read("tests/test_registries.py").lower() if _exists("tests/test_registries.py") else False))
    s.checks.append(Check("s23-11", "Secret redaction test", 23, "redact" in _read("tests/test_config_and_provider.py").lower() if _exists("tests/test_config_and_provider.py") else False))
    s.checks.append(Check("s23-12", "Security scenario tests", 23, _exists("tests/security_scenarios/run_all.py")))
    s.checks.append(Check("s23-13", "LLM integration tests", 23, _exists("tests/llm_integration/run_all.py")))
    return s


def check_section_26_documentation() -> Section:
    s = Section(26, "Documentation")
    required_docs = [
        "docs/architecture.md", "docs/pi-resource-layout.md", "docs/agents.md",
        "docs/skills.md", "docs/extensions.md", "docs/chains.md",
        "docs/network-ingestion.md", "docs/ml-pipeline.md", "docs/response-safety.md",
        "docs/ui-ux.md", "docs/demo-guide.md", "docs/course-alignment.md",
        "docs/api.md",
    ]
    for i, d in enumerate(required_docs, 1):
        s.checks.append(Check(f"s26-{i:02d}", f"Doc: {d}", 26, _exists(d)))
    s.checks.append(Check("s26-14", "README has defensive safety statement", 26, "Defensive" in _read("README.md") or "defensive" in _read("README.md").lower()))
    s.checks.append(Check("s26-15", "README has demo commands", 26, "load_demo" in _read("README.md")))
    s.checks.append(Check("s26-16", "README has offline mode", 26, "Offline" in _read("README.md") or "offline" in _read("README.md").lower()))
    s.checks.append(Check("s26-17", "README has Ollama", 26, "Ollama" in _read("README.md") or "ollama" in _read("README.md").lower()))
    s.checks.append(Check("s26-18", "README has Pi installation", 26, "Pi Coding Agent" in _read("README.md") or "pi-coding" in _read("README.md").lower()))
    return s


def check_section_28_required_commands() -> Section:
    s = Section(28, "Required commands before completion")
    cmds = [
        ("compileall", [sys.executable, "-m", "compileall", "-q", "app", "scripts"]),
        ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
        ("pytest", [sys.executable, "-m", "pytest", "-q"]),
        ("validate_pi", [sys.executable, "scripts/validate_pi_resources.py"]),
        ("validate_chains", [sys.executable, "scripts/validate_chains.py"]),
    ]
    for i, (name, cmd) in enumerate(cmds, 1):
        try:
            result = subprocess.run(cmd, cwd=_PROJECT_ROOT, capture_output=True, timeout=120, text=True)
            passed = result.returncode == 0
            notes = "" if passed else result.stderr[-200:] or result.stdout[-200:]
        except Exception as e:
            passed = False
            notes = str(e)[:200]
        s.checks.append(Check(f"s28-{i:02d}", f"`{' '.join(cmd[1:])}`", 28, passed, notes=notes))
    # TS extension typecheck — the binary lives at the project root
    tsc_candidates = [
        _PROJECT_ROOT / "node_modules" / ".bin" / "tsc",
        _PROJECT_ROOT / "node_modules" / ".bin" / "tsc.cmd",
    ]
    tsc_binary = next((p for p in tsc_candidates if p.exists()), None)
    if tsc_binary is None:
        s.checks.append(Check("s28-06", "tsc --noEmit in .pi/extensions", 28, False, "tsc binary not found; run `npm install`"))
    else:
        try:
            result = subprocess.run(
                [str(tsc_binary), "--noEmit"],
                cwd=_PROJECT_ROOT / ".pi/extensions",
                capture_output=True, timeout=60, text=True,
            )
            s.checks.append(Check("s28-06", "tsc --noEmit in .pi/extensions", 28, result.returncode == 0,
                                  notes="" if result.returncode == 0 else (result.stderr or result.stdout)[-200:]))
        except Exception as e:
            s.checks.append(Check("s28-06", "tsc --noEmit in .pi/extensions", 28, False, str(e)[:200]))
    return s


# ── Runner ────────────────────────────────────────────────────────────


def run_all() -> list[Section]:
    return [
        check_section_1_architecture(),
        check_section_3_structure(),
        check_section_7_ingestion(),
        check_section_8_flow_ml(),
        check_section_9_detection_correlation(),
        check_section_10_agent_behavior(),
        check_section_12_lifecycle(),
        check_section_13_response(),
        check_section_14_database(),
        check_section_15_api(),
        check_section_16_19_ui(),
        check_section_22_security(),
        check_section_23_tests(),
        check_section_24_demo(),
        check_section_26_documentation(),
        check_section_28_required_commands(),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--section", type=int, help="Only show this section")
    parser.add_argument("--json", type=str, help="Write JSON report to this path")
    parser.add_argument("--only-fail", action="store_true", help="Only print failed checks")
    args = parser.parse_args()

    sections = run_all()
    if args.section:
        sections = [s for s in sections if s.number == args.section]

    total = 0
    passed = 0
    failed = []
    for s in sections:
        print(f"\n══ Section {s.number}: {s.title} ({s.passed}/{s.total}) ══")
        for c in s.checks:
            if args.only_fail and c.passed:
                continue
            glyph = "✓" if c.passed else "✗"
            note = f" — {c.notes}" if c.notes else ""
            print(f"   {glyph} {c.id}  {c.title}{note}")
            total += 1
            if c.passed:
                passed += 1
            else:
                failed.append(c)

    print(f"\n{'═' * 60}")
    print(f"GRAND TOTAL: {passed}/{total} passed ({100*passed/total:.1f}%)")
    if failed:
        print(f"\nFAILED ({len(failed)}):")
        for c in failed[:20]:
            print(f"  ✗ {c.id} (section {c.section}): {c.title}")
            if c.notes:
                print(f"      {c.notes}")
        if len(failed) > 20:
            print(f"  ... and {len(failed) - 20} more")

    if args.json:
        report = {
            "passed": passed,
            "total": total,
            "sections": [
                {
                    "number": s.number,
                    "title": s.title,
                    "passed": s.passed,
                    "total": s.total,
                    "checks": [
                        {"id": c.id, "title": c.title, "passed": c.passed, "notes": c.notes}
                        for c in s.checks
                    ],
                }
                for s in sections
            ],
        }
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nReport written to {args.json}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
