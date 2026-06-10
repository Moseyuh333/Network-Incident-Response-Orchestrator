"""Parallel incident response orchestration demo.

This script is intentionally defensive and lab-safe: containment actions are
simulated unless ENABLE_REAL_RESPONSE is explicitly enabled.
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.agents.incident_response_agent import IncidentResponseAgent
from app.core.paths import DATA_DIR, PI_DIR, TRIAGE_DIR, LOG_DIR, REPORT_DIR
from app.detection.rule_engine import analyze_events


MITRE_MAP: dict[str, dict[str, str]] = {
    "Port Scan": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "Brute Force": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "Web Attack": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Data Exfiltration": {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "C2 Beaconing": {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "DDoS/Flood": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "Policy Violation": {"technique": "T1040", "name": "Network Sniffing/Traffic Observation", "tactic": "Collection"},
}

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class StageResult:
    name: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class OutputPaths:
    triage_dir: Path
    log_dir: Path
    report_dir: Path

    @classmethod
    def from_base(cls, base_dir: Path) -> "OutputPaths":
        return cls(
            triage_dir=base_dir / "triage",
            log_dir=base_dir / "logs",
            report_dir=base_dir / "reports",
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)


def append_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{now_iso()} {message}\n")


def parse_events(raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for event in raw_events:
        normalized = dict(event)
        timestamp = normalized.get("timestamp")
        if isinstance(timestamp, str):
            normalized["timestamp"] = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        events.append(normalized)
    events.sort(key=lambda item: item["timestamp"])
    return events


def scope_events_to_alert(
    raw_events: list[dict[str, Any]],
    alert: dict[str, Any],
    window_minutes: int = 15,
) -> list[dict[str, Any]]:
    """Return events related to the alert by IP and time window."""
    alert_time = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
    start = alert_time - timedelta(minutes=window_minutes)
    end = alert_time + timedelta(minutes=window_minutes)
    alert_ips = {alert.get("source_ip"), alert.get("destination_ip")}
    scoped: list[dict[str, Any]] = []
    for event in raw_events:
        event_time = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        if not (start <= event_time <= end):
            continue
        if event.get("source_ip") in alert_ips or event.get("destination_ip") in alert_ips:
            scoped.append(event)
    return scoped


def collect_recon(alert: dict[str, Any]) -> StageResult:
    assets = read_json(DATA_DIR / "asset_inventory.json")
    target_ip = alert["destination_ip"]
    matched = [asset for asset in assets["assets"] if asset["ip"] == target_ip]
    return StageResult(
        "parallel_recon",
        {
            "target_ip": target_ip,
            "matched_assets": matched,
            "risk_notes": [
                "Public-facing service detected" if any(asset.get("internet_facing") for asset in matched) else "Internal asset",
                "Business criticality: " + (matched[0].get("criticality", "unknown") if matched else "unknown"),
            ],
        },
    )


def collect_logs(alert: dict[str, Any]) -> StageResult:
    raw = read_json(DATA_DIR / "security_events.json")
    relevant_raw = scope_events_to_alert(raw["events"], alert)
    events = parse_events(relevant_raw)
    findings = analyze_events(events)
    return StageResult(
        "parallel_log_collection",
        {
            "event_count": len(raw["events"]),
            "relevant_event_count": len(relevant_raw),
            "events": relevant_raw,
            "findings": findings,
        },
    )


def extract_pcap_features(alert: dict[str, Any]) -> StageResult:
    pcap = read_json(DATA_DIR / "pcap_features.json")
    related = [
        flow for flow in pcap["flows"]
        if flow["source_ip"] == alert["source_ip"] or flow["destination_ip"] == alert["destination_ip"]
    ]
    total_out = sum(flow.get("bytes_out", 0) for flow in related)
    return StageResult(
        "parallel_pcap_feature_extraction",
        {"related_flow_count": len(related), "total_bytes_out": total_out, "flows": related},
    )


def classify_incident(log_payload: dict[str, Any], pcap_payload: dict[str, Any]) -> dict[str, Any]:
    findings = log_payload["findings"]
    if not findings:
        return {"label": "Benign/Unconfirmed", "severity": "low", "confidence": 0.3, "signals": []}
    top = max(findings, key=lambda item: (SEVERITY_WEIGHT.get(item["severity"], 0), item["confidence"]))
    score = min(1.0, float(top["confidence"]) + min(0.2, pcap_payload["related_flow_count"] / 50))
    return {
        "label": top["incident_type"],
        "severity": top["severity"],
        "confidence": round(score, 2),
        "signals": top["evidence"],
        "model": "rule-weighted classifier with optional sklearn anomaly module",
    }


def score_mitre(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for finding in findings:
        attack = MITRE_MAP.get(finding["incident_type"], {})
        if attack:
            mapped.append(
                {
                    **attack,
                    "incident_type": finding["incident_type"],
                    "score": round(float(finding["confidence"]) * SEVERITY_WEIGHT.get(finding["severity"], 1) / 4, 2),
                }
            )
    mapped.sort(key=lambda item: item["score"], reverse=True)
    return mapped


def permission_gate(actions: list[str], paths: OutputPaths | None = None) -> list[dict[str, str]]:
    paths = paths or OutputPaths.from_base(PI_DIR)
    allowed_prefixes = ("simulate_",)
    decisions: list[dict[str, str]] = []
    for action in actions:
        decision = "allowed" if action.startswith(allowed_prefixes) else "blocked"
        decisions.append({"action": action, "decision": decision, "reason": "lab-safe simulated action only"})
        append_log(paths.log_dir / "permission_gate.log", f"{decision.upper()} action={action}")
    return decisions


def build_containment(classification: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    actions = ["simulate_notify_admin"]
    label = classification["label"]
    if label in {"Port Scan", "Web Attack", "Brute Force"}:
        actions.append("simulate_block_ip")
    if label in {"Web Attack", "Data Exfiltration", "C2 Beaconing"}:
        actions.append("simulate_quarantine_host")
    if label == "Brute Force":
        actions.append("simulate_disable_user")
    for finding in findings:
        for recommendation in finding.get("recommended_actions", []):
            normalized = recommendation.lower()
            if "block" in normalized and "simulate_block_ip" not in actions:
                actions.append("simulate_block_ip")
    return actions


def write_markdown_report(alert: dict[str, Any], triage: dict[str, Any], paths: OutputPaths | None = None) -> None:
    paths = paths or OutputPaths.from_base(PI_DIR)
    lines = [
        "# Ket qua Incident Response",
        "",
        f"- Alert ID: {alert['alert_id']}",
        f"- Thoi gian chay: {triage['run_started_at']}",
        f"- Phan loai: {triage['classification']['label']}",
        f"- Muc do: {triage['classification']['severity']}",
        f"- Do tin cay: {triage['classification']['confidence']}",
        f"- LLM provider: {triage['llm_analysis']['provider']} / {triage['llm_analysis']['model']}",
        f"- LLM available: {triage['llm_analysis']['available']}",
        "",
        "## MITRE ATT&CK Mapping",
    ]
    for item in triage["mitre_attack"]:
        lines.append(f"- {item['technique']} - {item['name']} ({item['tactic']}), score={item['score']}")
    lines += ["", "## Containment Steps"]
    for action in triage["containment"]["actions"]:
        lines.append(f"- {action}")
    lines += ["", "## Evidence"]
    for finding in triage["stage_1"]["logs"]["findings"]:
        lines.append(f"- {finding['incident_type']} / {finding['severity']}: {'; '.join(finding['evidence'])}")
    lines += ["", "## LLM Analysis", triage["llm_analysis"]["summary"], ""]
    if triage["llm_analysis"].get("fallback_reason"):
        lines.append(f"Fallback reason: {triage['llm_analysis']['fallback_reason']}")
    paths.report_dir.mkdir(parents=True, exist_ok=True)
    (paths.report_dir / "ket_qua.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_pipeline(
    alert_path: Path,
    output_dir: Path | None = None,
    agent: IncidentResponseAgent | None = None,
) -> dict[str, Any]:
    paths = OutputPaths.from_base(output_dir or PI_DIR)
    for path in (paths.triage_dir, paths.log_dir, paths.report_dir):
        path.mkdir(parents=True, exist_ok=True)
    alert = read_json(alert_path)
    append_log(paths.log_dir / "audit.log", f"RUN_START alert_id={alert['alert_id']}")

    with ThreadPoolExecutor(max_workers=3) as executor:
        stage1_futures = [
            executor.submit(collect_recon, alert),
            executor.submit(collect_logs, alert),
            executor.submit(extract_pcap_features, alert),
        ]
        stage1_results = [future.result() for future in stage1_futures]
        stage1 = {result.name: result.payload for result in stage1_results}

    logs = stage1["parallel_log_collection"]
    pcap = stage1["parallel_pcap_feature_extraction"]
    with ThreadPoolExecutor(max_workers=2) as executor:
        classification_future = executor.submit(classify_incident, logs, pcap)
        mitre_future = executor.submit(score_mitre, logs["findings"])
        classification = classification_future.result()
        mitre = mitre_future.result()

    actions = build_containment(classification, logs["findings"])
    agent_context = {
        "alert": alert,
        "stage_1": {
            "recon": stage1["parallel_recon"],
            "logs": logs,
            "pcap": pcap,
        },
        "classification": classification,
        "mitre_attack": mitre,
        "containment_actions": actions,
    }
    llm_analysis = (agent or IncidentResponseAgent(PI_DIR)).analyze(agent_context)
    triage = {
        "run_started_at": now_iso(),
        "alert": alert,
        "pipeline": {
            "stage_1": "parallel recon + log collection + pcap feature extraction",
            "stage_2": "parallel incident classification + MITRE scoring",
            "stage_3": "LLM agent analysis + permission-gated containment + report generation",
        },
        "stage_1": {
            "recon": stage1["parallel_recon"],
            "logs": logs,
            "pcap": pcap,
        },
        "classification": classification,
        "mitre_attack": mitre,
        "llm_analysis": llm_analysis,
        "containment": {"actions": actions, "permission_gate": permission_gate(actions, paths)},
    }

    write_json(paths.triage_dir / "incident_triage.json", triage)
    write_markdown_report(alert, triage, paths)
    append_log(paths.log_dir / "audit.log", f"RUN_END alert_id={alert['alert_id']} classification={classification['label']}")
    return triage


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Network IR orchestration pipeline.")
    parser.add_argument("--alert", default=str(DATA_DIR / "sample_alert.json"), help="Path to alert JSON")
    parser.add_argument("--output-dir", default=str(PI_DIR), help="Directory for triage, logs, and reports")
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    triage = run_pipeline(Path(args.alert), output_dir=output_dir)
    print(json.dumps({"classification": triage["classification"], "triage": str(output_dir / "triage" / "incident_triage.json")}, indent=2))


if __name__ == "__main__":
    main()
