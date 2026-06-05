"""Parallel incident response orchestration demo.

This script is intentionally defensive and lab-safe: containment actions are
simulated unless ENABLE_REAL_RESPONSE is explicitly enabled.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.detection.rule_engine import analyze_events

PI_DIR = ROOT / ".pi"
DATA_DIR = PI_DIR / "data"
TRIAGE_DIR = PI_DIR / "triage"
LOG_DIR = PI_DIR / "logs"
REPORT_DIR = PI_DIR / "reports"


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
    events = parse_events(raw["events"])
    findings = analyze_events(events)
    relevant = [
        event for event in raw["events"]
        if event.get("source_ip") == alert["source_ip"] or event.get("destination_ip") == alert["destination_ip"]
    ]
    return StageResult(
        "parallel_log_collection",
        {"event_count": len(events), "relevant_event_count": len(relevant), "events": raw["events"], "findings": findings},
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


def permission_gate(actions: list[str]) -> list[dict[str, str]]:
    allowed_prefixes = ("simulate_",)
    decisions: list[dict[str, str]] = []
    for action in actions:
        decision = "allowed" if action.startswith(allowed_prefixes) else "blocked"
        decisions.append({"action": action, "decision": decision, "reason": "lab-safe simulated action only"})
        append_log(LOG_DIR / "permission_gate.log", f"{decision.upper()} action={action}")
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


def write_markdown_report(alert: dict[str, Any], triage: dict[str, Any]) -> None:
    lines = [
        "# Ket qua Incident Response",
        "",
        f"- Alert ID: {alert['alert_id']}",
        f"- Thoi gian chay: {triage['run_started_at']}",
        f"- Phan loai: {triage['classification']['label']}",
        f"- Muc do: {triage['classification']['severity']}",
        f"- Do tin cay: {triage['classification']['confidence']}",
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
    (REPORT_DIR / "ket_qua.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_pipeline(alert_path: Path) -> dict[str, Any]:
    for path in (TRIAGE_DIR, LOG_DIR, REPORT_DIR):
        path.mkdir(parents=True, exist_ok=True)
    alert = read_json(alert_path)
    append_log(LOG_DIR / "audit.log", f"RUN_START alert_id={alert['alert_id']}")

    with ThreadPoolExecutor(max_workers=3) as executor:
        stage1_futures = [
            executor.submit(collect_recon, alert),
            executor.submit(collect_logs, alert),
            executor.submit(extract_pcap_features, alert),
        ]
        stage1 = {future.result().name: future.result().payload for future in stage1_futures}

    logs = stage1["parallel_log_collection"]
    pcap = stage1["parallel_pcap_feature_extraction"]
    with ThreadPoolExecutor(max_workers=2) as executor:
        classification_future = executor.submit(classify_incident, logs, pcap)
        mitre_future = executor.submit(score_mitre, logs["findings"])
        classification = classification_future.result()
        mitre = mitre_future.result()

    actions = build_containment(classification, logs["findings"])
    triage = {
        "run_started_at": now_iso(),
        "alert": alert,
        "pipeline": {
            "stage_1": "parallel recon + log collection + pcap feature extraction",
            "stage_2": "parallel incident classification + MITRE scoring",
            "stage_3": "sequential report and containment plan generation",
        },
        "stage_1": {
            "recon": stage1["parallel_recon"],
            "logs": logs,
            "pcap": pcap,
        },
        "classification": classification,
        "mitre_attack": mitre,
        "containment": {"actions": actions, "permission_gate": permission_gate(actions)},
    }

    write_json(TRIAGE_DIR / "incident_triage.json", triage)
    write_markdown_report(alert, triage)
    append_log(LOG_DIR / "audit.log", f"RUN_END alert_id={alert['alert_id']} classification={classification['label']}")
    return triage


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Network IR orchestration pipeline.")
    parser.add_argument("--alert", default=str(DATA_DIR / "sample_alert.json"), help="Path to alert JSON")
    args = parser.parse_args()
    triage = run_pipeline(Path(args.alert))
    print(json.dumps({"classification": triage["classification"], "triage": str(TRIAGE_DIR / "incident_triage.json")}, indent=2))


if __name__ == "__main__":
    main()
