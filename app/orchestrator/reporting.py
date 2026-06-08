"""Report builders for incident-response pipeline output."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_markdown_report(report: dict[str, Any]) -> str:
    """Return a concise Markdown incident report."""
    classification = report["stage_2_analysis"]["incident_classification"]
    lines = [
        "# Topic 09 - Network Incident Response Orchestrator",
        "",
        "## Executive Summary",
        (
            f"Alert `{report['alert']['alert_id']}` was classified as "
            f"**{classification['incident_type']}** with severity "
            f"**{classification['severity']}** and confidence "
            f"**{classification['confidence']}**."
        ),
        "",
        "## Parallel Pipeline",
        "- Stage 1 ran recon, log collection, and PCAP feature extraction in parallel.",
        "- Stage 2 ran incident classification and embedding-style profile scoring in parallel.",
        "- Stage 3 mapped the finding to MITRE ATT&CK and produced containment steps.",
        "",
        "## Evidence",
        f"- Source host: `{report['stage_1_collection']['recon']['source_host']['hostname']}`",
        (
            "- Outbound bytes: "
            f"`{report['stage_1_collection']['pcap_features']['total_bytes_out']:,}`"
        ),
        (
            "- Beacon interval: "
            f"`{report['stage_1_collection']['pcap_features']['avg_beacon_interval_seconds']}s`"
        ),
        "",
        "## MITRE ATT&CK",
    ]
    for item in report["mitre_attack"]:
        lines.append(
            f"- `{item['technique_id']}` - {item['tactic']} / {item['technique']}"
        )
    lines.extend(["", "## Containment Plan"])
    for step in report["containment_plan"]:
        lines.append(f"{step['step']}. {step['action']} ({step['owner']})")
    lines.extend(
        [
            "",
            "## Generated Files",
            "- `incident_report.json`",
            "- `incident_report.md`",
            "- `.pi/` submission artifacts",
        ]
    )
    return "\n".join(lines) + "\n"


def persist_reports(report: dict[str, Any], output_dir: Path) -> dict[str, str]:
    """Write JSON and Markdown report artifacts."""
    import json

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "incident_report.json"
    md_path = output_dir / "incident_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(build_markdown_report(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def report_metadata() -> dict[str, str]:
    """Return deterministic metadata used by generated reports."""
    return {
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "generator": "network-ir-orchestrator-offline",
    }
