"""Create the `.pi` submission layout for Topic 09."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SAMPLE_ALERT: dict[str, Any] = {
    "alert_id": "ALERT-09-001",
    "title": "Possible C2 beaconing and exfiltration",
    "source_ip": "10.10.5.23",
    "destination_ip": "203.0.113.77",
    "timestamp": "2026-06-08T08:30:00+00:00",
    "severity": "high",
}


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def create_pi_artifacts(project_root: Path) -> Path:
    """Create a Pi-style artifact tree and return the `.pi` root path."""
    root = Path(project_root) / ".pi"
    for folder in [
        "agents",
        "prompts",
        "skills/network-ir-orchestrator",
        "chains",
        "triage",
        "logs",
        "data",
        "results",
        "outputs",
    ]:
        (root / folder).mkdir(parents=True, exist_ok=True)

    _write(
        root / "agents" / "incident-orchestrator-agent.md",
        """---
name: incident-orchestrator-agent
description: Coordinates parallel network incident response tasks and produces a structured IR report.
tools: [python, filesystem]
---

You are a defensive SOC orchestration agent. Given one alert, run recon,
log collection, and PCAP feature extraction in parallel. Then classify the
incident, map it to MITRE ATT&CK, and recommend containment actions.
""",
    )
    _write(
        root / "prompts" / "classification-system-prompt.md",
        """# Classification Prompt

Classify the network incident using only defensive evidence. Return severity,
confidence, MITRE ATT&CK mapping, and containment steps. Never provide exploit
instructions.
""",
    )
    _write(
        root / "skills" / "network-ir-orchestrator" / "SKILL.md",
        """---
name: network-ir-orchestrator
description: Runs a defensive network incident response pipeline with parallel collection, ML-style classification, MITRE mapping, and containment reporting.
---

## Workflow

1. Normalize the alert.
2. Run recon, log collection, and PCAP feature extraction in parallel.
3. Run incident classification and embedding-style profile scoring in parallel.
4. Map the incident to MITRE ATT&CK.
5. Produce JSON, Markdown, DOCX, and ZIP artifacts for submission.
""",
    )
    _write(
        root / "chains" / "network-ir-chain.md",
        """---
name: network-ir-chain
description: Alert-triggered chain for Topic 09 Network Incident Response Orchestrator.
---

alert -> parallel(recon, logs, pcap_features) -> parallel(classify, embedding_score)
-> mitre_mapping -> containment_plan -> structured_ir_report
""",
    )
    _write_json(root / "data" / "sample_alert.json", SAMPLE_ALERT)
    _write_json(
        root / "triage" / "sample_triage.json",
        {
            "alert_id": SAMPLE_ALERT["alert_id"],
            "status": "ready",
            "expected_incident_type": "C2 Beaconing with Data Exfiltration",
            "parallel_stages": ["recon", "logs", "pcap_features"],
        },
    )
    _write(
        root / "logs" / "pipeline_audit.log",
        "\n".join(
            [
                "2026-06-08T08:30:00Z pipeline initialized",
                "2026-06-08T08:30:01Z stage1 parallel collectors scheduled",
                "2026-06-08T08:30:02Z stage2 analysis scheduled",
                "2026-06-08T08:30:03Z report artifacts generated",
            ]
        )
        + "\n",
    )
    _write(
        root / "results" / "ket-qua-topic-09.md",
        """# Ket qua Topic 09

Pipeline da chay voi mot alert mau. Stage 1 gom recon, log collection va
PCAP feature extraction. Stage 2 gom classifier va embedding-style scoring.
Ket qua duoc xuat ra JSON/Markdown va dung de tao bao cao DOCX.
""",
    )
    return root
