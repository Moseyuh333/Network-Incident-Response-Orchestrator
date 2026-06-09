# Network Incident Response Orchestrator

Defensive network incident response pipeline for Topic 09 - Lap trinh Mang.

The project demonstrates an alert-triggered IR flow:

1. Stage 1 runs recon collection, security log collection, and PCAP feature extraction in parallel.
2. Stage 2 runs incident classification and MITRE ATT&CK mapping/scoring in parallel.
3. Stage 3 produces JSON triage output, audit logs, and a Markdown incident report with containment steps.

Real containment is disabled by default. The sample project only writes simulated response actions.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[ml]
Copy-Item .env.example .env
python scripts\run_pipeline.py --alert .pi\data\sample_alert.json
```

Outputs are written to:

- `.pi/triage/incident_triage.json`
- `.pi/logs/audit.log`
- `.pi/logs/permission_gate.log`
- `.pi/reports/ket_qua.md`

## Example Prompts

- "Run the incident pipeline for alert ALERT-2026-09-001 and summarize containment."
- "Classify this network incident and map it to MITRE ATT&CK."
- "Generate an IR report from the latest triage JSON."
