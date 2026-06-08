# Topic 09 - Network Incident Response Orchestrator

Defensive incident-response pipeline for a network alert. The project runs
parallel recon, log collection, and PCAP feature extraction, then classifies the
incident, maps it to MITRE ATT&CK, and writes structured IR reports.

## Run

```powershell
C:\Users\LQK\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe scripts\run_demo.py
```

Outputs:

- `.pi/` submission artifact tree
- `.pi/outputs/demo/incident_report.json`
- `.pi/outputs/demo/incident_report.md`
- `reports/Topic_09_Network_IR_Orchestrator_Report.docx`

## Test

```powershell
C:\Users\LQK\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m unittest discover -s tests
```

## Package

```powershell
C:\Users\LQK\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe scripts\package_submission.py
```
