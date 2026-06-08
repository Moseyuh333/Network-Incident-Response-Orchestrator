# Topic 09 - Network Incident Response Orchestrator

## Executive Summary
Alert `ALERT-09-001` was classified as **C2 Beaconing with Data Exfiltration** with severity **critical** and confidence **0.98**.

## Parallel Pipeline
- Stage 1 ran recon, log collection, and PCAP feature extraction in parallel.
- Stage 2 ran incident classification and embedding-style profile scoring in parallel.
- Stage 3 mapped the finding to MITRE ATT&CK and produced containment steps.

## Evidence
- Source host: `ws-finance-023`
- Outbound bytes: `69,000,000`
- Beacon interval: `10.0s`

## MITRE ATT&CK
- `T1071.001` - Command and Control / Application Layer Protocol: Web Protocols
- `T1041` - Exfiltration / Exfiltration Over C2 Channel
- `T1105` - Command and Control / Ingress Tool Transfer

## Containment Plan
1. Isolate host 10.10.5.23 from user VLAN (SOC L2)
2. Block outbound traffic to 203.0.113.77 (Network Security)
3. Collect volatile endpoint evidence and full packet capture (DFIR)
4. Rotate credentials for the affected user and review OAuth tokens (IAM)
5. Open IR bridge for critical severity tracking (Incident Commander)

## Generated Files
- `incident_report.json`
- `incident_report.md`
- `.pi/` submission artifacts
