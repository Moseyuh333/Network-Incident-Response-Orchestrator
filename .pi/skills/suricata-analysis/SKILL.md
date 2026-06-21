---
name: suricata-analysis
description: >
  Parse and analyze Suricata EVE JSON logs to extract alerts, flows, DNS, HTTP, TLS, and anomaly records.
  Produces normalized findings for correlation and triage.
triggers:
  - suricata
  - eve json
  - ids alerts
  - network ids
inputs:
  - eve_file: str (path to EVE JSON file)
  - incident_id: int (optional, for incident-scoped analysis)
outputs:
  - alerts: list[dict]
  - flows: list[dict]
  - dns_records: list[dict]
  - http_records: list[dict]
  - tls_records: list[dict]
safety: read-only
---

# Suricata Analysis Skill

## Purpose
Extract structured security telemetry from Suricata EVE JSON output for incident detection and analysis.

## When to Use
- Suricata EVE JSON files are available
- Network IDS alerts need triage
- Flow records need analysis for C2 beaconing or exfiltration
- DNS/HTTP/TLS metadata needed for investigation

## Inputs
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| eve_file | str | Yes | Path to Suricata EVE JSON file |
| incident_id | int | No | Limit analysis to events related to this incident |

## Environment
- Python 3.11+
- `app.collectors.suricata.parse_eve_file` function

## Procedure
1. Read EVE JSON file line by line
2. Parse each record using `parse_eve_record`
3. Categorize by event_type: alert, flow, dns, http, tls, anomaly
4. Extract key indicators: source/dest IP, ports, protocol, signatures, metadata
5. If incident_id provided, filter to related events
6. Return structured findings for each category

## Commands
```bash
python .pi/skills/suricata-analysis/parse_eve.py --file alerts.eve.json
python .pi/skills/suricata-analysis/parse_eve.py --file alerts.eve.json --incident-id 42
```

## Output Schema
```json
{
  "alerts": [
    {
      "timestamp": "2026-06-10T15:20:00Z",
      "signature_id": 2001219,
      "signature": "ET WEB_SERVER Possible SQL Injection",
      "severity": 2,
      "source_ip": "203.0.113.77",
      "destination_ip": "10.10.20.15",
      "source_port": 45210,
      "destination_port": 443,
      "protocol": "TCP",
      "flow_id": "flw-abc123",
      "metadata": {...}
    }
  ],
  "flows": [
    {
      "flow_id": "flw-abc123",
      "source_ip": "203.0.113.77",
      "destination_ip": "10.10.20.15",
      "source_port": 45210,
      "destination_port": 443,
      "protocol": "TCP",
      "start": "2026-06-10T15:20:00Z",
      "end": "2026-06-10T15:20:05Z",
      "bytes_toserver": 1024,
      "bytes_toclient": 2048,
      "pkts_toserver": 10,
      "pkts_toclient": 15
    }
  ],
  "dns_records": [...],
  "http_records": [...],
  "tls_records": [...]
}
```

## Interpretation Rules
- Alert severity 1-3 map to high/medium/low
- Flow records enable bidirectional traffic analysis
- DNS records reveal C2 domains, DGA, tunneling
- HTTP records show web attack payloads, user agents
- TLS records reveal certificate anomalies, JA3 fingerprints

## Error Handling
- Malformed lines skipped with warning
- Missing file returns empty results with error
- Large files processed in streaming mode (no full load)

## Safety Constraints
- Read-only: no database writes, no network calls
- File access limited to provided path
- Memory bounded by streaming parser

## Verification Command
```bash
python -m pytest tests/unit/test_suricata_analysis.py -v
```