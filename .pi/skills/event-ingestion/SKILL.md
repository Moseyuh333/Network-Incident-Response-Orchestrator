---
name: event-ingestion
description: >
  Normalize and persist incoming network events from REST, Suricata EVE, Zeek JSON, syslog, and PCAP sources.
  Assigns stable event IDs, extracts key fields, and writes normalized events for downstream detection.
triggers:
  - event ingestion
  - suricata eve
  - zeek json
  - syslog
  - pcap import
inputs:
  - raw_events: list[dict]
  - source_type: str (rest|suricata|zeek|syslog|pcap)
outputs:
  - normalized_events: list[dict]
  - event_ids: list[str]
safety: read-only
---

# Event Ingestion Skill

## Purpose
Convert heterogeneous network telemetry into a unified event schema for detection, correlation, and ML pipelines.

## When to Use
- New alerts arrive via REST API
- Suricata EVE JSON files are imported
- Zeek JSON logs are ingested
- Syslog messages are received
- PCAP files are uploaded for offline analysis

## Inputs
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| raw_events | list[dict] | Yes | Raw event records from source |
| source_type | str | Yes | One of: rest, suricata, zeek, syslog, pcap |
| sensor | str | No | Sensor identifier |

## Environment
- Python 3.11+
- Access to `app.core.config.settings`
- Database session for persistence (optional, can return normalized only)

## Procedure
1. Validate each raw event has required fields (source_ip, destination_ip, timestamp)
2. Extract and normalize: timestamp, source/destination IP/port, protocol, event_type, severity
3. Preserve source-specific fields (flow_id, http fields, dns fields, tls fields)
4. Assign stable external_event_id for idempotent ingestion
5. Write normalized events to database or return for downstream processing

## Commands
```bash
python .pi/skills/event-ingestion/ingest_events.py --source suricata --file alerts.eve.json
python .pi/skills/event-ingestion/ingest_events.py --source zeek --file conn.log.json
python .pi/skills/event-ingestion/ingest_events.py --source rest --stdin
```

## Output Schema
```json
{
  "normalized_events": [
    {
      "external_event_id": "evt-...",
      "timestamp": "2026-06-10T15:20:00Z",
      "sensor": "edge-firewall-01",
      "source_type": "suricata",
      "source_ip": "203.0.113.77",
      "destination_ip": "10.10.20.15",
      "source_port": 45210,
      "destination_port": 443,
      "protocol": "TCP",
      "event_type": "alert",
      "action": "allowed",
      "severity": "high",
      "flow_id": "flw-...",
      "normalized": {...},
      "raw": {...}
    }
  ],
  "event_ids": ["evt-...", "evt-..."]
}
```

## Interpretation Rules
- Missing timestamps default to ingestion time
- Unknown protocols default to "unknown"
- Internal IPs (RFC1918) are tagged for asset correlation
- Flow IDs preserved for bidirectional flow grouping

## Error Handling
- Malformed events are logged and skipped (not fatal)
- Duplicate external_event_id returns existing event (idempotent)
- Source-specific parse errors logged with event sample

## Safety Constraints
- Read-only: does not modify incidents, actions, or response state
- No network calls
- No shell execution
- Input size capped at 10,000 events per invocation

## Verification Command
```bash
python -m pytest tests/unit/test_event_ingestion.py -v
```