---
name: zeek-analysis
description: >
  Parse and analyze Zeek JSON logs (conn, dns, http, ssl, notice) to extract network connections,
  DNS queries, HTTP transactions, TLS handshakes, and notices for correlation and triage.
triggers:
  - zeek
  - bro
  - conn log
  - dns log
  - http log
  - ssl log
  - notice log
inputs:
  - zeek_file: str (path to Zeek JSON log file)
  - log_type: str (conn|dns|http|ssl|notice)
  - incident_id: int (optional)
outputs:
  - connections: list[dict]
  - dns_records: list[dict]
  - http_records: list[dict]
  - tls_records: list[dict]
  - notices: list[dict]
safety: read-only
---

# Zeek Analysis Skill

## Purpose
Extract structured network telemetry from Zeek (formerly Bro) JSON logs for incident detection and analysis.

## When to Use
- Zeek JSON logs are available
- Network connection analysis needed
- DNS query/response analysis for C2, tunneling, DGA
- HTTP transaction analysis for web attacks
- TLS handshake analysis for certificate anomalies, JA3
- Zeek notices for policy violations, anomalies

## Inputs
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| zeek_file | str | Yes | Path to Zeek JSON log file |
| log_type | str | No | Filter to specific log type: conn, dns, http, ssl, notice |
| incident_id | int | No | Limit analysis to events related to this incident |

## Environment
- Python 3.11+
- `app.collectors.zeek.parse_zeek_file` function

## Procedure
1. Read Zeek JSON log file line by line
2. Parse each record using `parse_zeek_record`
3. Categorize by log type (inferred from fields or log_type parameter)
4. Extract key fields: UID, timestamps, IPs, ports, protocol, service, metadata
5. If incident_id provided, filter to related events
6. Return structured findings for each category

## Commands
```bash
python .pi/skills/zeek-analysis/parse_zeek.py --file conn.log.json --type conn
python .pi/skills/zeek-analysis/parse_zeek.py --file dns.log.json --type dns
python .pi/skills/zeek-analysis/parse_zeek.py --file http.log.json --type http
```

## Output Schema
```json
{
  "connections": [
    {
      "uid": "CkZ5f23KxV8",
      "timestamp": "2026-06-10T15:20:00Z",
      "source_ip": "203.0.113.77",
      "destination_ip": "10.10.20.15",
      "source_port": 45210,
      "destination_port": 443,
      "protocol": "tcp",
      "service": "ssl",
      "duration": 5.2,
      "orig_bytes": 1024,
      "resp_bytes": 2048,
      "orig_pkts": 10,
      "resp_pkts": 15,
      "conn_state": "SF"
    }
  ],
  "dns_records": [
    {
      "uid": "DxZ5f23KxV8",
      "timestamp": "2026-06-10T15:20:00Z",
      "source_ip": "10.10.20.15",
      "destination_ip": "8.8.8.8",
      "query": "malicious-c2.example.com",
      "qtype": "A",
      "rcode": "NOERROR",
      "answers": ["203.0.113.77"]
    }
  ],
  "http_records": [...],
  "tls_records": [...],
  "notices": [...]
}
```

## Interpretation Rules
- Connection state `SF` = normal completion, `S0` = no response, `REJ` = rejected
- Long durations + low bytes may indicate C2 beaconing
- DNS queries to suspicious TLDs, high entropy domains flagged
- HTTP with suspicious URIs, user agents, or POST data flagged
- TLS with self-signed certs, mismatched SNI, rare JA3 flagged

## Error Handling
- Malformed lines skipped with warning
- Missing file returns empty results with error
- Unknown log_type processes all record types

## Safety Constraints
- Read-only: no database writes, no network calls
- File access limited to provided path
- Memory bounded by streaming parser

## Verification Command
```bash
python -m pytest tests/unit/test_zeek_analysis.py -v
```