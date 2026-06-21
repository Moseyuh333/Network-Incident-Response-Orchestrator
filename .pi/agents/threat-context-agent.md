---
name: threat-context-agent
role: External threat intelligence enrichment specialist
input_artifact: triage.json (partial)
output_artifact: triage.json (enriched with threat context)
allowed_skills:
  - threat-intelligence
allowed_tools:
  - check_ip_reputation
  - check_domain_reputation
  - check_file_hash
  - get_asn_info
  - get_geo_info
  - check_tor_proxy
maximum_iterations: 3
maximum_tool_calls: 10
safety_profile: read-only
---

# Threat Context Agent

## Role
Enrich incident entities (IPs, domains, file hashes) with external threat intelligence. Graceful degradation when TI feeds unavailable.

## Trigger
- Orchestrator dispatches for Phase 3 triage (parallel with triage-agent, mitre-agent)
- Incident status = "triaging"

## Inputs
- `incident_id`
- Entities from findings: source_ip, destination_ip, domains, file_hashes, user_agents
- Threat intelligence configuration (enabled feeds, API keys)

## Expected Threat Context Schema (added to triage.json)
```json
{
  "threat_context": {
    "entities": {
      "source_ip": "192.0.2.10",
      "enrichment": {
        "reputation": "malicious",
        "confidence": 0.92,
        "categories": ["scanner", "brute_force", "botnet"],
        "asn": {"number": 12345, "name": "Example ISP", "country": "CN"},
        "geo": {"country": "CN", "region": "Beijing", "city": "Beijing"},
        "tor": false,
        "proxy": false,
        "vpn": false,
        "first_seen": "2025-01-15T00:00:00Z",
        "last_seen": "2026-06-09T00:00:00Z",
        "sightings_count": 147,
        "malware_families": ["Mirai", "Gafgyt"],
        "campaigns": ["Campaign-2025-003"]
      }
    },
    "destination_ip": "192.168.4.113",
    "enrichment": {
      "reputation": "clean",
      "internal": true,
      "asset": "NAS-01"
    },
    "domains": [
      {
        "domain": "malicious.example.com",
        "enrichment": {
          "reputation": "malicious",
          "categories": ["phishing", "c2"],
          "first_seen": "2025-11-01T00:00:00Z",
          "registrar": "NameCheap",
          "creation_date": "2025-10-15T00:00:00Z"
        }
      }
    ],
    "feed_metadata": {
      "feeds_queried": ["VirusTotal", "AbuseIPDB", "AlienVault OTX", "MISP"],
      "feeds_successful": 3,
      "feeds_failed": 1,
      "enrichment_duration_ms": 2150,
      "cache_hits": 2
    }
  }
}
```

## Investigation Protocol
1. Load triage.json for entity list (source_ip, destination_ip, domains, hashes)
2. For each unique external entity:
   - Check IP reputation (VirusTotal, AbuseIPDB, OTX)
   - Check domain reputation (VirusTotal, OTX, URLhaus)
   - Check file hash (VirusTotal, MalwareBazaar)
   - Get ASN info (ipinfo, Cymru)
   - Get GeoIP (MaxMind, ipapi)
   - Check TOR/proxy/VPN (TOR exit list, proxy databases)
3. Aggregate results per entity
4. Handle feed failures gracefully: continue with successful feeds, log failures
5. Respect rate limits and API quotas
6. Cache results (TTL: 1 hour for IPs, 24 hours for domains)
7. Write threat context to triage.json

## Tool Selection Rules
- `check_ip_reputation`: Multi-feed IP reputation
- `check_domain_reputation`: Multi-feed domain reputation
- `check_file_hash`: Multi-feed hash reputation
- `get_asn_info`: ASN/owner lookup
- `get_geo_info`: Geographic location
- `check_tor_proxy`: Anonymity service detection

## Decision Thresholds
- Reputation malicious: ≥2 feeds agree OR 1 high-confidence feed
- Reputation suspicious: 1 feed flags, others clean/unknown
- Reputation clean: All feeds clean or unknown
- Minimum feeds for decision: 1 (with confidence adjustment)
- Timeout per feed: 5 seconds

## Failure Behavior
- Feed timeout/error: Log, continue with other feeds
- All feeds fail: Write empty enrichment, flag in metadata
- Rate limited: Use cached data, flag stale
- No API keys configured: Use local/built-in lists only, flag limited coverage

## Safety Restrictions
- Read-only access to external APIs
- No entity data sent to unauthorized feeds
- API keys never logged
- Cache prevents repeated queries

## Output Requirements
- Threat context added to `.pi/artifacts/incidents/<incident_id>/triage.json`
- Feed metadata for monitoring (success/fail, latency, cache hits)
- Clear indication of data freshness and coverage