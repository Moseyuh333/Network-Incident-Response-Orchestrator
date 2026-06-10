---
name: threat-intelligence
description: >
  Lookup reputation, host details, Tor exit status, and previous malicious sightings for IP addresses or domains.
triggers:
  - reputation
  - threat intel
  - ip reputation
  - tor node
inputs:
  - target_ip: str
  - target_domain: str (optional)
outputs:
  - reputation_score: float
  - category: str
safety: read-only
---

# Threat Intelligence Skill

## Purpose
Check external entity details against known indicators of compromise (IOCs). Ensures external threat details are enriched.
