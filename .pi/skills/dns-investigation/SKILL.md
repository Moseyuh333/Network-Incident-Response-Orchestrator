---
name: dns-investigation
description: >
  Analyse DNS queries, identify suspicious domains, and check for beaconing.
triggers:
  - dns query
  - domain lookup
  - suspicious domain
  - dns telemetry
inputs:
  - incident_id
outputs:
  - JSON DNS summary
safety: read-only
---

# DNS Investigation Skill

## Purpose
Collect and summarize DNS request history, highlight high-frequency query domains, and identify potential command and control (C2) domains.
