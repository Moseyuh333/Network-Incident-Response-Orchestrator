---
name: auth-investigation
description: >
  Use when an incident contains repeated authentication failures,
  login anomalies, SSH brute-force indicators or account lockouts.
triggers:
  - brute force
  - failed login
  - SSH authentication
  - account lockout
inputs:
  - incident_id
outputs:
  - JSON evidence summary
safety: read-only
---

# Auth Investigation Skill

## Purpose
Analyse authentication events, count failed logins, identify brute-force patterns, and map targeted accounts.

## Inputs
- `incident_id` (int): Incident database identifier.

## Environment
- Python 3.11+
- Database access (Event, Finding models)

## Outputs
Returns a summary of authentication attempts, unique usernames targeted, and failures over time.
