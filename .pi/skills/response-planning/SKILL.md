---
name: response-planning
description: >
  Generate containment proposals (IP blocking, quarantine, disable account) based on alert classification and policy.
triggers:
  - contain
  - response plan
  - propose action
  - mitigation
inputs:
  - incident_id
outputs:
  - JSON actions summary
safety: read-only
---

# Response Planning Skill

## Purpose
Propose reversible, policy-compliant security actions to contain the network threat and prevent further damage.
