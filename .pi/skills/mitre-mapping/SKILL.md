---
name: mitre-mapping
description: >
  Map incident type or finding details to MITRE ATT&CK tactics and techniques.
triggers:
  - mitre
  - att&ck
  - technique
  - mapping
inputs:
  - incident_type: str
outputs:
  - tactic: str
  - technique_id: str
  - technique_name: str
safety: read-only
---

# MITRE Mapping Skill

## Purpose
Look up and associate security findings with the corresponding MITRE ATT&CK framework tactics and techniques.
