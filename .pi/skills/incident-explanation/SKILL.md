---
name: incident-explanation
description: >
  Gather full incident context, findings, evidence, and target asset metadata to build a structured context document.
triggers:
  - explain
  - summary
  - context
  - incident explanation
inputs:
  - incident_id
outputs:
  - JSON evidence context
safety: read-only
---

# Incident Explanation Skill

## Purpose
Assemble a unified JSON document containing target host characteristics, network logs, and security alert details for analysts or upstream reasoning.
