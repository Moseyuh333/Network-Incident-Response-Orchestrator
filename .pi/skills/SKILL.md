---
name: network-ir-orchestration
description: Runs a defensive network incident response workflow: collect recon, logs, and PCAP features in parallel; classify incident severity; map findings to MITRE ATT&CK; and generate containment actions plus a structured IR report.
inputs:
  - alert JSON with source_ip, destination_ip, alert_id, timestamp, and summary
outputs:
  - triage JSON
  - audit logs
  - permission gate logs
  - Markdown IR result
---

# Network IR Orchestration Skill

Use this skill when a network security alert needs a repeatable triage workflow.

## Behavior

1. Validate the incoming alert.
2. Launch parallel Stage 1 collectors:
   - recon collector from asset inventory
   - log collector from firewall/web/auth events
   - PCAP feature extractor from network flow summaries
3. Launch parallel Stage 2 analysis:
   - rule/ML-weighted incident classifier
   - MITRE ATT&CK technique scorer
4. Run a permission gate before containment.
5. Write final incident response artifacts.

## Safety

Containment defaults to simulated actions only. Real blocking or quarantine must be explicitly enabled in a controlled lab.
