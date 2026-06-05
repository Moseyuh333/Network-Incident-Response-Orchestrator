---
name: network-ir-alert-chain
description: Alert-triggered chain with parallel collection and parallel analysis stages.
entrypoint: scripts/run_pipeline.py
---

# Chain

## Phase 0 - Alert Intake

Input: `.pi/data/sample_alert.json`

Validates required fields and initializes audit logs.

## Phase 1 - Parallel Evidence Collection

Runs concurrently:

- `collect_recon`: asset owner, exposed services, criticality.
- `collect_logs`: security events and rule detections.
- `extract_pcap_features`: flow count and byte-level indicators.

## Phase 2 - Parallel Analysis

Runs concurrently:

- `classify_incident`: selects incident label, severity, confidence.
- `score_mitre`: maps findings to MITRE ATT&CK.

## Phase 3 - Response Report

Sequentially applies the permission gate, writes triage JSON, audit logs, and `ket_qua.md`.
