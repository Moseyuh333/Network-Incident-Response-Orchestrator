# Orchestration Chains

This document details the YAML execution chains used by the orchestration engine to coordinate phase-based incident triage.

---

## 1. Chain Definitions

### 1.1 Incident Response Chain (`incident-response-chain.yaml`)
This is the primary pipeline that runs when a network security alert triggers a new incident:
- **Phase 0 — Incident Intake**: Ingestion, validation, and schema normalization.
- **Phase 1 — Evidence Acquisition (Parallel)**:
  - `event-context-agent`: Collects related events, dns logs, and web metadata.
  - `asset-context-agent`: Retrieves business criticality, network zone, and internet-facing status.
  - `flow-analysis-agent`: Extracts PCAP bidirectional conversation metrics.
- **Phase 2 — Detection and Correlation (Parallel + Fan-out)**:
  - `rule-detection-agent`: Runs signature checks.
  - `ml-anomaly-agent`: Evaluates IsolationForest anomaly score.
  - `correlation-agent`: Correlates with existing active incidents.
- **Phase 3 — Triage (Parallel + Merge)**:
  - `triage-agent`: Classifies severity and type.
  - `mitre-agent`: Maps findings to ATT&CK tactics/techniques.
  - `threat-context-agent`: Queries reputation for external IPs.
- **Phase 4 — Response Planning (Parallel per-action)**:
  - `response-planner-agent`: Proposes reversible containment actions.
  - `response-validator-agent`: Validates scope and checks safety policies.
- **Phase 5 — Approval and Containment**: Halts for human approval on high-risk actions. Executes simulation or nftables adapter upon approval.
- **Phase 6 — Reporting**: Consolidates telemetry and generates report artifacts.

### 1.2 Explain Incident Chain (`explain-incident-chain.yaml`)
Triggered when an operator asks a question about a specific incident. It focuses on gathering evidence context and querying the LLM to explain the correlation rationale.

### 1.3 Live Event Chain (`live-event-chain.yaml`)
Subscribes to live socket listeners, parsing incoming events in real-time, grouping them into flows, and feeding them to the active detection filters.

### 1.4 Report Chain (`report-chain.yaml`)
Invoked periodically or manually to assemble historical incident data, compile timeline summaries, and output Markdown/PDF reporting packs.
