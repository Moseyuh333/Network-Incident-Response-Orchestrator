# Logical Agents

This document lists the Logical Agents operating in the **Network Incident Response Operations (N.I.R.O.)** environment. Each agent is defined by a markdown profile located under `.pi/agents/`.

---

## 1. Phase-Specific Logical Agents

### 1.1 Intake Agent (`intake-agent.md`)
- **Role**: Validates, parses, and normalizes ingested raw events.
- **Triggers**: Receipt of new API posts, syslog UDP traffic, or Suricata/Zeek file uploads.
- **Goal**: Formulate a validated baseline `intake.json` artifact containing standardized event data.

### 1.2 Evidence Agent (`evidence-agent.md`)
- **Role**: Collects internal context surrounding affected assets, user accounts, and hostnames.
- **Goal**: Gathers related logs and prior incidents to populate `evidence.json`.

### 1.3 Flow Analysis Agent (`flow-analysis-agent.md`)
- **Role**: Group packets into bidirectional flows.
- **Goal**: Extracts statistics from packet capture (PCAP) features (bytes out, flow duration, flags) to enrich the evidence.

### 1.4 Detection Agent (`detection-agent.md`)
- **Role**: Runs deterministic rule-based analysis.
- **Goal**: Identifies patterns matching ports, web patterns, or failed logons.

### 1.5 ML Anomaly Agent (`ml-anomaly-agent.md`)
- **Role**: Runs multivariate IsolationForest anomaly detection models.
- **Goal**: Computes anomaly scores for flows and outputs anomaly findings.

### 1.6 Triage Agent (`triage-agent.md`)
- **Role**: Performs incident classification.
- **Goal**: Evaluates all rule/ML findings, assigns severity weights, and outputs a consolidated `triage.json` report.

### 1.7 MITRE Agent (`mitre-agent.md`)
- **Role**: Performs MITRE ATT&CK technique mapping.
- **Goal**: Resolves findings to tactics (e.g. Discovery, Initial Access) and Technique IDs (e.g. T1046, T1110).

### 1.8 Response Planner Agent (`response-planner-agent.md`)
- **Role**: Proposes incident containment actions.
- **Goal**: Resolves alerts to safe, reversible containment recommendations (e.g., blocking an IP address).

### 1.9 Response Validator Agent (`response-validator-agent.md`)
- **Role**: Assesses risks and safety limits.
- **Goal**: Ensures no protected IP addresses (like gateways or loopbacks) are targeted for firewall blocking.

### 1.10 Report Agent (`report-agent.md`)
- **Role**: Consolidates results.
- **Goal**: Generates clean Markdown, JSON, and PDF incident reports under `.pi/reports/`.
