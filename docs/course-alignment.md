# Course Alignment & CDIO Mapping

This document details how the **Network Incident Response Operations (N.I.R.O.)** orchestrator aligns with the academic objectives of the network programming, AI agent, and defensive cybersecurity curriculum.

---

## 1. CDIO Framework Alignment

### 1.1 Conceive
- **Security Problem**: Automated, high-velocity network attacks (e.g. brute-force, web exploits, C2 beaconing) target internal enterprise assets. Human operators alone cannot analyze telemetry, correlate findings, and isolate hosts rapidly enough.
- **Incident Response Requirements**: Ingest log sources, extract bi-directional packet flows, run detection engines, perform machine learning analysis, mapping to MITRE ATT&CK techniques, proposing containment actions, and obtaining operator approval.
- **AI-Agent and ML Role**: Integrate LLM reasoning (via Pi agent harness) to orchestrate data collections, explain complex attacks, and propose containment actions based on structured evidence.
- **Threat Model & Safety**: Establish a defensive-only boundary. Block offensive features (e.g. exploit generation, credential cracking). Define strict network boundaries and safe simulated adapters for response execution.

### 1.2 Design
- **Async Architecture**: Multi-stage queued pipeline allowing asynchronous overlap of incoming alerts (Incident A in Triage, Incident B in Detection, Incident C in Ingestion).
- **Socket Collectors**: Async TCP socket server for JSON logs and UDP socket server for syslog format.
- **Data Model**: SQLModel/SQLite database to track and index events, flows, findings, incidents, agent runs, audit logs, and response actions.
- **PI Resources**: Centralized agents, prompts, skills, and extensions under the `.pi` folder to maintain agent context, tools, and permission hooks.
- **UI UX Plan**: Three-column Operations Dashboard in 100% dark mode (M.I.N.A Red Team C2 style adapted for defense). Cytoscape-based entity relationship graph and auto-scrolling agent log terminal.

### 1.3 Implement
- **Collectors**: Implement `asyncio.start_server` and Datagram receiver protocols.
- **PCAP Flow Extractor**: Read PCAPs offline, group bidirectional packets into five-tuple flows, and compute flow duration, IAT, packet/byte counts, and TCP flags.
- **ML Anomaly Detection**: IsolationForest classification pipeline for network flow anomaly scoring.
- **Pi API & UI**: FastAPI `/api/v1` backend endpoints. React/Vite front-end dashboard using Cytoscape.js and Server-Sent Events (SSE) for real-time telemetry.

### 1.4 Operate
- **Monitoring**: Live operations panel displaying active incidents, queue depth, CPU metrics, and database statistics.
- **Response Gate & Rollback**: Intercept containment commands, block dangerous commands (e.g., blocking gateway, deleting files), record decisions, execute simulated rule changes, and handle expiration timers/manual rollbacks.

---

## 2. Highlighted Concepts & Code References

### 2.1 Network & Socket Programming
- **TCP Server**: Implemented using `asyncio.start_server` to receive network events.
- **UDP Syslog**: Implemented using custom asyncio datagram protocol wrapper tracking source addresses.
- **PCAP Flow Extraction**: Groups forward and reverse packets into a bidirectional conversation flow (five-tuple).
  - Code: [extract_flows.py](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/pcap-flow-extraction/extract_flows.py)

### 2.2 Async I/O & Concurrency
- **`asyncio.gather`**: Executes Stage 1 collections (Logs, Recon, PCAP features) and Stage 2 classification in parallel.
- **`asyncio.Semaphore`**: Restricts the maximum number of concurrent incidents being processed by queue workers.
- **`asyncio.wait_for`**: Wraps external tool calls and agent executions with timeouts to prevent pipeline hangs.
- **`aiohttp.ClientSession`**: Reuses TCP connections for outbound HTTP calls (e.g., threat intelligence reputation checks).
  - Code: [engine.py](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/app/orchestration/engine.py)

### 2.3 AI-Agent & LLM Mechanics
- **Pi Agent Harness**: Maintains state, reads agent profiles, and invokes skills from the canonical `.pi/` directory.
- **Function Calling & Tool Execution**: Exposes system state (incidents, findings, events, actions) as typed tools.
- **Parallel Tool Calls**: Executes multiple read-only checks in parallel to minimize model turn overhead.
- **Prompt Injection Defense**: Validates and strips untrusted data, labels data boundaries, and prevents "ignore previous instruction" injection attempts from log messages.
- **Structured Output**: Models all findings, triage records, and response plans using Pydantic and JSON Schema.
  - Code: [v1.py](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/app/api/v1.py)

### 2.4 Machine Learning Pipeline
- **IsolationForest Anomaly Detector**: Scans incoming flow logs for volumetric anomalies, outputs anomaly scores, and falls back gracefully when libraries or scalers are missing.
  - Code: [anomaly_detector.py](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/app/detection/anomaly_detector.py)

### 2.5 Security, Safety, & Policy Gates
- **Permission Gate**: Intercepts high-risk actions (IP block, quarantine, account disable), classifies risk, blocks destructive behavior, and routes items to the Approval Queue.
- **Audit Logging**: Append-only JSONL files capturing agent executions, tool arguments, permission gate decisions, and database changes.
- **Protected Address Protection**: Explicitly prevents blocking loopback, broadcast, default gateways, and critical local servers.
  - Code: [security-permission-gate](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/extensions/security-permission-gate/index.ts)
