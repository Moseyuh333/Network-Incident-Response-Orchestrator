# System Architecture

This document describes the high-level architecture of the **Network Incident Response Operations (N.I.R.O.)** orchestrator.

---

## 1. High-Level Component View

```
                  +-----------------------------------+
                  |            Web UI (Vite)          |
                  |  - Operations Dashboard (3-col)   |
                  |  - Cytoscape Relationship Graph   |
                  |  - Live SSE Event Stream          |
                  +-----------------+-----------------+
                                    | REST / SSE
                                    v
                  +-----------------------------------+
                  |         FastAPI Backend           |
                  |  - REST Endpoints (/api/v1)       |
                  |  - Lifespan Startup/Shutdown      |
                  |  - SQLite / SQLModel Database     |
                  +--------+-----------------+--------+
                           |                 |
                           v                 v
            +----------------------+  +---------------------+
            | Orchestration Engine |  | Pi Agent Harness    |
            | - Async Queues       |  | - Markdown Profiles |
            | - Concurrency Limits |  | - Python Skills     |
            | - Phase Execution    |  | - TS Extensions     |
            +----------------------+  +---------------------+
                           |                 |
                           v                 v
                  +-----------------------------------+
                  |       Network Listeners /         |
                  |       Ingestion Adapters          |
                  |  - TCP Socket Log Collector       |
                  |  - UDP Syslog Collector           |
                  |  - Suricata & Zeek File Parsers   |
                  +-----------------------------------+
```

---

## 2. Core Components

### 2.1 Web UI Operations Console
Built with TypeScript, React, and Vite, using a cyber-tactical layout:
- **Left Panel (25%)**: Incident Locking, Agent Dispatch controls, Rules of Engagement configuration, and Ingestion queue status.
- **Center Panel (45%)**: Node-based incident relationship graph using Cytoscape.js, depicting the connections between assets, IPs, events, findings, and containment actions.
- **Right Panel (30%)**: Real-time terminal log viewer, incident entity summaries, approvals queue, and report export actions.

### 2.2 FastAPI Backend Application
Exposes versioned APIs (`/api/v1`) for:
- Event ingestion (REST JSON posts, Suricata/Zeek logs, PCAP files).
- Incident querying, lifecycle state transitions, and reporting.
- Pi agent resource loading, editing, and validation.
- Live Server-Sent Events (SSE) streaming metrics and agent operations.

### 2.3 Async Orchestration Engine
Manages incoming network security events through sequential and parallel phases using `asyncio.Queue` workers:
1. **Intake**: Event validation, parsing, normalization, and database record creation.
2. **Evidence**: Running parallel agent routines to collect logs, dns records, authentication telemetry, and PCAP features.
3. **Detection**: Running deterministic rule checks and ML IsolationForest anomaly classification.
4. **Triage**: Mapping findings to MITRE ATT&CK techniques, scoring severity, and assigning confidence levels.
5. **Response**: Proposing containment actions, running validator/policy checks, and posting actions requiring operator approval to the approval queue.

### 2.4 Pi Agent Harness & Resource Layer
Located in the `.pi/` directory, maintaining the canonical source of truth for:
- **Agents**: Markdown profiles with defined roles, input/output schemas, and allowed tools.
- **Skills**: Persistent executable scripts and SKILL.md manifests (e.g. DNS analysis, PCAP flow extraction).
- **Extensions**: TypeScript files (e.g. security-permission-gate, audit-logger) providing tool validations, safe boundaries, and lifecycle event bridging.

---

## 3. Data Ingestion Flow

1. **Ingestion**: Sockets (TCP/UDP) or REST endpoints capture logs.
2. **Normalization**: Events are parsed into standard SQLModel database structures.
3. **Detection**: Rule engines search for SSH brute force, web attacks, port scans, exfiltration, and beaconing. ML Anomaly checks are executed concurrently.
4. **Correlation**: Related events and findings are grouped into an Incident.
5. **Orchestration**: The incident ID is submitted to the ingestion queue. Workers progress the incident through the phases, invoking LLM analysis at Stage 3.
6. **Response Proposal**: Containment actions (e.g., blocking an IP) are proposed and vetted by the permission gate. High-risk actions enter `awaiting_approval` state.
7. **Approval & Containment**: An operator approves the action in the Web UI. The backend executes the corresponding adapter, verifies the result, and logs the execution.
