# TypeScript Pi Extensions

This document details the TypeScript Extensions loaded by the Pi Agent Runtime. These extensions act as validators, permission interceptors, audit gates, and event bridges.

---

## 1. Extension Catalog

### 1.1 Security Tools (`security-tools`)
- **Role**: Provides the typed interface definitions and schemas for tools exposed to the LLM agent.
- **Functionality**: Defines parameters (e.g. `incident_id`, `ip_address`), ensures correct types, implements execution timeouts, and enforces output size limits.
- **Source**: [index.ts](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/extensions/security-tools/index.ts)

### 1.2 Security Permission Gate (`security-permission-gate`)
- **Role**: Intercepts and reviews all tool/bash calls before execution.
- **Functionality**:
  - Classifies commands into low/high risk categories.
  - Denies destructive commands (`rm -rf`, cracking frameworks).
  - Routes IP blocking or quarantine actions to the operator approval queue.
  - Prevents blocking loopbacks (`127.0.0.1`), gateways, broadcast, or critical allowlisted addresses.
- **Source**: [index.ts](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/extensions/security-permission-gate/index.ts)

### 1.3 Audit Logger (`audit-logger`)
- **Role**: Records agent session start, tool invocations, parameters, results, and gate decisions.
- **Functionality**: Appends records to `/logs/tool_audit.jsonl` and `/logs/permission_gate.jsonl` in an append-only JSON Lines format.
- **Source**: [index.ts](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/extensions/audit-logger/index.ts)

### 1.4 Agent Event Bridge (`agent-event-bridge`)
- **Role**: Bridges agent events to the FastAPI server.
- **Functionality**: Streams phase starts, tool calls, findings, proposed actions, and completions. The server broadcasts these events to the Web UI using Server-Sent Events.
- **Source**: [index.ts](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/extensions/agent-event-bridge/index.ts)

### 1.5 Context Safety (`context-safety`)
- **Role**: Context filtration and sanitization.
- **Functionality**:
  - Delimits untrusted log or packet payload data.
  - Flags potential prompt-injection strings ("ignore previous instructions", "you are now root").
  - Truncates long outputs to prevent context window overflow.
- **Source**: [index.ts](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/extensions/context-safety/index.ts)
