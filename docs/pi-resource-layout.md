# Pi Resource Layout

This document describes the structure of the `.pi` directory, which serves as the canonical repository configuration and storage for agents, skills, extensions, chains, data, and logs.

---

## 1. Directory Structure

```text
.pi/
├── settings.json
│
├── agents/
│   ├── orchestrator-agent.md
│   ├── intake-agent.md
│   ├── evidence-agent.md
│   ├── flow-analysis-agent.md
│   ├── detection-agent.md
│   ├── ml-anomaly-agent.md
│   ├── triage-agent.md
│   ├── mitre-agent.md
│   ├── response-planner-agent.md
│   ├── response-validator-agent.md
│   └── report-agent.md
│
├── prompts/
│   ├── system.md
│   ├── investigate-incident.md
│   ├── explain-incident.md
│   ├── answer-operator.md
│   ├── generate-report.md
│   └── review-action.md
│
├── skills/
│   ├── event-ingestion/
│   │   ├── SKILL.md
│   │   └── ingest_events.py
│   ├── suricata-analysis/
│   │   ├── SKILL.md
│   │   └── parse_eve.py
│   ├── zeek-analysis/
│   │   ├── SKILL.md
│   │   └── parse_zeek.py
│   ├── pcap-flow-extraction/
│   │   ├── SKILL.md
│   │   └── extract_flows.py
│   ├── auth-investigation/
│   │   ├── SKILL.md
│   │   └── analyse_auth.py
│   ├── dns-investigation/
│   │   ├── SKILL.md
│   │   └── analyse_dns.py
│   ├── threat-intelligence/
│   │   ├── SKILL.md
│   │   └── threat_intel.py
│   ├── mitre-mapping/
│   │   ├── SKILL.md
│   │   └── mitre_lookup.py
│   ├── incident-explanation/
│   │   ├── SKILL.md
│   │   └── build_evidence_context.py
│   ├── response-planning/
│   │   ├── SKILL.md
│   │   └── propose_actions.py
│   └── report-generation/
│       ├── SKILL.md
│       └── generate_report.py
│
├── extensions/
│   ├── security-tools/
│   │   └── index.ts
│   ├── security-permission-gate/
│   │   └── index.ts
│   ├── audit-logger/
│   │   └── index.ts
│   ├── agent-event-bridge/
│   │   └── index.ts
│   └── context-safety/
│       └── index.ts
│
├── chains/
│   ├── incident-response-chain.yaml
│   ├── explain-incident-chain.yaml
│   ├── live-event-chain.yaml
│   └── report-chain.yaml
│
├── data/
│   ├── sample/
│   ├── incoming/
│   ├── normalized/
│   ├── assets/
│   ├── policies/
│   └── mitre/
│
├── artifacts/
│   └── incidents/
│
├── logs/
│   ├── agent_runs.jsonl
│   ├── tool_audit.jsonl
│   ├── permission_gate.jsonl
│   ├── pipeline.jsonl
│   └── errors.jsonl
│
└── reports/
```

---

## 2. Resource Descriptions

### 2.1 Settings (`settings.json`)
Saves configuration values for the Pi runtime framework, detailing active providers, model names, timeouts, and rate limits.

### 2.2 Agents (`agents/*.md`)
Markdown files containing frontmatter and detailed profiles for specific agents. Frontmatter defines constraints such as:
- `allowed_skills`
- `allowed_tools`
- `maximum_iterations`
- `maximum_tool_calls`
- `safety_profile` (e.g. `read-only`)

### 2.3 Prompts (`prompts/*.md`)
Reusable task prompts containing parameter tokens (e.g. `<incident_id>`) that guide LLM execution paths while enforcing source citation, distinguishing facts from inferences, and preventing prompt-injection.

### 2.4 Skills (`skills/*/`)
Folders containing a `SKILL.md` manifest and Python implementation scripts. The manifest contains triggers, input/output schemas, safety profiles, and verification commands.

### 2.5 Extensions (`extensions/*/`)
TypeScript integrations that extend Pi framework behaviors. They validate tool calls, intercept dangerous arguments (Permission Gate), log run states (Audit Logger), and push event events to the FastAPI server (Agent Event Bridge).

### 2.6 Chains (`chains/*.yaml`)
YAML DAG (Directed Acyclic Graph) configurations declaring sequential execution orders, zones of concurrency (`/parallel`), timeouts, retries, and data merges.
