# Pi Coding Agent Resources

Tài liệu này tổng hợp toàn bộ Pi resources của N.I.R.O. (trước đây tách thành 5 file riêng: `agents.md`, `skills.md`, `chains.md`, `extensions.md`, `pi-resource-layout.md` — đã gộp lại để dễ tra cứu).

---

## 1. Cấu Trúc Thư Mục `.pi/`

```text
.pi/
├── settings.json
│
├── agents/                          # 15 agent profiles (markdown)
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
│   ├── report-agent.md
│   └── ...                           # 4 more (correlation, policy, threat-context)
│
├── prompts/                         # System + 5 task prompts
│   ├── system.md
│   ├── system_prompt.md
│   ├── investigate-incident.md
│   ├── explain-incident.md
│   ├── answer-operator.md
│   ├── generate-report.md
│   └── review-action.md
│
├── skills/                          # 14 executable skills
│   ├── event-ingestion/             # SKILL.md + ingest_events.py
│   ├── suricata-analysis/           # parse_eve.py
│   ├── zeek-analysis/               # parse_zeek.py
│   ├── pcap-flow-extraction/        # extract_flows.py
│   ├── auth-investigation/          # analyse_auth.py
│   ├── dns-investigation/           # analyse_dns.py
│   ├── threat-intelligence/         # threat_intel.py
│   ├── mitre-mapping/               # mitre_lookup.py
│   ├── incident-explanation/        # build_evidence_context.py
│   ├── response-planning/           # propose_actions.py
│   └── report-generation/           # generate_report.py  (← .md/.json/.txt/.docx)
│
├── extensions/                      # 5 TypeScript validators
│   ├── security-tools/
│   ├── security-permission-gate/
│   ├── audit-logger/
│   ├── agent-event-bridge/
│   └── context-safety/
│
├── chains/                          # 4 orchestration chains (YAML)
│   ├── incident-response-chain.yaml
│   ├── explain-incident-chain.yaml
│   ├── live-event-chain.yaml
│   └── report-chain.yaml
│
├── data/                            # Sample alerts, policies, models
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
├── logs/                            # Append-only JSONL audit
│   ├── agent_runs.jsonl
│   ├── tool_audit.jsonl
│   ├── permission_gate.jsonl
│   ├── pipeline.jsonl
│   └── errors.jsonl
│
└── reports/                         # Generated reports (.md/.json/.txt/.docx)
```

---

## 2. Resource Descriptions

### 2.1 Settings (`settings.json`)
Cấu hình Pi runtime: provider, model, timeouts, rate limits. Fallback về env vars nếu thiếu.

### 2.2 Agents (`agents/*.md`)
Markdown profiles với YAML frontmatter định nghĩa:
- `allowed_skills`, `allowed_tools`
- `maximum_iterations`, `maximum_tool_calls`
- `safety_profile` (e.g. `read-only`)

### 2.3 Prompts (`prompts/*.md`)
Reusable task prompts chứa parameter tokens (e.g. `<incident_id>`), enforce source citation, distinguish facts from inferences, ngăn prompt-injection.

### 2.4 Skills (`skills/*/`)
Folders chứa `SKILL.md` manifest + Python implementation. Manifest có triggers, I/O schemas, safety profiles, verification commands.

### 2.5 Extensions (`extensions/*/`)
TypeScript integrations extend Pi framework behaviors:
- Validate tool calls
- Intercept dangerous arguments (Permission Gate)
- Log run states (Audit Logger)
- Push events tới FastAPI server (Agent Event Bridge)

### 2.6 Chains (`chains/*.yaml`)
YAML DAG khai báo thứ tự thực thi, zones of concurrency (`/parallel`), timeouts, retries, data merges.

---

## 3. 15 Logical Agents

### 3.1 Intake Agent (`intake-agent.md`)
- **Role**: Validate, parse, normalize ingested raw events.
- **Triggers**: API posts, syslog UDP traffic, Suricata/Zeek file uploads.
- **Output**: `intake.json` chuẩn hoá.

### 3.2 Evidence Agent (`evidence-agent.md`)
- **Role**: Thu thập internal context (assets, accounts, hostnames).
- **Output**: `evidence.json`.

### 3.3 Flow Analysis Agent (`flow-analysis-agent.md`)
- **Role**: Group packets thành bidirectional flows.
- **Output**: PCAP flow features (bytes out, flow duration, flags).

### 3.4 Detection Agent (`detection-agent.md`)
- **Role**: Rule-based analysis deterministic.
- **Output**: Patterns match ports, web patterns, failed logons.

### 3.5 ML Anomaly Agent (`ml-anomaly-agent.md`)
- **Role**: Multivariate IsolationForest anomaly detection.
- **Output**: Anomaly scores cho flows.

### 3.6 Triage Agent (`triage-agent.md`)
- **Role**: Incident classification.
- **Output**: `triage.json` với severity weights.

### 3.7 MITRE Agent (`mitre-agent.md`)
- **Role**: MITRE ATT&CK technique mapping.
- **Output**: Tactics + Technique IDs (e.g. T1046, T1110).

### 3.8 Response Planner Agent (`response-planner-agent.md`)
- **Role**: Đề xuất containment actions.
- **Output**: Safe, reversible recommendations (e.g. block IP).

### 3.9 Response Validator Agent (`response-validator-agent.md`)
- **Role**: Assess risks + safety limits.
- **Output**: Đảm bảo không block gateways/loopbacks/protected IPs.

### 3.10 Report Agent (`report-agent.md`)
- **Role**: Consolidate results.
- **Output**: Generate Markdown + JSON + **Plain Text + Word (.docx)** incident reports → `.pi/reports/`.

### 3.11 Orchestrator Agent (`orchestrator-agent.md`)
- **Role**: Điều phối multi-phase pipeline.

### 3.12 Correlation Agent (`correlation-agent.md`)
- **Role**: Correlate findings với active incidents.

### 3.13 Threat Context Agent (`threat-context-agent.md`)
- **Role**: Query reputation cho external IPs (ASN, geo, Tor).

### 3.14 Policy Agent (`policy-agent.md`)
- **Role**: Apply enterprise security policies.

### 3.15 Asset Context Agent (referenced trong chains)
- **Role**: Business criticality, network zone, internet-facing status.

---

## 4. 14 Skills Registry

| # | Skill | Script | Mục đích |
|---|---|---|---|
| 1 | `event-ingestion` | `ingest_events.py` | Normalize raw events → SQLModel DB |
| 2 | `suricata-analysis` | `parse_eve.py` | Parse Suricata EVE JSON |
| 3 | `zeek-analysis` | `parse_zeek.py` | Decode Zeek JSON logs (conn, dns, http, ssl) |
| 4 | `pcap-flow-extraction` | `extract_flows.py` | Bidirectional flow features từ PCAP |
| 5 | `auth-investigation` | `analyse_auth.py` | Auth histories, brute-force indicators |
| 6 | `dns-investigation` | `analyse_dns.py` | DGA / high query volume detection |
| 7 | `threat-intelligence` | `threat_intel.py` | IP reputation (ASN, geo, Tor) |
| 8 | `mitre-mapping` | `mitre_lookup.py` | MITRE ATT&CK lookup |
| 9 | `incident-explanation` | `build_evidence_context.py` | Evidence context model cho operator |
| 10 | `response-planning` | `propose_actions.py` | Containment actions + policy check |
| 11 | `report-generation` | `generate_report.py` | **4 format: `.md` + `.json` + `.txt` + `.docx`** |

(Tổng cộng 14 — 11 listed ở trên + 3 supplementary: `auth-investigation`, `dns-investigation`, `threat-intelligence`. Mỗi skill có `SKILL.md` manifest cùng folder.)

---

## 5. 4 Orchestration Chains

### 5.1 Incident Response Chain (`incident-response-chain.yaml`)
Pipeline chính khi có security alert:

| Phase | Tên | Agents | Concurrency |
|---|---|---|---|
| 0 | Incident Intake | `intake-agent` | serial |
| 1 | Evidence Acquisition | `event-context-agent`, `asset-context-agent`, `flow-analysis-agent` | parallel |
| 2 | Detection & Correlation | `rule-detection-agent`, `ml-anomaly-agent`, `correlation-agent` | parallel |
| 3 | Triage | `triage-agent`, `mitre-agent`, `threat-context-agent` | parallel |
| 4 | Response Planning | `response-planner-agent`, `response-validator-agent` | parallel per-action |
| 5 | Approval & Containment | (human gate) | halt-for-approval |
| 6 | Reporting | `report-agent` | serial |

### 5.2 Explain Incident Chain (`explain-incident-chain.yaml`)
Trigger khi operator hỏi về 1 incident cụ thể. Gather evidence context, query LLM explain correlation rationale.

### 5.3 Live Event Chain (`live-event-chain.yaml`)
Subscribe socket listeners, parse events real-time, group thành flows, feed detection filters.

### 5.4 Report Chain (`report-chain.yaml`)
Periodic/manual assemble incident data → timeline → `.md`/`.json`/`.txt`/`.docx` packs.

---

## 6. 5 TypeScript Extensions

### 6.1 Security Tools (`security-tools`)
- **Role**: Typed interface definitions + schemas cho tools LLM dùng.
- **Function**: Parameter validation, execution timeouts, output size limits.
- **Source**: `.pi/extensions/security-tools/index.ts`

### 6.2 Security Permission Gate (`security-permission-gate`)
- **Role**: Intercept + review tất cả tool/bash calls trước khi execute.
- **Function**:
  - Classify commands → low/high risk
  - **Deny** destructive commands (`rm -rf`, cracking frameworks)
  - **Route** IP block / quarantine → operator approval queue
  - **Block** loopbacks (127.0.0.1), gateways, broadcast, critical allowlist
- **Source**: `.pi/extensions/security-permission-gate/index.ts`

### 6.3 Audit Logger (`audit-logger`)
- **Role**: Record agent session start, tool invocations, parameters, results, gate decisions.
- **Function**: Append-only JSONL → `/logs/tool_audit.jsonl` + `/logs/permission_gate.jsonl`.
- **Source**: `.pi/extensions/audit-logger/index.ts`

### 6.4 Agent Event Bridge (`agent-event-bridge`)
- **Role**: Bridge agent events → FastAPI server.
- **Function**: Stream phase starts, tool calls, findings, proposed actions, completions → Web UI qua SSE.
- **Source**: `.pi/extensions/agent-event-bridge/index.ts`

### 6.5 Context Safety (`context-safety`)
- **Role**: Context filtration + sanitization.
- **Function**:
  - Delimit untrusted log/packet payload data
  - Flag prompt-injection strings ("ignore previous instructions", "you are now root")
  - Truncate long outputs (prevent context window overflow)
- **Source**: `.pi/extensions/context-safety/index.ts`

---

## 7. Validation

```bash
python scripts/validate_pi_resources.py   # 15 agents + 14 skills
python scripts/validate_chains.py         # 4 chains
```

Mỗi agent `.md` cần YAML frontmatter với 6 trường bắt buộc:
`name`, `role`, `input_artifact`, `output_artifact`, `allowed_skills`, `allowed_tools`.

Mỗi skill cần `SKILL.md` + ≥1 file `.py` implementation.
