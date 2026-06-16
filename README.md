# N.I.R.O. - Network Incident Response Operations

Defensive network incident response orchestrator with LLM-assisted triage and automated safe containment capabilities.

> [!WARNING]
> **Defensive Safety Statement**: This project is exclusively defensive. It does not implement, support, or compile offensive security tools (e.g. exploit generation, credential attacks, payloads, or reverse shells). All blocking and isolation features default to simulated mode to prevent accidental outages in testing environments.

---

## 1. System Overview

N.I.R.O. acts as an incident command center, parsing telemetry, extracting bidirectional packet flows, running rule and machine learning engines, and orchestrating triage phases via the Pi Agent Runtime.

### 1.1 Key Features
- **Bidirectional PCAP Parsing**: Extract 5-tuple flow metrics (durations, flags, packet length distribution, IAT).
- **ML Anomaly Detection**: Unsupervised flow-based anomaly classification using an `IsolationForest` pipeline.
- **Async Stage Queue**: Concurrent orchestration loops that prevent alert bottlenecks.
- **TypeScript Pi Extensions**: Safety gates, audit logs, event bridges, and prompt injection filters.
- **Cyber-Tactical Operations Console**: A high-density 3-column dark-mode dashboard with Cytoscape relationship graphs and live terminal streams.

---

## 2. Directory Layout

```text
security-agents/
├── .pi/                     # Canonical Pi Agent Resources
│   ├── agents/              # Markdown Agent Profiles
│   ├── prompts/             # Task Prompts
│   ├── skills/              # Executable Procedures & Python scripts
│   ├── extensions/          # TypeScript validators & permission gates
│   └── data/policies/       # Enterprise Security Policies
├── app/                     # FastAPI Backend Application
│   ├── collectors/          # TCP/UDP Socket Listeners & log parsers
│   ├── detection/           # Rule Engine & ML Anomaly modules
│   └── db/                  # SQLModel session & database schemas
├── ui/                      # React / Vite / TypeScript Operations Console
├── scripts/                 # Administration and demo scripts
└── docs/                    # Component & architecture design specifications
```

---

## 3. Quick Start

### 3.1 Prerequisite Setup
Configure python dependencies:
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[ml,dev]
Copy-Item .env.example .env
```

### 3.2 Initialize the Database & Run Tests
```bash
python -m compileall app scripts
python -m pytest
```

### 3.3 Validate Pi Resources
Ensure Pi configurations conform to registries:
```bash
python scripts/validate_pi_resources.py
python scripts/validate_chains.py
```

### 3.4 Build UI Console
```bash
cd ui
npm install
npm run build
cd ..
```

### 3.5 Launch N.I.R.O. Command Server
Run the FastAPI web application serving both APIs and the compiled Web UI:
```bash
python -m uvicorn app.web.server:app --reload
```
Open `http://localhost:8000/operations` in your browser.

---

## 4. Demo Scenarios & Pipeline Checks

To test the system end-to-end, execute the following commands in another terminal:

1. **Load a synthetic SSH brute force scenario**:
   ```bash
   python scripts/load_demo.py --scenario ssh-bruteforce
   ```
   *Expected Output: Logs complete detection of 1 finding and creates an Incident ID.*

2. **Trigger the AI agent triage and containment proposal**:
   ```bash
   python scripts/run_incident.py --latest
   ```
   *Expected Output: Agent completes runs, outputs a Markdown report summary, and registers proposed IP block recommendations in the approvals queue.*

## 7.5 Pi Coding Agent Integration

N.I.R.O. is designed to run under the [Pi Coding Agent](https://github.com/microsoft/pi-coding-agent) runtime
(`@earendil-works/pi-coding-agent`). Pi is the canonical agent harness — it loads
`.pi/agents/`, `.pi/prompts/`, `.pi/skills/`, `.pi/extensions/`, and `.pi/chains/`
and orchestrates the tool-calling loop.

### Install Pi

```bash
# Pi is published as an npm workspace dependency (already wired in package.json).
cd <project>
npm install
```

Pi is invoked via the workspace script. To run a Pi session against the
incident-response chain:

```bash
npx pi run --skill incident-response-chain --alert data/sample_alert.json
```

### Pi settings (`.pi/settings.json`)

The runtime reads the following settings. Create the file if it is
absent — Pi falls back to environment variables in that case.

```json
{
  "llm": {
    "provider": "google",
    "model": "gemini-2.5-flash",
    "apiKeyEnv": "LLM_API_KEY"
  },
  "maxIterations": 8,
  "maxToolCalls": 15,
  "toolTimeoutSeconds": 30,
  "outputTruncation": 4096
}
```

### Skill / extension loading

Pi auto-loads every directory under `.pi/skills/` and `.pi/extensions/`.
A resource is "active" only if its `SKILL.md` / `index.ts` validates. Run
the validators to see the active set:

```bash
python scripts/validate_pi_resources.py
python scripts/validate_chains.py
```

### Fallback when Pi is unavailable

If Pi is not installed in the environment (e.g. a CI runner without
Node.js), N.I.R.O. still works end-to-end through the Python pipeline.
The same `run_incident.py` CLI and `/api/analyze` endpoint are used in
both modes; only the agent loop differs. Tests pass either way — see
section 8 below.

---

## 7.6 LLM Configuration

N.I.R.O. can use Google Gemini, Anthropic Claude, OpenAI, or local
Ollama. The provider is selected via `LLM_PROVIDER` in `.env`.

### Google Gemini (default)

```bash
LLM_PROVIDER=google
LLM_MODEL=gemini-2.5-flash
LLM_API_KEY=***    # or GOOGLE_API_KEY
LLM_MAX_TOKENS=***
LLM_TEMPERATURE=0.1
```

`gemini-2.5-flash` is the recommended default — fast, schema-aware, and
cheap. `gemma-4-31b-it` is also available but slower on long prompts.

### Offline mode (no LLM)

Leave the API key empty. N.I.R.O. runs in fully-deterministic fallback:
the rule engine + ML detector produce findings, and the agent emits a
template-based analysis citing the rule evidence. To force this mode:

```bash
LLM_API_KEY=
GOOGLE_API_KEY=
```

Or simply remove those lines from `.env`. The system runs every demo
scenario with zero network calls.

### Ollama (local)

```bash
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1:8b
LLM_API_BASE=http://localhost:11434
```

Make sure `ollama serve` is running and the model is pulled:

```bash
ollama pull llama3.1:8b
ollama serve
```

### Anthropic / OpenAI

```bash
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-20250514
LLM_API_KEY=***
```

---

## 7.7 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `LLM provider not configured` | Empty key in `.env` | Set `LLM_API_KEY` (offline mode is OK too) |
| `503 UNAVAILABLE` from Google | Quota exceeded or model overloaded | Switch to a different model, or wait and retry |
| UI shows "no incidents" | DB is empty | Run `python scripts/load_demo.py --scenario ssh-bruteforce` |
| `ModuleNotFoundError: pypdf` | Dev dep not installed | `pip install -e ".[dev]"` |
| `tsc not found` in `validate_pi` | TypeScript not installed | `npm install` in project root |

## 7.8 Known limitations

- ML anomaly detector is unsupervised — it flags statistical outliers
  but does not classify attack family. Combine with rule engine for
  family labels.
- LLM `gemma-4-31b-it` may return empty text on long structured-output
  prompts. Use `gemini-2.5-flash` instead.
- Free-tier Gemini API has 20 requests/day quota. The LLM integration
  test suite (opt-in) costs ~6 requests per full run.
- PCAP upload supports offline extraction; live capture is not
  implemented in the default deployment.

---
