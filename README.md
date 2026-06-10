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

For more details on other scenarios (Port Scan, C2 Beaconing, Data Exfiltration, and suppression), see [Demo Scenarios Guide](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/docs/demo-guide.md).
