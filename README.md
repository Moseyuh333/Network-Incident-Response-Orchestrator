# N.I.R.O. — Network Incident Response Orchestrator

> **Defensive security tool** với LLM-assisted triage và automated safe containment.
> Phân tích sự cố mạng, đề xuất MITRE mapping + response actions, xuất báo cáo 4 định dạng (`.md` + `.json` + `.txt` + `.docx`).

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Node.js 18+](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests: 44+](https://img.shields.io/badge/tests-44%2B-success.svg)](#5-tests--validation)

---

## 📋 Mục Lục

1. [Tổng Quan](#1-tổng-quan)
2. [Tính Năng](#2-tính-năng)
3. [Cài Đặt](#3-cài-đặt)
4. [Khởi Động Nhanh](#4-khởi-động-nhanh)
5. [Tests & Validation](#5-tests--validation)
6. [Cấu Hình LLM](#6-cấu-hình-llm)
7. [Cấu Trúc Project](#7-cấu-trúc-project)
8. [Pi Coding Agent](#8-pi-coding-agent)
9. [Report Generation](#9-report-generation)
10. [Troubleshooting](#10-troubleshooting)
11. [Defense-in-Depth](#11-defense-in-depth)
12. [Tài Liệu Tham Khảo](#12-tài-liệu-tham-khảo)

---

## 1. Tổng Quan

**N.I.R.O.** (Network Incident Response Operations) là một **defensive security orchestrator** được thiết kế để:

- Thu thập network telemetry (firewall logs, Zeek, Suricata, PCAP flows)
- Phát hiện các mẫu tấn công phổ biến: brute-force, port-scan, C2 beaconing, data exfiltration, web attack
- Tạo incident records với severity scoring + MITRE ATT&CK mapping
- Chạy LLM agent phân tích ngữ nghĩa + đề xuất response actions
- Sinh báo cáo sự cố tự động ở **4 format**: Markdown, JSON, Plain Text, Word (`.docx`)

```
[Network Telemetry] → [Collectors] → [Detection Engine] → [Incidents]
                                                              ↓
                              [Reports .md/.json/.txt/.docx] ← [LLM Agent]
```

Hệ thống chạy dưới [Pi Coding Agent](https://github.com/microsoft/pi-coding-agent) runtime — load `.pi/agents/`, `.pi/skills/`, `.pi/extensions/`, `.pi/chains/` để điều phối multi-phase pipeline.

> ⚠️ **Defensive-only**: Tool này **không** exploit, **không** payload, **không** credential attack. Tất cả containment actions mặc định ở **simulated mode** để tránh gây outage ngoài ý muốn.

---

## 2. Tính Năng

### 2.1 Detection
- **Rule Engine**: brute-force threshold, port-scan detector, C2 beaconing detection, exfiltration volume, flood detector
- **ML Anomaly**: IsolationForest pipeline cho flow-based anomaly classification
- **Correlation**: Nhóm nhiều findings thành 1 incident dựa trên source/dest IP overlap

### 2.2 LLM-Assisted Triage
- Multi-provider: Google Gemini, Anthropic Claude, OpenAI, **TokenRouter (MiniMax-M3)**, Ollama local
- Schema-enforced JSON output (Pydantic validation)
- Prompt-injection defense (UNTRUSTED_DATA tags + scrubber)
- Fallback về rule-based analysis khi LLM không khả dụng

### 2.3 Response Safety
- 4 built-in actions: `simulate_block_ip`, `simulate_quarantine_host`, `simulate_disable_user`, `simulate_notify_admin`
- Mặc định `ENABLE_REAL_RESPONSE=false` → tất cả actions là **simulated**
- Human-in-the-loop approval queue cho mọi containment action
- Verification step sau execute

### 2.4 Reporting (5 format)
| Format | File | Mục đích |
|---|---|---|
| Markdown | `<id>.md` | Source of truth, GitHub/GitLab rendering |
| JSON | `<id>.json` | Machine-readable, SIEM ingest |
| Plain Text | `<id>.txt` | SIEM logs, `grep` search |
| Word | `<id>.docx` | Báo cáo chính thức, in ấn, gửi CISO |
| PDF | `<id>.pdf` | Universal — in ấn, email, lưu trữ |

Xem chi tiết tại [§ 9 Report Generation](#9-report-generation).

### 2.5 Web UI
- FastAPI backend + React/Vite/TypeScript dashboard
- Cytoscape relationship graphs
- Live terminal streams
- Dark-mode, high-density 3-column layout

---

## 3. Cài Đặt

### 3.1 Yêu Cầu Hệ Thống

| Thành phần | Version | Kiểm tra |
|---|---|---|
| Python | 3.11+ | `python --version` |
| Node.js | 18+ | `node --version` |
| Git Bash | Windows | (terminal POSIX-style) |
| pip | 24+ | `pip --version` |

### 3.2 Setup Virtual Environment

```bash
# Di chuyển vào project
cd "D:/New folder/Network-Incident-Response-Orchestrator"

# Tạo venv
python -m venv .venv

# Activate (Git Bash trên Windows)
source .venv/Scripts/activate

# Hoặc PowerShell
.\.venv\Scripts\Activate.ps1

# Hoặc Linux/macOS
source .venv/bin/activate
```

### 3.3 Cài Dependencies

Có **3 file requirements** tùy mục đích:

```bash
# ① Runtime only (production)
pip install -r requirements.txt

# ② Runtime + report.docx support
pip install -r requirements.txt -r requirements-reports.txt

# ③ Runtime + dev/test
pip install -r requirements.txt -r requirements-dev.txt

# Full (dev + reports)
pip install -r requirements.txt -r requirements-dev.txt -r requirements-reports.txt
```

Hoặc dùng editable mode (khuyến nghị cho dev):

```bash
pip install -e .[dev,reports]
```

### 3.4 Cài Pi Coding Agent

```bash
npm install
```

Lệnh này cài `@earendil-works/pi-coding-agent` (workspace devDep trong `package.json`).

### 3.5 Khởi Tạo `.env`

```bash
cp .env.example .env
```

Mặc định `.env.example` ở **offline mode** — chạy đủ demo mà không cần API key. Để dùng LLM thật, xem [§ 6 Cấu Hình LLM](#6-cấu-hình-llm).

---

## 4. Khởi Động Nhanh

### 4.1 Validate Project Resources

```bash
# 15 agents + 14 skills trong .pi/
python scripts/validate_pi_resources.py

# 4 chains trong .pi/chains/
python scripts/validate_chains.py
```

Cả hai phải in `[+] ... validation succeeded`.

### 4.2 Chạy Demo End-to-End

```bash
# ① Load scenario SSH brute-force (tạo Incident trong DB)
.venv/Scripts/python.exe scripts/load_demo.py --scenario ssh-bruteforce

# ② Chạy LLM agent phân tích incident mới nhất
.venv/Scripts/python.exe scripts/run_incident.py --latest

# ③ Generate report (4 format)
.venv/Scripts/python.exe .pi/skills/report-generation/generate_report.py --incident-id 7

# ④ Xem reports
ls .pi/reports/
# INC-000007.md   INC-000007.json
# INC-000007.txt  INC-000007.docx
```

### 4.3 Khởi Động Web UI

```bash
.venv/Scripts/python.exe -m uvicorn app.web.server:app --reload
```

Mở `http://localhost:8000/operations` trong browser.

### 4.4 Available Demo Scenarios

| Scenario | Mô tả |
|---|---|
| `ssh-bruteforce` | Nhiều SSH login fail từ 1 IP |
| `port-scan` | Quét nhiều port từ 1 IP |
| `c2-beaconing` | Kết nối định kỳ đến C2 server |
| `data-exfil` | Outbound data lớn bất thường |
| `false-positive` | Traffic hợp lệ (negative test) |

```bash
.venv/Scripts/python.exe scripts/load_demo.py --scenario <name>
```

---

## 5. Tests & Validation

### 5.1 Pytest (44+ tests)

```bash
# Full suite
.venv/Scripts/python.exe -m pytest -v

# Chỉ report generation (3 tests mới)
.venv/Scripts/python.exe -m pytest tests/test_report_generation.py -v

# Security scenarios (25 attack patterns)
.venv/Scripts/python.exe -m pytest tests/security_scenarios/ -v

# TokenRouter provider
.venv/Scripts/python.exe -m pytest tests/test_tokenrouter_provider.py -v
```

### 5.2 LLM Integration Tests (opt-in, tốn quota)

```bash
RUN_LLM_TESTS=1 .venv/Scripts/python.exe -m pytest tests/llm_integration/ -v
```

### 5.3 Audit / Compliance

```bash
.venv/Scripts/python.exe tests/audit/audit.py --json audit-report.json
.venv/Scripts/python.exe tests/audit/llm_compliance.py --json llm-compliance.json
```

### 5.4 Lint

```bash
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m ruff format .
```

---

## 6. Cấu Hình LLM

### 6.1 Providers

| Provider | `.env` config | Ưu điểm |
|---|---|---|
| **Google Gemini** (mặc định) | `LLM_PROVIDER=google`, `LLM_MODEL=gemini-2.5-flash` | Schema-aware, nhanh, rẻ |
| **TokenRouter** | `LLM_PROVIDER=tokenrouter`, `LLM_MODEL=MiniMax-M3` | Reasoning model, OpenAI-compatible |
| **Anthropic Claude** | `LLM_PROVIDER=anthropic`, `LLM_MODEL=claude-sonnet-4-20250514` | Reasoning mạnh |
| **Ollama local** | `LLM_PROVIDER=ollama`, `LLM_MODEL=llama3.1:8b` | Không cần internet |

### 6.2 Offline Mode (mặc định)

Để chạy **không cần** API key, để trống:

```bash
LLM_API_KEY=
GOOGLE_API_KEY=
```

Hệ thống tự động fallback về rule-based analysis. Đủ cho mọi demo scenario.

### 6.3 TokenRouter (đã test)

```bash
LLM_PROVIDER=tokenrouter
LLM_API_BASE=https://api.tokenrouter.com/v1
LLM_API_KEY=<your-key>
LLM_MODEL=MiniMax-M3
LLM_MAX_TOKENS=1024
LLM_TEMPERATURE=0.1
```

Provider adapter ở `app/llm/providers.py:174` (`TokenRouterProvider`) — OpenAI-compatible HTTP qua `httpx`. Có resilience layer:
- 3 attempts, exponential backoff capped 4s
- 30s deadline tổng
- 503/UNAVAILABLE fail-fast (không retry overloaded model)
- Strip `think` blocks + markdown fences trước khi parse JSON

---

## 7. Cấu Trúc Project

```
Network-Incident-Response-Orchestrator/
├── app/                          # FastAPI backend
│   ├── agents/                   # LLM agent runtime (incident_response_agent.py, tools.py)
│   ├── api/                      # REST endpoints (v1.py)
│   ├── collectors/               # Network telemetry ingest
│   ├── core/                     # Config (config.py), paths, redaction
│   ├── db/                       # SQLModel session + schemas
│   ├── detection/                # Rule + ML engine
│   ├── incidents/                # Incident lifecycle
│   ├── llm/                      # Provider adapters (Google / TokenRouter / Anthropic / Ollama)
│   ├── models/                   # SQLModel schemas
│   ├── orchestration/            # Pipeline runners
│   ├── plugins/                  # Plugin registry
│   ├── response/                 # Containment actions
│   ├── schemas/                  # Pydantic models
│   ├── services/                 # Business logic
│   ├── skills/                   # In-repo skills
│   └── web/                      # FastAPI web server (serves `ui/dist/`)
├── .pi/                          # Pi Coding Agent resources
│   ├── agents/                   # 15 agent profiles (.md)
│   ├── prompts/                  # System + 4 task prompts
│   ├── skills/                   # 14 executable skills
│   │   └── report-generation/    # ← Skill này generate .docx + .txt + .md + .json
│   ├── extensions/               # TypeScript validators
│   ├── chains/                   # 4 orchestration chains
│   ├── data/                     # Sample alerts, policies, models
│   └── reports/                  # Generated reports (output)
├── scripts/                      # CLI tools
│   ├── load_demo.py              # Load demo scenario
│   ├── run_incident.py           # Run agent trên incident
│   ├── run_pipeline.py           # Full pipeline
│   ├── train_ml.py               # Train IsolationForest
│   ├── validate_pi_resources.py  # Validate .pi/ assets
│   └── validate_chains.py        # Validate chains
├── tests/                        # Pytest (44+ tests)
│   ├── test_report_generation.py # 3 tests cho report skill
│   ├── security_scenarios/       # 25 attack scenarios
│   ├── llm_integration/          # Opt-in LLM tests
│   └── audit/                    # Compliance audit
├── ui/                           # React/Vite/TypeScript dashboard
├── docs/                         # Architecture docs (xem § 12)
├── niro.db                       # SQLite database
├── pyproject.toml                # Project metadata
├── requirements.txt              # Runtime deps
├── requirements-dev.txt          # Dev/test deps
├── requirements-reports.txt      # Optional python-docx
├── package.json                  # npm workspace (Pi agent)
├── package-lock.json
└── README.md                     # ← File này
```

---

## 8. Pi Coding Agent

N.I.R.O. chạy dưới **Pi Coding Agent runtime** (`@earendil-works/pi-coding-agent`). Pi load 5 resource types từ `.pi/`:

| Directory | Số lượng | Mô tả |
|---|---|---|
| `.pi/agents/` | 15 | Agent profiles (intake, detection, mitre, response, **report**, …) |
| `.pi/prompts/` | 6 | System prompt + 5 task prompts |
| `.pi/skills/` | 14 | Executable skills (event-ingestion, mitre-mapping, **report-generation**, …) |
| `.pi/extensions/` | 5 | TypeScript validators, permission gates, audit loggers |
| `.pi/chains/` | 4 | Orchestration chains (incident-response, explain-incident, live-event, **report**) |

### 8.1 Chạy 1 Chain Thủ Công

```bash
npx pi run --skill incident-response-chain --alert .pi/data/sample_alert.json
```

### 8.2 Validate Pi Resources

```bash
python scripts/validate_pi_resources.py
python scripts/validate_chains.py
```

Mỗi agent `.md` cần YAML frontmatter với 6 trường bắt buộc: `name`, `role`, `input_artifact`, `output_artifact`, `allowed_skills`, `allowed_tools`.

Mỗi skill cần `SKILL.md` + ít nhất 1 file `.py` implementation.

### 8.3 Fallback Khi Pi Không Khả Dụng

Nếu môi trường không có Node.js (CI runner chẳng hạn), N.I.R.O. vẫn chạy end-to-end qua Python pipeline:

```bash
python scripts/load_demo.py --scenario ssh-bruteforce
python scripts/run_incident.py --latest
```

Cùng CLI, cùng API `/api/analyze` — chỉ khác agent loop.

---

## 9. Report Generation

### 9.1 Skill `.pi/skills/report-generation/`

Tạo **5 file artefact** từ 1 incident:

| Format | File | Mục đích | Viewer |
|---|---|---|---|
| Markdown | `<id>.md` | Source of truth | GitHub/GitLab |
| JSON | `<id>.json` | Machine-readable | SIEM, scripts |
| Plain text | `<id>.txt` | Log-friendly | `grep`, `tail` |
| Word | `<id>.docx` | Formatted report | MS Word, LibreOffice |
| PDF | `<id>.pdf` | Universal document | Adobe Reader, browser |

### 9.2 Code Path

```
main() 
  ├─ _snapshot(incident, findings, actions, audits)  # dict thuần (no ORM)
  ├─ write <id>.md      # giữ nguyên Markdown
  ├─ write <id>.json    # structured JSON
  ├─ write <id>.txt     # _markdown_to_text: strip **bold** / `code` / heading
  ├─ write <id>.docx    # _write_docx: python-docx headings + bullets + tables
  └─ write <id>.pdf     # _write_pdf: reportlab SimpleDocTemplate (A4, Helvetica)
```

### 9.3 Best-Effort `.docx` & `.pdf`

Nếu `python-docx` hoặc `reportlab` chưa cài, skill vẫn ghi các file còn lại và in warning:

```
[!] python-docx not installed — skipping <id>.docx
[!] reportlab not installed — skipping <id>.pdf
```

Cài đầy đủ:

```bash
pip install -r requirements-reports.txt   # python-docx + reportlab
```

### 9.4 Cú Pháp Sử Dụng

```bash
# Qua CLI (sau khi đã có incident trong DB)
.venv/Scripts/python.exe .pi/skills/report-generation/generate_report.py --incident-id 7

# Qua Pi chain (tự động trong pipeline)
# .pi/chains/report-chain.yaml → report-agent → report-generation skill
```

### 9.5 Output JSON

```json
{
  "incident_id": 7,
  "public_id": "INC-000007",
  "markdown_report": "D:\\...\\.pi\\reports\\INC-000007.md",
  "json_report": "D:\\...\\.pi\\reports\\INC-000007.json",
  "text_report": "D:\\...\\.pi\\reports\\INC-000007.txt",
  "docx_report": "D:\\...\\.pi\\reports\\INC-000007.docx",
  "status": "success"
}
```

---

## 10. Troubleshooting

| # | Symptom | Nguyên nhân | Fix |
|---|---|---|---|
| 1 | `ModuleNotFoundError: fastapi` | Chưa activate venv | `source .venv/Scripts/activate` |
| 2 | `ModuleNotFoundError: docx` | Thiếu python-docx | `pip install -r requirements-reports.txt` |
| 3 | `LLM provider not configured` | `.env` thiếu key | Set `LLM_API_KEY=***` hoặc để trống để chạy offline |
| 4 | `503 UNAVAILABLE` từ Google | Quota exceeded | Switch model hoặc đợi quota reset |
| 5 | UI shows "no incidents" | DB rỗng | `python scripts/load_demo.py --scenario ssh-bruteforce` |
| 6 | `tsc not found` trong validate | Node chưa cài | `npm install` ở project root |
| 7 | `DetachedInstanceError` | SQLAlchemy 2.x expire-on-commit | Đã fix trong test (snapshot dict + `expire_on_commit=False`) |
| 8 | `No module named pytest` | Chưa cài dev extras | `pip install -r requirements-dev.txt` |
| 9 | `ValidationError: schema` | LLM trả về JSON không đúng schema | Fallback tự động về template analysis |
| 10 | Free-tier quota hit | Gemini 20 req/day | Switch sang TokenRouter hoặc đợi |

---

## 11. Defense-in-Depth

> **N.I.R.O. là defensive security tool. Không khai thác, không payload, không credential attack.**

Các safe-by-default properties:

1. **Simulated actions**: `ENABLE_REAL_RESPONSE=false` mặc định. Để thật sự block IP, cần opt-in explicit + allowlist cụ thể.
2. **Human-in-the-loop**: Mọi containment action phải qua approval queue trước khi execute.
3. **Audit log**: Mọi state change được log vào `AuditEntry` với actor + before/after state.
4. **Prompt injection defense**: `<UNTRUSTED_DATA>` tags + scrubber trong `incident_response_agent._sanitise_context()`.
5. **Schema validation**: LLM output phải pass Pydantic schema trước khi trust.
6. **PI safety gates**: TypeScript validators trong `.pi/extensions/security-permission-gate/` enforce permission boundaries.

Xem chi tiết tại `docs/response-safety.md` và `SECURITY.md`.

---

## 12. Tài Liệu Tham Khảo

### 12.1 Architecture & Design (`docs/`)

| File | Nội dung |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | System architecture, component view, data flow |
| [`docs/pi-resources.md`](docs/pi-resources.md) | **15 Pi agents + 14 skills + 4 chains + 5 extensions + `.pi/` layout** (consolidated) |
| [`docs/api.md`](docs/api.md) | REST API endpoints (`/api/v1/*`) |
| [`docs/network-ingestion.md`](docs/network-ingestion.md) | Collectors (TCP/UDP, Zeek, Suricata, PCAP) |
| [`docs/ml-pipeline.md`](docs/ml-pipeline.md) | IsolationForest training & inference |
| [`docs/response-safety.md`](docs/response-safety.md) | Containment actions, approval workflow |
| [`docs/ui-ux.md`](docs/ui-ux.md) | Web dashboard design |
| [`docs/demo-guide.md`](docs/demo-guide.md) | Demo script cho presentation |

### 12.2 Vietnamese Guides (`docs/project-guide/`)

Hướng dẫn song ngữ cho người mới:

| File | Nội dung |
|---|---|
| [`docs/project-guide/01-bat-dau-nhanh.md`](docs/project-guide/01-bat-dau-nhanh.md) | Bắt đầu nhanh |
| [`docs/project-guide/02-huong-dan-ui.md`](docs/project-guide/02-huong-dan-ui.md) | Hướng dẫn sử dụng UI |
| [`docs/project-guide/03-tuy-bien-agent-skill-chain.md`](docs/project-guide/03-tuy-bien-agent-skill-chain.md) | Tuỳ biến agent/skill/chain |
| [`docs/project-guide/04-du-lieu-api-pipeline.md`](docs/project-guide/04-du-lieu-api-pipeline.md) | Dữ liệu & API pipeline |
| [`docs/project-guide/05-loi-thuong-gap.md`](docs/project-guide/05-loi-thuong-gap.md) | Lỗi thường gặp |

### 12.3 External Links

- **Pi Coding Agent**: https://github.com/microsoft/pi-coding-agent
- **python-docx**: https://python-docx.readthedocs.io/
- **Pydantic**: https://docs.pydantic.dev/
- **SQLModel**: https://sqlmodel.tiangolo.com/
- **FastAPI**: https://fastapi.tiangolo.com/

---

## 📜 License

MIT — xem [LICENSE](LICENSE).

## 👤 Author

**Moseyuh333**

## 🙏 Acknowledgments

- Microsoft Pi Coding Agent team
- Google Gemini, Anthropic Claude, TokenRouter
- Open-source security community

---

> 💡 **Tip**: Để chạy full pipeline từ scratch:
> ```bash
> python -m venv .venv && source .venv/Scripts/activate
> pip install -r requirements.txt -r requirements-dev.txt -r requirements-reports.txt
> npm install
> python scripts/validate_pi_resources.py && python scripts/validate_chains.py
> .venv/Scripts/python.exe scripts/load_demo.py --scenario ssh-bruteforce
> .venv/Scripts/python.exe scripts/run_incident.py --latest
> .venv/Scripts/python.exe .pi/skills/report-generation/generate_report.py --incident-id 7
> ls .pi/reports/  # 4 files generated
> ```
