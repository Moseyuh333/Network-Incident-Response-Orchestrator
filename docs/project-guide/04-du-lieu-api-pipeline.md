# 04 - Du Lieu, API, Pipeline

File nay giai thich ngan gon data di qua app nhu the nao.

## Data chay nhu the nao?

```text
Log/Event -> Detection -> Finding -> Incident -> Agent -> Action -> Approval
```

Nghia la:

1. Ban dua log vao.
2. App phat hien dau hieu bat thuong.
3. App tao finding.
4. Finding duoc gom thanh incident.
5. Agent phan tich incident.
6. Agent de xuat action.
7. Ban approve/reject action.

## API hay dung

### Kiem tra app

```http
GET /api/status
GET /api/v1/health
```

### Tao event

```http
POST /api/v1/events
```

Body vi du:

```json
{
  "source_ip": "192.0.2.22",
  "destination_ip": "192.168.4.113",
  "event_type": "ssh",
  "action": "failed_login",
  "severity": "high"
}
```

### Xem incidents

```http
GET /api/v1/incidents
GET /api/v1/incidents/1
```

### Goi agent phan tich incident

```http
POST /api/v1/incidents/1/agent/run
```

Body:

```json
{
  "task": "Analyze this incident and recommend safe actions."
}
```

### Xem/duyet action

```http
GET  /api/v1/actions
POST /api/v1/actions/1/approve
POST /api/v1/actions/1/reject
POST /api/v1/actions/1/execute
POST /api/v1/actions/1/rollback
```

### Luu model/key LLM

```http
PUT /api/v1/config/llm
```

Body:

```json
{
  "provider": "google",
  "model": "models/gemma-4-31b-it",
  "api_key": "paste-key-here"
}
```

API khong tra lai key.

## Pipeline CLI

Chay:

```powershell
python scripts/run_pipeline.py --alert .pi\data\sample_alert.json --output-dir .pi\runtime\manual-run
```

Pipeline lam:

1. Doc alert.
2. Doc asset/log/pcap mau trong `.pi/data`.
3. Phan loai incident.
4. Map MITRE.
5. Goi LLM agent.
6. Tao action simulated.
7. Ghi report.

## LLM loi thi sao?

Khong sao.

Neu model/key loi, app fallback sang rule-based analysis.

Ban van co:

- classification.
- severity.
- confidence.
- recommended actions.
- report.

## Action co nguy hiem khong?

Mac dinh khong.

App chi execute simulated action, vi du:

- `simulate_block_ip`
- `simulate_quarantine_host`
- `simulate_disable_user`
- `simulate_notify_admin`

High-risk action phai approve truoc.
