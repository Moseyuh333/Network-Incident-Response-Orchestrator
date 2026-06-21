# 05 - Loi Thuong Gap

## UI khong thay thay doi moi

Ly do: FastAPI dang serve file build cu trong `ui/dist`.

Sua:

```powershell
cd ui
npm run build
cd ..
```

Restart server.

## Khong vao duoc `http://127.0.0.1:8000/`

Kiem tra server co chay khong:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen
```

Neu port bi ket:

```powershell
Stop-Process -Id <PID> -Force
```

Chay lai:

```powershell
python -m uvicorn app.web.server:app --host 127.0.0.1 --port 8000
```

## Agent khong goi duoc LLM

Kiem tra trong tab `ML Models`:

- Provider co dung khong.
- Model name co dung khong.
- API key da save chua.

Kiem tra bang API:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/config/llm
```

Neu LLM loi, app van fallback, khong phai app chet.

## Pi CLI khong chay

Kiem tra:

```powershell
npx pi --version
```

Neu loi, chay:

```powershell
npm install
```

## Khong co incident nao

Vao `Operations` va bam demo:

- `DEMO: SSH BRUTE FORCE`
- `DEMO: SCANS`
- `DEMO: C2 BEACON`

Sau do xem `Incidents`.

## Approval Queue trong

Co nghia la chua co action nao dang cho duyet.

Cach tao action:

1. Vao `Operations`.
2. Chay demo.
3. Chon incident.
4. Bam `LOCK CASE`.
5. Doi agent de xuat action.

Hoac vao `Approvals` de xem toan bo action.

## Skill validate fail

Kiem tra:

- Co file `SKILL.md` khong.
- Frontmatter co dau `---` khong.
- Co `name` khong.
- Co `description` khong.
- Co script Python khong neu validator yeu cau.

## Extension validate fail

Kiem tra:

```text
.pi/extensions/ten-extension/index.ts
```

Phai co folder va file `index.ts`.

## Chain khong hien dung

Kiem tra YAML co dung format khong:

```yaml
name: my-chain
entry: intake-agent
steps:
  - id: intake-agent
    next: triage-agent
```

## Chay test

```powershell
python -m pytest -q
python -m ruff check . --exclude ui/node_modules --exclude ui/dist --exclude node_modules
cd ui
npm run build
cd ..
```

## Truoc khi commit

Khong commit:

- `.env`
- API key.
- `niro.db`
- `.pi/runtime`
- `.pi/logs`
- `node_modules`
- `ui/dist`
