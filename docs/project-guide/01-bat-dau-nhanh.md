# 01 - Bat Dau Nhanh

File nay chi noi cach chay project va test nhanh.

## 1. Chay backend + UI

Tai thu muc project:

```powershell
python -m uvicorn app.web.server:app --host 127.0.0.1 --port 8000
```

Mo trinh duyet:

```text
http://127.0.0.1:8000/
```

## 2. Neu UI khong moi sau khi sua code

Build lai UI:

```powershell
cd ui
npm run build
cd ..
```

Sau do restart server.

## 3. Chay demo nhanh nhat

1. Mo tab `Operations`.
2. Bam `DEMO: SSH BRUTE FORCE`.
3. Chon incident moi o `Target Incident`.
4. Bam `LOCK CASE`.
5. Xem graph, terminal va approval queue.

## 4. Cai API key va model LLM

1. Mo tab `ML Models`.
2. Provider: nhap `google`.
3. Model name: nhap model can dung.
4. API key: dan key vao.
5. Bam `Save LLM Config`.

Key se duoc luu vao `.env`. UI khong hien lai key.

## 5. Lenh test can chay

```powershell
python -m pytest -q
python -m ruff check . --exclude ui/node_modules --exclude ui/dist --exclude node_modules
cd ui
npm run build
cd ..
```

## 6. Chay pipeline bang lenh

```powershell
python scripts/run_pipeline.py --alert .pi\data\sample_alert.json --output-dir .pi\runtime\manual-run
```

Ket qua nam o:

```text
.pi/runtime/manual-run/triage/incident_triage.json
.pi/runtime/manual-run/reports/ket_qua.md
.pi/runtime/manual-run/logs/
```

## 7. Kiem tra Pi CLI

```powershell
npx pi --version
```

Neu ra version la da cai duoc Pi CLI.
