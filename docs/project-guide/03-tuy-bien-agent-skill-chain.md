# 03 - Tuy Bien Agent, Skill, Extension, Chain

File nay chi noi cach them/sua/xoa cac thu trong `.pi`.

## 1. Agents

Noi luu:

```text
.pi/agents/
```

Agent la vai tro cua AI.

Them bang UI:

1. Vao `Agents`.
2. Nhap ten agent.
3. Bam `+`.
4. Sua noi dung.
5. Bam `Save Agent`.

Xoa bang file:

```powershell
Remove-Item .pi\agents\ten-agent.md
```

## 2. Skills

Noi luu:

```text
.pi/skills/ten-skill/SKILL.md
.pi/skills/ten-skill/ten_skill.py
```

Skill la mot kha nang cua agent.

Them bang UI:

1. Vao `Pi Skills`.
2. Nhap ten skill.
3. Bam `+`.
4. Sua manifest.
5. Sua script Python.
6. Bam `Save`.
7. Bam `Validate`.
8. Bam `Test`.

Manifest don gian:

```markdown
---
name: my-skill
description: Skill nay dung de phan tich log
triggers:
  - log
  - incident
safety: read_only
enabled: true
---

# My Skill

Huong dan agent dung skill nay.
```

Xoa bang file:

```powershell
Remove-Item -Recurse -Force .pi\skills\ten-skill
```

## 3. Extensions

Noi luu:

```text
.pi/extensions/ten-extension/index.ts
```

Extension la code TypeScript de mo rong hanh vi.

Them bang UI:

1. Vao `Pi Extensions`.
2. Nhap ten extension.
3. Bam `+`.
4. Sua `index.ts`.
5. Bam `Save`.
6. Bam `Validate`.

Xoa:

```powershell
Remove-Item -Recurse -Force .pi\extensions\ten-extension
```

## 4. Chains

Noi luu:

```text
.pi/chains/ten-chain.yaml
```

Chain la luong lam viec cua agent.

Them bang UI:

1. Vao `Chains`.
2. Nhap ten chain.
3. Bam `+`.
4. Sua YAML.
5. Bam `Save Chain`.

YAML don gian:

```yaml
name: my-chain
entry: intake-agent
steps:
  - id: intake-agent
    next: evidence-agent
  - id: evidence-agent
    next: triage-agent
  - id: triage-agent
    next: response-planner-agent
```

Xoa:

```powershell
Remove-Item .pi\chains\ten-chain.yaml
```

## 5. Plugins

Noi luu:

```text
.pi/plugins/
```

Plugin hien tai chu yeu la file JSON khai bao tool.

Vi du:

```json
{
  "id": "simulation",
  "version": "1.0.0",
  "entrypoint": "simulation",
  "description": "Safe simulated actions",
  "tools": [],
  "enabled": true
}
```

Luu y:

- `entrypoint` hien chi nen de `simulation`.
- Plugin khong nen chay code nguy hiem.

## 6. Sau khi sua file bang tay

Reload lai:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/pi/reload
```

Hoac bam Save tren UI, UI se reload giup.
