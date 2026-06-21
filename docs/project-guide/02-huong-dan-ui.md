# 02 - Huong Dan Tung Nut Tren UI

Day la file quan trong nhat neu ban chi muon biet UI dung the nao.

## Operations

Day la man hinh chinh.

Dung de:

- Chay demo.
- Chon incident.
- Goi agent phan tich.
- Xem graph.
- Chat/ra lenh cho agent.
- Duyet nhanh action.

Cach dung:

1. Bam `DEMO: SSH BRUTE FORCE` neu chua co du lieu.
2. Chon incident trong `Target Incident`.
3. Bam `LOCK CASE`.
4. Xem `Tactical Node Graph`.
5. Neu co action, bam `Approve` hoac `Reject` trong `Approval Queue`.

Giai thich cac vung:

- `Target Incident`: chon vu viec dang xu ly.
- `Agent Dispatch Matrix`: xem agent nao da chay xong.
- `Rules of Engagement`: gioi han an toan, nen de safe mode ON.
- `Pipeline Async Queue`: xem hang doi xu ly.
- `Tactical Node Graph`: so do incident, IP, finding, action.
- `Operator Console Command`: o chat de ra lenh cho agent.
- `Live Terminal`: log dang chay.
- `Approval Queue`: hanh dong dang cho duyet.

## Incidents

Dung de xem danh sach su co.

Ban se thay:

- Ten incident.
- Loai su co.
- Muc do nghiem trong.
- IP nguon/dich.
- Evidence.
- Report/summary neu agent da phan tich.

Cach dung:

1. Mo `Incidents`.
2. Chon mot incident.
3. Doc chi tiet.
4. Neu can thi doi status.

## Events Logs

Dung de xem log dau vao.

Ban dung tab nay khi muon xem:

- Log nao da duoc ingest.
- Source IP la gi.
- Destination IP la gi.
- Event co nghiem trong khong.

Cach dung:

1. Mo `Events Logs`.
2. Loc theo Source IP, Destination IP, Protocol hoac Severity.
3. Xem bang event.

## Approvals

Dung de duyet hanh dong do agent de xuat.

Trang thai:

- `awaiting_approval`: dang cho duyet.
- `approved`: da duyet, co the execute.
- `completed`: da execute xong.
- `rejected`: da tu choi.
- `rolled_back`: da hoan tac.

Cach dung:

1. Mo `Approvals`.
2. Neu action hop ly, bam `Approve`.
3. Sau do bam `Execute Policy`.
4. Neu can hoan tac, bam `Rollback Policy`.

Luu y: mac dinh la simulation, khong block may that.

## Agents

Dung de tao/sua agent.

Agent la vai tro cua AI, vi du:

- Agent phan tich log.
- Agent viet report.
- Agent de xuat response.

Cach tao:

1. Mo `Agents`.
2. Nhap ten agent moi.
3. Bam `+`.
4. Sua noi dung ben phai.
5. Bam `Save Agent`.

## Pi Skills

Dung de tao/sua skill.

Skill la kha nang cu the cua agent, vi du:

- Phan tich DNS.
- Doc Zeek log.
- Map MITRE.
- Viet report.

Cach tao:

1. Mo `Pi Skills`.
2. Nhap ten skill.
3. Bam `+`.
4. Sua `SKILL.MD MANIFEST`.
5. Sua script Python neu can.
6. Bam `Save`.
7. Bam `Validate`.
8. Bam `Test`.

## Pi Extensions

Dung de tao/sua extension TypeScript.

Extension thuong dung cho:

- Permission gate.
- Audit logger.
- Context safety.
- Event bridge.

Cach tao:

1. Mo `Pi Extensions`.
2. Nhap ten extension.
3. Bam `+`.
4. Sua `index.ts`.
5. Bam `Save`.
6. Bam `Validate`.
7. Bam `Test extension`.

## Chains

Dung de tao/sua luong lam viec cua agent.

Vi du luong don gian:

```text
Intake -> Evidence -> Detection -> Triage -> Response
```

Cach tao:

1. Mo `Chains`.
2. Nhap ten chain.
3. Bam `+`.
4. Sua YAML.
5. Bam `Save Chain`.

## ML Models

Dung de cai model LLM va API key.

Day la tab can vao neu agent khong goi duoc LLM.

Cach dung:

1. Provider: `google`.
2. Model name: model dang dung.
3. API key: dan key vao.
4. Bam `Save LLM Config`.

Tab nay cung hien Pi CLI da cai chua.

## Settings

Dung de chinh gioi han an toan.

Nen dung khi muon sua:

- Mang nao duoc phep xu ly.
- IP nao can bao ve.
- Co bat approval khong.
- Rate limit tool.

Neu chi test project, de mac dinh la duoc.

## Audit Trail

Dung de xem lich su.

No giup xem:

- Event da ingest.
- Incident da tao.
- Action da approve/reject/execute.
- Agent da chay.

Neu can tim nhanh, dung o search.
