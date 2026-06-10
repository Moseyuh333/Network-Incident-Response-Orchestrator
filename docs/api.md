# REST API Documentation

This document maps all public REST and streaming API endpoints exposed by the N.I.R.O. backend under the `/api/v1` prefix.

---

## 1. System Endpoints

### `GET /api/v1/health`
- **Description**: Returns basic application health status.
- **Response**: `{"status": "ok"}`

### `GET /api/v1/health/components`
- **Description**: Returns status indicators for individual internal subsystems.
- **Response**: `{"database": "ok", "detectors": "ok", "response_mode": "simulation"}`

### `GET /api/v1/system/status`
- **Description**: Returns configuration settings, database URLs, and log level info.

---

## 2. Ingestion Endpoints

### `POST /api/v1/events`
- **Description**: Ingests one normalized security event.
- **Body Schema**: `EventCreate` (Pydantic model)

### `POST /api/v1/events/bulk`
- **Description**: Ingests a list of security events in bulk.
- **Body Schema**: `BulkEventsRequest`
- **Response**: `{"ingested": int, "incidents": [str]}`

### `POST /api/v1/events/import/suricata`
- **Description**: Imports a Suricata EVE JSON file from a local path.
- **Body**: `{"path": "/absolute/path/to/eve.json"}`

### `POST /api/v1/events/import/zeek`
- **Description**: Imports a Zeek JSON log file.
- **Body**: `{"path": "/path/to/conn.log", "log_type": "conn"}`

---

## 3. Incident Endpoints

### `GET /api/v1/incidents`
- **Description**: Lists all incidents sorted by modification date.

### `GET /api/v1/incidents/{incident_id}`
- **Description**: Retrieves detailed fields of a specific incident.

### `POST /api/v1/incidents/{incident_id}/status`
- **Description**: Transitions an incident to a new state.
- **Body**: `{"status": "containing", "actor": "operator"}`

### `POST /api/v1/incidents/{incident_id}/agent/run`
- **Description**: Spawns an agent reasoning run for the incident.
- **Body**: `{"task": "Analyze incident", "max_tool_calls": 5}`

---

## 4. Response & Actions Endpoints

### `GET /api/v1/actions`
- **Description**: Lists all proposed, approved, and executed response actions.

### `POST /api/v1/actions/{action_id}/approve`
- **Description**: Marks a pending action as approved.

### `POST /api/v1/actions/{action_id}/execute`
- **Description**: Triggers execution on approved adapters.

### `POST /api/v1/actions/{action_id}/rollback`
- **Description**: Rolls back an executed action.

---

## 5. Streaming & Live Event Endpoints

### `GET /api/v1/live/events`
- **Description**: Server-Sent Events (SSE) connection streaming real-time statistics, active incidents lists, and actions snapshots.
- **Media Type**: `text/event-stream`

### `GET /api/v1/pipeline/events`
- **Description**: Server-Sent Events (SSE) connection streaming orchestration queue events (queued, running, completed, timed_out).
