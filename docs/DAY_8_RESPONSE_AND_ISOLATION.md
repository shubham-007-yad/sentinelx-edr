# Day 8 — Endpoint Response & Device Isolation Documentation

## Architecture Overview

Day 8 evolves **SentinelX-EDR** from passive detection/alerting (**Detect → Alert**) into an active containment & mitigation platform (**Detect → Alert → Respond**).

```
USB Insert
   │
   ▼
Threat Detection Engine
   │
   ▼
Alert Triggered
   │
   ▼
Response Engine
 ┌─┴─────────────────────────┐
 ▼                           ▼
Automatic Policy Response    Manual Operator Response
 (Quarantine / Isolate)       (Via Dashboard Console)
```

---

## Phase 1 — Response Database

### `ResponseAction` Model

Defined in `backend/app/models/response_action.py`:
- `id`: UUID Primary Key
- `alert_id`: Foreign Key to `alerts.id` (nullable for direct endpoint actions)
- `device_id`: Foreign Key to `devices.id` (Target endpoint device)
- `action_type`: Enum (`QUARANTINE`, `DELETE`, `ISOLATE`, `IGNORE`)
- `status`: Enum (`PENDING`, `RUNNING`, `SUCCESS`, `FAILED`, `CANCELLED`)
- `initiated_by`: Initiator string (`AUTOMATIC` / admin username)
- `started_at`: Timestamp (`server_default=func.now()`)
- `completed_at`: Timestamp
- `result`: Execution log details text

### Migration

- Created Alembic migration script `007_create_response_actions.py`.

---

## Phase 2 — Response Engine

Implemented in `backend/app/services/response_service.py`:
1. **Receive Response Requests**: Entry point `execute_response(...)` handles both automated policy triggers and manual operator requests.
2. **Validate Permissions**: `validate_response_request(...)` verifies endpoint existence, active state, and operator role authorization.
3. **Dispatch Commands**: `dispatch_command_to_agent(...)` emits real-time `RESPONSE_COMMAND` WebSocket messages to target endpoint agents.
4. **Track Execution Status**: `update_response_action_status(...)` records completion timestamps, execution logs, and updates target device status to `ISOLATED` upon successful isolation actions.
5. **Audit Logging**: Every action event is persisted in PostgreSQL and recorded in Python structured audit logs (`[ResponseEngine AUDIT]`).

---

## Phase 3 — Agent Command Channel

Implemented in `agent/command_executor.py` and `agent/command_channel.py`:
- **WebSocket Endpoint**: `ws://<backend>/ws/agent/{device_id}`
- **Supported Commands**:
  - `DELETE_FILE`: Permanently removes malicious files from disk.
  - `QUARANTINE_FILE`: Isolates files to the quarantine vault.
  - `ISOLATE_DEVICE`: Enforces endpoint network isolation.
  - `START_SCAN`: Triggers on-demand USB/drive scan.
- **Status Reporting**: Agent reports command outcomes back to `POST /responses/{action_id}/status`.

---

## Phase 4 — File Quarantine

Implemented in `agent/quarantine_manager.py`:
- **Vault Location**: `.quarantine/` (configurable via `SENTINELX_QUARANTINE_DIR`).
- **Permission Hardening**: Revokes read/write/execute permissions (`chmod 000`) on isolated files.
- **Manifest Index**: Maintains `.quarantine/manifest.json` tracking:
  - `original_path`
  - `quarantine_path`
  - `timestamp`
  - `sha256`
  - `reason`

---

## Phase 5 — Device Isolation (Simulation)

- **State Management**: Endpoint device status marked as `ISOLATED`. Heartbeat preserves `ISOLATED` state until explicitly restored.
- **USB Events Blocked**: `POST /usb/events` checks device isolation and returns **HTTP 403 Forbidden**.
- **Scan Jobs Blocked**: `POST /usb/scans` checks device isolation and returns **HTTP 403 Forbidden**.
- **Endpoints**:
  - `POST /api/v1/devices/{id}/isolate`
  - `POST /api/v1/devices/{id}/unisolate`

---

## Phase 6 — Response Dashboard

Implemented in `frontend/src/pages/ResponseDashboard.tsx` under route `/respond`:

### Table Columns
1. **Device**: Target endpoint hostname and UUID.
2. **Action**: Visual badge (`QUARANTINE`, `DELETE`, `ISOLATE`, `START_SCAN`).
3. **Status**: Real-time status badge (`PENDING`, `RUNNING`, `SUCCESS`, `FAILED`, `CANCELLED`).
4. **Operator**: Initiator identifier (`AUTOMATIC` / admin username).
5. **Time**: Timestamp formatted date/time.
6. **Duration**: Calculated execution duration (e.g. `250ms`, `1.45s`).

### Interactive Controls
- **Retry**: Re-dispatches failed actions (`POST /responses/{id}/retry`).
- **Cancel**: Cancels pending or running actions (`POST /responses/{id}/cancel`).
- **Status Filter**: Dropdown filter for `ALL`, `PENDING`, `RUNNING`, `SUCCESS`, `FAILED`, `CANCELLED`.
- **Manual Dispatch Modal**: Operator form to trigger on-demand response actions against any registered device.

---

## Phase 7 — Forensic Audit Trail

Implemented in `backend/app/models/response_audit_log.py`, `backend/app/services/response_service.py`, and `frontend/src/pages/ResponseDashboard.tsx`:

- **Forensic History Model**: `ResponseAuditLog` tracks every action event stage:
  - `INITIATED`: `"Admin initiated Quarantine"` / `"AUTOMATIC policy initiated Quarantine"`
  - `ACKNOWLEDGED`: `"Agent on node-01 acknowledged command"`
  - `EXECUTING` / `SUCCESS` / `FAILED`: `"File moved successfully to .quarantine/"` -> `"Status = SUCCESS"`
- **API Endpoint**: `GET /api/v1/responses/{action_id}/audit-logs` returns chronological audit events.
- **UI Viewer**: Interactive **Forensic Audit Viewer Modal** in `/respond` allows operators to inspect step-by-step audit timelines, actors, stages, and raw JSON details.

---

## Phase 8 — End-to-End Verification Test Suite

Implemented in `backend/tests/test_e2e_day8_response_verification.py`:

1. **Scenario 1 — Quarantine Malicious Executable**: Validated file movement to `.quarantine/`, permission revocation (`chmod 000`), and `.quarantine/manifest.json` indexing.
2. **Scenario 2 — Simulate Device Isolation**: Validated endpoint status change to `ISOLATED` and enforcement of **HTTP 403 Forbidden** on incoming `POST /usb/events` and `POST /usb/scans`.
3. **Scenario 3 — Retry Failed Response**: Validated status re-transition from `FAILED` -> `RUNNING` -> `SUCCESS` via `POST /responses/{id}/retry` with audit trail recording.
4. **Scenario 4 — Deduplication Control**: Validated duplicate active command requests return **HTTP 409 Conflict** and `DuplicateActionError`.
5. **Scenario 5 — Dashboard Live Status Updates**: Validated real-time event broadcasting over WebSocket for response action updates.

---

## Test Verification Matrix

| Test Suite | Total Tests | Status |
|:---|:---:|:---:|
| Backend Pytest Suite | 73 | PASSED |
| Agent Pytest Suite | 42 | PASSED |
| Frontend Production Build | 95 Modules | PASSED |
