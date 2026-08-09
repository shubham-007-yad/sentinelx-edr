# SentinelX EDR — Day 18: Agent Fleet Management & Remote Administration

## 🎯 Architecture Overview

```
                      React Dashboard (/fleet)
                                │
                      Fleet Management & Command
                                │
                       FastAPI Backend (/api/v1)
                                │
                    Agent Management Service
                                │
      ┌─────────────────────────┼─────────────────────────┐
      │                         │                         │
 Windows Agent             Linux Agent              Raspberry Pi
      │                         │                         │
      └─────────────────────────┴─────────────────────────┘
```

---

## 📦 Delivered Components & Capabilities

### 1. Fleet Inventory (Phase 1)
- **Extended Device Operational Metadata**:
  - `agent_version`, `applied_policy_version`, `last_checkin`, `last_heartbeat`, `status`, `operating_system`, `ip_address`, `mac_address`, `health_status`, `last_command_status`.
- **Fleet Metrics API**: `GET /api/v1/fleet/metrics`
  - Calculates Total Agents, Online, Offline, Outdated, and Unhealthy endpoints.

### 2. Agent Health Telemetry & Automated Alerts (Phase 2)
- **Resource Monitoring**: Tracks CPU %, RAM MB/%, Disk %, Agent uptime, Service status (`RUNNING`/`STOPPED`), Last telemetry upload, Last policy sync.
- **Automated Health Alert Rules**:
  - `Agent Service Stopped` ➔ CRITICAL Severity Alert
  - `No Heartbeat Received` (>300s timeout) ➔ HIGH Severity Alert & `OFFLINE` status transition
  - `High Resource Usage` (CPU > 85%, RAM > 90%) ➔ HIGH Severity Alert & `WARNING` health status
  - `Policy Sync Failure` (>24h stale) ➔ MEDIUM Severity Alert
- **Telemetry Ingestion Endpoint**: `POST /api/v1/fleet/health/report`
- **Fleet Evaluation Endpoint**: `POST /api/v1/fleet/health/evaluate`

### 3. Remote Command Center (Phase 3)
- **Supported Remote Commands**:
  1. `START_SCAN` (On-demand threat scan)
  2. `RESTART_AGENT` (Daemon restart)
  3. `REFRESH_POLICY` (Security policy sync)
  4. `COLLECT_DIAGNOSTICS` (System diagnostic gathering)
  5. `UPLOAD_LOGS` (Event & telemetry log upload)
  6. `RECONNECT` (Socket reconnection)
  7. `SHUTDOWN_AGENT` (Agent shutdown simulation)
  8. `UPDATE_CONFIG` (Agent configuration update)
- **Command Lifecycle**: `PENDING` ➔ `DISPATCHED` ➔ `EXECUTING` ➔ `SUCCESS` / `FAILED`.
- **Endpoints**:
  - `POST /api/v1/fleet/commands` (Single queue)
  - `POST /api/v1/fleet/commands/batch` (Multi-device bulk queue)
  - `GET /api/v1/fleet/commands/pending/{device_id}` (Agent poll & dispatch)
  - `POST /api/v1/fleet/commands/acknowledge` (Agent completion ACK)
  - `GET /api/v1/fleet/commands/history` (Execution history)
  - `GET /api/v1/fleet/commands/audit-logs` (Immutable security audit trail)

### 4. Fleet Dashboard UI (Phase 4)
- **URL**: `/fleet`
- **Columns**: Hostname, Device (IP/MAC), OS, Agent Version, Policy Version, Status Badge, Last Seen Timestamp, Health Badge, Remote Action Trigger.
- **Filter Toolbar**:
  - OS Filter (`WINDOWS`, `LINUX`, `MACOS`, `OTHER`)
  - Version Filter (`v1.2.0`, `v1.0.0`, `v0.9.8`, `v0.9.0`)
  - Status Filter (`ONLINE`, `OFFLINE`, `ISOLATED`, `OUTDATED`, `UNHEALTHY`)
  - Policy Filter (`v1`, `v2`, `v3`)
  - Instant Multi-Attribute Search (Hostname, IP, MAC, Agent Version)

### 5. Multi-Device Bulk Operations (Phase 5)
- **Checkbox Table Selection**: Select All / Individual Device checkboxes with sticky floating action toolbar.
- **Bulk Actions**:
  - Restart Selected Agents
  - Push Policy (Interactive Policy Tag input e.g. `v3.2`)
  - Start On-Demand Scan
  - Export Inventory (CSV export via `GET /api/v1/fleet/export`)
  - Refresh Health Evaluation

### 6. Agent Diagnostics Package (Phase 6)
- **Troubleshooting Package**:
  - Live Agent Daemon Log Buffer & Error Traces
  - Active Configuration Parameters (Heartbeat interval, log level, C2 URLs, buffer sizes)
  - Installed Collectors Throughput (Process, Network, FIM, USB, Ransomware, Auth)
  - Recent Health Errors & Alerts
  - Command History & Execution Outputs
  - Synchronization Timestamps (Heartbeat, Check-in, Policy Sync, Telemetry Upload)
- **Endpoints**:
  - `GET /api/v1/fleet/devices/{device_id}/diagnostics`
  - `GET /api/v1/fleet/devices/{device_id}/diagnostics/download` (Downloadable `.json` bundle)

### 7. Agent Upgrade Framework (Phase 7)
- **Upgrade Pipeline**:
  `New Version Available` ➔ `Downloading` (25%) ➔ `Installing` (65%) ➔ `Restarting` (90%) ➔ `Report Success` (100%).
- **Automated Rollback**: Restores agent daemon binary to previous stable release (`rollback_status = SUCCESSFUL`).
- **Endpoints**:
  - `POST /api/v1/fleet/upgrade/trigger`
  - `POST /api/v1/fleet/upgrade/step`
  - `POST /api/v1/fleet/upgrade/rollback`
  - `GET /api/v1/fleet/upgrade/history`

### 8. Automated Test Suite & E2E Validation (Phase 8)
- **Master Test Files**:
  - `backend/tests/test_fleet_inventory.py`
  - `backend/tests/test_agent_health_monitoring.py`
  - `backend/tests/test_remote_command_center.py`
  - `backend/tests/test_agent_upgrade_framework.py`
  - `backend/tests/test_fleet_management_e2e.py`
- **Result**: 15/15 test cases passing cleanly!

---

## 🛠 Database Schema Migrations

1. `016_extend_device_fleet_inventory.py` — Adds operational metadata fields to `devices`.
2. `017_add_agent_health_metrics.py` — Adds health metrics & resource telemetry columns to `devices`.
3. `018_create_agent_commands.py` — Creates `agent_commands` and `agent_command_audit_logs` tables.
4. `019_create_agent_upgrades.py` — Creates `agent_upgrades` table for upgrade pipeline tracking.

---

## 🚀 Getting Started & Verification Commands

### Run Backend Server:
```bash
PYTHONUNBUFFERED=1 PYTHONPATH=backend:.:agent ./backend/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Run Frontend Development Server:
```bash
npm --prefix frontend run dev
```

### Execute Test Suite:
```bash
PYTHONPATH=backend:.:agent backend/venv/bin/pytest backend/tests/
```
