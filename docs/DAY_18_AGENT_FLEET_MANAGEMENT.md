# Day 18 — Agent Fleet Management & Remote Administration

## 🎯 Strategic Objective
Provide a unified enterprise console to deploy, monitor, configure, and troubleshoot all SentinelX agents across Windows, Linux, and Raspberry Pi (ARM) endpoints.

---

## 🏗️ Architecture & Data Flow

```
             React Fleet Console (/fleet)
                          │
               Fleet Dashboard & Metrics
                          │
             FastAPI Backend Services
            (/api/v1/fleet/* & /devices)
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
  Fleet Service                  Agent Health Service
  (app/services/fleet.py)    (app/services/agent_health_service.py)
        │                                   │
        └─────────────────┬─────────────────┘
                          │
         PostgreSQL Device & Alert Datasets
                          │
      ┌───────────────────┼───────────────────┐
      │                   │                   │
 Windows Agent       Linux Agent       Raspberry Pi (ARM)
 (win32 service)    (systemd service)   (ARM64 daemon)
```

---

## 📦 Phase 1 — Fleet Inventory

### Extended Operational Metadata Tracked
- **Agent Version** (`agent_version`)
- **Applied Policy Version** (`applied_policy_version` / `policy_version`)
- **Last Check-in Timestamp** (`last_checkin` / `last_seen`)
- **Last Heartbeat Timestamp** (`last_heartbeat`)
- **Agent Operational Status** (`ONLINE`, `OFFLINE`, `ISOLATED`, `UNREGISTERED`, `OUTDATED`, `UNHEALTHY`)
- **Operating System** (`WINDOWS`, `LINUX`, `MACOS`, `OTHER` + `os_version`)
- **Hostname** & **IP Address**
- **Health Status** (`HEALTHY`, `WARNING`, `DEGRADED`, `UNHEALTHY`, `OUTDATED`)
- **Last Command Status** (`NONE`, `PENDING`, `DISPATCHED`, `EXECUTED`, `SUCCESS`, `FAILED`)

### Fleet Overview KPI Metrics
- **Total Agents**
- **Online Agents**
- **Offline Agents**
- **Outdated Agents**
- **Unhealthy Agents**

---

## 🩺 Phase 2 — Agent Health Monitoring & Alerting Engine

### 1. Telemetry Monitored (`AgentHealthReportRequest`)
- **CPU Usage %** (`cpu_usage_percent`)
- **RAM Usage (MB & %)** (`ram_usage_mb`, `ram_usage_percent`)
- **Disk Usage %** (`disk_usage_percent`)
- **Agent Uptime** (`agent_uptime_seconds`)
- **Service Status** (`RUNNING`, `STOPPED`, `DEGRADED`, `ERROR`)
- **Last Successful Telemetry Upload** (`last_telemetry_upload`)
- **Last Policy Sync** (`last_policy_sync`)

### 2. Automated Health Evaluation Rules (`agent_health_service.py`)
- 🔴 **Agent Stopped** (`SERVICE_STOPPED`): Triggered when `service_status` is `STOPPED`, `ERROR`, `CRASHED`, or `FAILED`. Generates **CRITICAL** Alert.
- 🟠 **No Heartbeat** (`NO_HEARTBEAT`): Triggered when `(now - last_heartbeat) > 300s (5 minutes)`. Sets status to `OFFLINE` and generates **HIGH** Alert.
- ⚠️ **High Resource Usage** (`HIGH_RESOURCE_USAGE`): Triggered when CPU > 85%, RAM > 90%, or Disk > 90%. Sets health status to `WARNING`/`DEGRADED` and generates **HIGH** Alert.
- 🟡 **Policy Sync Failure** (`POLICY_SYNC_FAILURE`): Triggered when `(now - last_policy_sync) > 86400s (24 hours)`. Generates **MEDIUM** Alert.

---

## 🧪 API Endpoints

- `GET /api/v1/fleet/metrics` — Aggregate fleet KPI metrics
- `GET /api/v1/fleet/devices` — Paginated device inventory with health telemetry
- `GET /api/v1/fleet/summary` — Overview metrics + recent devices
- `POST /api/v1/fleet/health/report` — Ingest agent health telemetry & run rules
- `POST /api/v1/fleet/health/evaluate` — Fleet-wide on-demand health evaluation audit
