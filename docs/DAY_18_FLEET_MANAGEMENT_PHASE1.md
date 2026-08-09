# Day 18 — Agent Fleet Management & Remote Administration (Phase 1 — Fleet Inventory)

## 🎯 Phase 1 Goal
Provide central operational inventory tracking and real-time status monitoring for all managed SentinelX EDR agents across Windows, Linux, and Raspberry Pi / ARM64 endpoints.

---

## 🏗️ Architecture & Operational Metadata Flow

```
   ┌─────────────────────────────────────────────────────────────┐
   │                React Fleet Console (/fleet)                 │
   │  Metrics: Total, Online, Offline, Outdated, Unhealthy       │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                       FastAPI Fleet Router
                      (/api/v1/fleet/*)
                                  │
                         Fleet Service Engine
                       (app/services/fleet.py)
                                  │
                    PostgreSQL Managed Devices Table
   ┌──────────────────────────────┴──────────────────────────────┐
   │ Extended Device Model Columns:                             │
   │ • agent_version                                             │
   │ • policy_version (applied_policy_version)                  │
   │ • last_checkin                                             │
   │ • last_heartbeat                                           │
   │ • status (ONLINE | OFFLINE | ISOLATED | OUTDATED | UNHEALTHY)│
   │ • operating_system (os_type, os_version)                   │
   │ • hostname & ip_address                                    │
   │ • health_status (HEALTHY | WARNING | DEGRADED | UNHEALTHY) │
   │ • last_command_status (NONE | PENDING | DISPATCHED | ...)  │
   └─────────────────────────────────────────────────────────────┘
```

---

## 📦 Key Deliverables Completed

### 1. Model Extensions & Enums (`backend/app/models/device.py`)
- **`DeviceStatus`**: Added `OUTDATED` and `UNHEALTHY`.
- **`HealthStatus`**: `HEALTHY`, `UNHEALTHY`, `WARNING`, `DEGRADED`, `OUTDATED`.
- **`CommandStatus`**: `NONE`, `PENDING`, `DISPATCHED`, `EXECUTED`, `SUCCESS`, `FAILED`.
- **New Columns**: `health_status`, `last_command_status`, `last_checkin`, `last_heartbeat`.
- **Properties**: `policy_version`, `operating_system`.

### 2. Alembic Database Migration (`backend/alembic/versions/016_extend_device_fleet_inventory.py`)
- Schema migration adding `health_status`, `last_command_status`, `last_checkin`, `last_heartbeat` to `devices` table.

### 3. Fleet Service Engine (`backend/app/services/fleet_service.py`)
- `get_fleet_metrics()`: Calculates top-level KPI metrics (*Total Agents*, *Online*, *Offline*, *Outdated*, *Unhealthy*).
- `get_fleet_inventory()`: Paginated search & filtering across hostname, IP, OS type, agent status, and health status.
- `get_fleet_summary()`: Combined metrics and recent device profiles.

### 4. Fleet Management API Endpoints (`backend/app/api/fleet.py`)
- `GET /api/v1/fleet/metrics`
- `GET /api/v1/fleet/devices`
- `GET /api/v1/fleet/summary`

### 5. Fleet Console Dashboard (`frontend/src/pages/FleetManagement.tsx`)
- 5 Top KPI Cards (*Total Agents*, *Online*, *Offline*, *Outdated*, *Unhealthy*).
- Search input & multi-dropdown filters.
- Detailed agent inventory table displaying hostname, IP address, OS, agent version, policy version, last checkin/heartbeat, status, health, and last command status.
