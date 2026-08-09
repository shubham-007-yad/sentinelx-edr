# SentinelX EDR — Disaster Recovery & System Resilience Architecture

This document defines the Disaster Recovery (DR) protocols, failure modes, self-healing mechanisms, and recovery playbooks for SentinelX EDR components.

---

## 🔄 Database Disaster Recovery Flow

When a catastrophic failure occurs on the primary PostgreSQL database cluster:

```
                  ┌───────────────────────────────┐
                  │ 1. Database Failure Detected  │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │ 2. Restore PostgreSQL Backup  │
                  │   (pg_restore / backup.dump)  │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │ 3. Execute Schema Migrations  │
                  │   (alembic upgrade head)      │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │ 4. Restart Backend Services   │
                  │   (docker compose restart)    │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │ 5. Endpoint Agents Reconnect  │
                  │   & Flush Offline Telemetry   │
                  └───────────────────────────────┘
```

### Recovery Playbook Execution

1. **Step 1 — Identify Outage & Isolate Impacted Instance**:
   ```bash
   docker compose ps postgres
   docker compose logs --tail=100 postgres
   ```

2. **Step 2 — Restore Latest Verified Backup**:
   ```bash
   # Restore PostgreSQL database from latest dump artifact
   docker compose exec -T postgres pg_restore -U sentinel -d sentinelx --clean --if-exists /backups/sentinelx_latest.dump
   ```

3. **Step 3 — Run Schema Migration Engine**:
   ```bash
   docker compose exec backend alembic upgrade head
   ```

4. **Step 4 — Verify Data & System Readiness**:
   ```bash
   # Execute automated integrity verification suite
   docker compose exec backend python /app/scripts/db_backup_restore_test.py
   ```

5. **Step 5 — Restart Backend Services & Unpause Polling**:
   ```bash
   docker compose restart backend worker nginx
   ```
   *Agents automatically reconnect and flush local offline telemetry buffers upon HTTP 200/201 response.*

---

## ⚡ Failure Modes & Self-Healing Behavior

### 1. Backend Service Goes Offline (`sentinelx-backend`)
- **Nginx Response**: Nginx proxy catches backend connection failures and returns `HTTP 502 Bad Gateway`.
- **Endpoint Agent Behavior**: Agents detect network timeout/502 response and enter exponential backoff (1s -> 2s -> 4s -> ... -> max 60s). Telemetry events (USB, FIM, Process, Network) are queued in local disk buffer (`.telemetry_buffer.json`).
- **Dashboard UI Behavior**: React console displays "Connection Interrupted — Retrying..." banner and retries REST/WebSocket connections automatically.

### 2. Primary Database Goes Offline (`sentinelx-postgres`)
- **Health & Readiness Impact**: `/ready` endpoint returns `HTTP 503 Service Unavailable` with `"postgres": {"status": "DOWN"}`.
- **SQLConnection Pooling**: SQLAlchemy pool (`pool_pre_ping=True`) drops dead connections and retries connections up to `pool_timeout=30s`.
- **Fail-Safe Operation**: Read/Write API endpoints fail gracefully with structured JSON error messages without crashing Python worker threads.

### 3. Redis Task Queue Goes Offline (`sentinelx-redis`)
- **Queue Operations**: Async jobs (bulk fleet commands, scheduled reports) fail fast with HTTP 503.
- **API Operations**: Core REST endpoints operating directly against PostgreSQL continue servicing clients.
- **Rate Limiting Fallback**: Rate limiter enters "Fail-Open" mode so legitimate client traffic is not dropped due to Redis unavailability.

### 4. Agent Loses Internet / Network Outage
- **Offline Telemetry Buffering**:
  - Telemetry logs (Process events, FIM diffs, Network events, USB scans) are enqueued into local `.telemetry_buffer.json` (max capacity: 5,000 items, file permission `0600`).
  - No telemetry data is lost during temporary network outages.
- **Reconnection & Batch Flushing**:
  - Upon network restoration, `flush_offline_telemetry()` automatically streams buffered events in batch order (100 events/batch) to `/api/v1/telemetry/ingest`.

### 5. SOC Dashboard Disconnects (WebSocket Drop)
- **Reconnection Logic**: React WebSocket client hooks (`useWebSocket`) catch `onclose` events and initiate automatic reconnection attempts with exponential backoff every 3 seconds.
- **State Synchronization**: Upon reconnection, dashboard fetches `GET /api/v1/alerts/unread-count` and `GET /api/v1/devices` to resynchronize UI state.
