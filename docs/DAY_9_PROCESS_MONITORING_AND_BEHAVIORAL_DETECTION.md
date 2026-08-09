# Day 9 — Process Monitoring & Behavioral Detection Documentation

## Architecture Overview

Day 9 evolves **SentinelX-EDR** from static file inspection into continuous endpoint process telemetry and behavioral threat detection (**Process Telemetry → Behavioral Rules → Alerts → Response**).

```
Endpoint Running Processes
           │
           ▼
  Process Monitor Worker
 (Diffing & Event Stream)
           │
           ▼
 Behavioral Detection Engine
 (PowerShell / CMD / LOLBins / Chains)
           │
           ▼
  Threat & Alert Generation
           │
           ▼
   Response & Containment
```

---

## Phase Breakdown

### Phase 1 — Process Inventory
- **Agent Collector**: Implemented `ProcessCollector` in `agent/collectors/process_collector.py` gathering PID, PPID, process name, executable path, username, CPU %, memory %, start time, and command-line arguments.
- **Backend Model & Storage**: Created `ProcessInfo` database model (`backend/app/models/process_info.py`) and Alembic migration `009_create_process_info.py`.
- **API Endpoints**:
  - `POST /api/v1/devices/{device_id}/processes`
  - `GET /api/v1/devices/{device_id}/processes`
  - `GET /api/v1/processes`

### Phase 2 — Live Process Monitoring
- **Real-Time Monitor**: Implemented `ProcessMonitor` daemon in `agent/collectors/live_process_monitor.py` with continuous state diffing (default `5.0`s interval).
- **Event Detection**: Diffing engine classifies process dynamics into `created`, `terminated`, and `long_running` (uptime >= threshold).
- **Diff Event Telemetry**: `POST /api/v1/devices/{device_id}/processes/events` handles live process event streaming and active process inventory state synchronization.

### Phase 3 — Behavioral Detection Rules
- **Rule Framework**: Created `BaseProcessRule` and `ProcessRuleResult` in `backend/app/detection/rules/process_base.py`.
- **Suspicious PowerShell Rule (`SuspiciousPowerShellRule`)**:
  - Memory Injection & Download-Execute strings (`DownloadString`, `WebClient`, `IEX`) → `CRITICAL`
  - Base64 Encoded Command Lines (`-enc`, `-encodedcommand`, `-e`) → `HIGH`
  - Window Evasion flags (`-w hidden`, `-nop`, `-noprofile`) → `HIGH`
- **Suspicious CMD Rule (`SuspiciousCmdRule`)**:
  - Piping into PowerShell / Shell (`cmd /c ... | powershell`) → `HIGH`
  - Execution from temporary locations (`AppData\Local\Temp`, `/tmp`, `/dev/shm`) → `HIGH`
  - Multi-command script chaining (`&&`, `||`, `&`) → `MEDIUM`
- **LOLBins Rule (`LOLBinsRule`)**:
  - Living-off-the-Land binary abuse heuristics (`certutil`, `regsvr32`, `rundll32`, `mshta`, `wmic`, `bitsadmin`, `cscript`, `wscript`, `curl`, `wget`, `nc`/`netcat`/`socat`).

### Phase 4 — Parent/Child Process Analysis
- **Rule Plugin**: Implemented `ParentChildChainRule` in `backend/app/detection/rules/parent_child_chain.py`.
- **Office / Browser Parent Spawns**: Detects when applications (`winword.exe`, `excel.exe`, `chrome.exe`, `nginx`, etc.) spawn shell interpreters (`cmd.exe`, `powershell.exe`, `bash`) → `CRITICAL`.
- **Shell-to-Shell Evasion**: Detects nested shell chains (`explorer.exe` → `powershell.exe` → `cmd.exe`) → `HIGH`.
- **Lineage Summaries**: Constructs human-readable process lineage strings attached to threat records.

### Phase 5 — Process Dashboard
- **Interactive UI Console**: Implemented `ProcessDashboard.tsx` under frontend route `/processes`.
- **Required Columns**: PID, Name, User, CPU %, Memory %, Device, Started timestamp.
- **Filtering System**:
  - Device Endpoint dropdown filter
  - Process Name search
  - Execution User search
  - High CPU Toggle (`>= 10%`)
  - High Memory Toggle (`>= 5%`)
- **Navigation Bar**: Added `/processes` Process Inventory link across all top-header panels.

### Phase 6 — Response Integration
- **Response Actions**: Extended `ResponseActionType` model (`backend/app/models/response_action.py`) and migration `011_add_process_response_actions.py`:
  - `TERMINATE_PROCESS` (Stops target running process by PID/name)
  - `SUSPEND_PROCESS` (Pauses process execution)
  - `MARK_TRUSTED` (Registers process as trusted)
  - `ADD_ALLOWLIST` (Adds process/binary path to allowlist)
- **Agent Command Executor**: Updated `CommandExecutor` in `agent/command_executor.py` with `terminate_process()`, `suspend_process()`, `mark_trusted()`, and `add_allowlist()`.
- **Dashboard Response Actions**: Integrated interactive response buttons (`🛑 Terminate`, `⏸️ Suspend`, `🛡️ Trust`, `📋 Allowlist`) into `ProcessDashboard.tsx` connected to `triggerResponseAction()`.

### Phase 7 — Audit & History
- **Process Audit Model**: Created `ProcessAuditLog` database model (`backend/app/models/process_audit_log.py`) and Alembic migration `012_create_process_audit_logs.py`.
- **Event Classification**: Tracks `PROCESS_STARTED`, `PROCESS_TERMINATED`, `RESPONSE_ACTION`, and `DETECTION_FOUND` audit events across endpoints.
- **Audit REST API**: `GET /api/v1/processes/audit-logs` endpoint supporting filtering by `device_id`, `event_type`, `process_name`, and `pid`.
- **Dashboard History Console**: Integrated interactive **Process Audit & Event History** view tab in `ProcessDashboard.tsx` displaying timeline audit logs.

### Phase 8 — End-to-End E2E Testing
- **E2E Integration Test Suite**: Created `backend/tests/test_e2e_day9_process_monitoring.py`.
- **Validation Scenarios**:
  1. **Normal applications**: Ingestion of `explorer.exe` & `chrome.exe` (0 threats/alerts triggered).
  2. **High CPU process**: Telemetry ingestion of `ffmpeg.exe` at 92.5% CPU percentage.
  3. **Suspicious command-line arguments**: `powershell.exe -w hidden -enc ...` and `certutil.exe -urlcache ...` triggering high-severity alerts.
  4. **Parent-child detection**: `winword.exe` spawning `cmd.exe` triggering `ParentChildChainRule`.
  5. **Process termination**: Live event diffing processing `terminated` events and logging `PROCESS_TERMINATED` audit entries.
  6. **Dashboard updates**: Verifying HTTP 200 OK payloads from `GET /api/v1/processes` and `GET /api/v1/processes/audit-logs`.

### 🛡️ Enterprise Detection Rule Metadata Enhancements
- **MITRE ATT&CK Mapping**: Standardized ATT&CK technique IDs across rules (`T1059.001`, `T1059.003`, `T1059`, `T1105`).
- **Detection Confidence Rating**: Quantitative confidence score (e.g. `98%` confidence vs severity).
- **Rule Versioning**: Explicit semantic rule versioning (`1.0.0`) for runtime rule tuning and updates.
- **Stable Rule Identifiers**: Assigned unique static identifiers (`RULE-0001` to `RULE-0004`) for suppression logic and audit tracking.

---

## Test Verification Matrix

| Test Suite | Total Tests | Status |
| :--- | :---: | :---: |
| Backend Pytest Suite (including `test_e2e_day9_process_monitoring.py`) | 85 | PASSED |
| Agent Pytest Suite | 47 | PASSED |
| Frontend Production Build | 97 Modules Transformed | PASSED |
| **Combined EDR Test Suite** | **132** | **ALL PASSED** |
