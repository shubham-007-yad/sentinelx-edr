# SentinelX EDR — Day 12: Windows Event Logs & Authentication Monitoring

## Overview
Day 12 equips **SentinelX EDR** with deep visibility into operating system security events, authentication activity, privilege changes, defense evasion attempts, and persistence mechanisms across Windows and Linux endpoints.

---

## Deliverables Summary

| Deliverable | Component / File | Description |
| :--- | :--- | :--- |
| **OS Event Inventory** | [`event_log.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/models/event_log.py) | Database model (`SecurityEvent`) storing event source, native OS event ID, level, username, domain, computer, logon type, source IP, description, and raw JSON payload. |
| **Agent Collector** | [`event_log_collector.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/agent/collectors/event_log_collector.py) | Cross-platform collector gathering Windows Security (`Security.evtx`), System (`System.evtx`), Application (`Application.evtx`) logs via PowerShell/`Get-WinEvent`, as well as Linux `auth.log`, `syslog`, and `journalctl`. |
| **Ingestion Engine** | [`event_log_service.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/services/event_log_service.py) | Service handling telemetry ingestion, metric aggregation (`get_authentication_summary`), and timeline generation (`get_auth_timeline`). |
| **Detection Rules** | [`event_log_rules.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/detection/rules/event_log_rules.py) | Modular detection rules for Brute Force, Admin Escalation, Account Disabled, Off-Hours Logons, Service Persistence, and Log Clearing. |
| **Threat Engine Pipeline** | [`engine.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/detection/engine.py), [`pipeline.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/detection/pipeline.py) | Modular registration in `DetectionEngine` emitting threats and alerts with risk scoring to WebSockets. |
| **API Endpoints** | [`event_logs.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/api/event_logs.py) | REST API endpoints (`POST /api/v1/events/ingest`, `GET /api/v1/events`, `GET /api/v1/events/summary`, `GET /api/v1/events/auth-timeline`, `POST /api/v1/events/simulate`). |
| **SOC Dashboard** | [`EventLogDashboard.tsx`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/frontend/src/pages/EventLogDashboard.tsx) | `/events` console featuring 5 metrics cards, attack chain timeline visualizer, live event stream with search/filters, and interactive attack simulator. |
| **Simulation & Phase 8 Tests** | [`simulate_event_log_test.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/simulate_event_log_test.py), [`test_e2e_day12_phase8_full_validation.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/tests/test_e2e_day12_phase8_full_validation.py) | Comprehensive test suite validating successful/failed logons, brute force, admin escalation, services, tasks, metrics, attack chains, and audited response actions. |


---

## Architecture & Detection Flow

```
Windows (Security.evtx / System.evtx) / Linux (auth.log / journalctl)
                                │
                                ▼
         Event Log Collector Agent (agent/collectors/event_log_collector.py)
                                │
                                ▼
         FastAPI Ingestion Endpoint (POST /api/v1/events/ingest)
                                │
                                ▼
         Modular Detection Engine (backend/app/detection/engine.py)
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
     Brute Force       Admin Escalation       Persistence & Evasion
     (Event 4625)       (Event 4732/4672)     (Event 4697/4702/1102)
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                ▼
         Threat & Alert Pipeline ➔ WebSocket Broadcast ➔ React Console (/events)
```

---

## Supported Windows & Linux Event IDs

- **Windows Security Event Log**:
  - `4624`: Successful Logon (Logon Types: 2-Interactive, 3-Network, 10-RemoteDesktop, 7-Unlock)
  - `4625`: Failed Logon (Unknown account, bad password, account disabled/locked)
  - `4672`: Special Privileges Assigned to New Logon (Administrator / System Logon)
  - `4720`: User Account Created
  - `4732` / `4728`: User Added to Security-Enabled Group (`Administrators`, `Domain Admins`)
  - `4725` / `4740`: Account Disabled / Account Locked Out
  - `1102` / `104`: Security Audit Log Cleared (Defense Evasion / Anti-Forensics)
  - `4697` / `7045`: Windows System Service Installed (Persistence)
  - `4702` / `4698`: Scheduled Task Created or Modified (Persistence)
- **Linux Security Logs (`auth.log`, `secure`, `journalctl`)**:
  - `SSH_SUCCESS`: Accepted password / SSH session opened
  - `SSH_FAILED`: Failed password for user from remote IP
  - `SUDO_EXEC`: Execution of `sudo` / `su` privilege escalation commands
  - `USER_CREATED`: User added via `useradd` / `usermod -aG sudo`
  - `LOG_CLEARED`: Disruption or clearing of `/var/log/auth.log`

---

## Detection Rules Summary

1. **Possible Brute Force (`BruteForceLogonRule`)**:
   - **Severity**: `CRITICAL`
   - **MITRE ATT&CK**: `T1110` (Brute Force)
   - **Condition**: 5+ failed logon attempts targeting an account or IP within 30 seconds.

2. **New Administrator Account (`NewAdminAccountRule`)**:
   - **Severity**: `HIGH`
   - **MITRE ATT&CK**: `T1078.001` (Valid Accounts: Default Accounts)
   - **Condition**: User created or added to administrative security groups (`Administrators`, `sudo`, `wheel`).

3. **Account Disabled (`AccountDisabledRule`)**:
   - **Severity**: `MEDIUM`
   - **MITRE ATT&CK**: `T1531` (Account Access Removal)
   - **Condition**: Account disabled or locked out (`Event ID 4725`, `4740`).

4. **Suspicious Login Time (`SuspiciousLoginTimeRule`)**:
   - **Severity**: `MEDIUM`
   - **MITRE ATT&CK**: `T1078`
   - **Condition**: Interactive logon occurring during off-hours (e.g., 03:15 AM between 11 PM and 5 AM).

5. **Simultaneous Multi-Device Access (`SimultaneousMultiDeviceLoginRule`)**:
   - **Severity**: `HIGH`
   - **MITRE ATT&CK**: `T1078`
   - **Condition**: Same user account logged on concurrently across multiple endpoints.

6. **New Windows Service Creation (`NewServiceCreationRule`)**:
   - **Severity**: `HIGH`
   - **MITRE ATT&CK**: `T1543.003` (Windows Service Persistence)
   - **Condition**: Installation of a new system service (`Event ID 4697`, `7045`).

7. **Scheduled Task Creation (`ScheduledTaskCreationRule`)**:
   - **Severity**: `HIGH`
   - **MITRE ATT&CK**: `T1053.005` (Scheduled Task)
   - **Condition**: Creation of auto-start scheduled tasks (`Event ID 4702`, `4698`).

8. **Defense Evasion: Audit Log Cleared (`DefenseEvasionLogClearingRule`)**:
   - **Severity**: `CRITICAL`
   - **MITRE ATT&CK**: `T1070.001` (Clear Windows Event Logs)
   - **Condition**: Clearing of Security audit logs (`Event ID 1102`, `104`).

---

## Running the Day 12 Simulation Suite

To run the full end-to-end validation test suite:

```bash
PYTHONPATH=backend:.:agent backend/venv/bin/python simulate_event_log_test.py
```
