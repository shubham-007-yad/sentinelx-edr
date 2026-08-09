# Day 16 — Central Security Policy Management Documentation

## 🎯 Goal & Architecture

Allow administrators to centrally define, enforce, audit, and distribute security policies across all managed SentinelX EDR endpoints. Instead of hardcoding rules into endpoint agent collectors, security behavior becomes dynamically configurable from the central dashboard without restarting code or re-deploying agents.

```
Administrator
        │
React Dashboard (/policies)
        │
FastAPI Backend API (/api/v1/policies)
        │
Policy Service & Policy Engine
        │
PostgreSQL Database (security_policies table)
        │
Policy Distribution API (/api/v1/policies/latest)
        │
SentinelX Agent (PolicySyncManager Daemon)
        │
Collectors (USB, Process, Network, FIM/Ransomware)
```

---

## 📦 Deliverables Summary

- [x] **Security Policy Database**: `SecurityPolicy` SQLAlchemy model & Alembic Migration `014_create_security_policies.py`.
- [x] **USB Policy Management**: Max file size inspection, extension filtering, SHA-256 toggles, auto-quarantine, read-only mode.
- [x] **Process Policy Management**: PowerShell & LOLBins inspection, CPU/Memory threshold sliders, blocklisted executable auto-kill, parent-child rules.
- [x] **Network Policy Management**: Prohibited destination ports, C2 remote IP blocklists, non-RFC1918 public connection monitoring, auto-severing.
- [x] **File Integrity & Ransomware Policy Management**: Protected watchlist folders, path exclusions, temporary file filtering, mass modification velocity limits, Shannon entropy thresholds.
- [x] **Policy Distribution to Agents**: Central `GET /api/v1/policies/latest` API and agent `PolicySyncManager` background daemon.
- [x] **Policy Dashboard UI**: Interactive React console at `/policies` with category tabs, enable/disable toggles, version history, JSON diff inspect modal, rollback, and clone actions.
- [x] **Versioning & Rollback**: Incremental versioning, rollback priority overrides, and clone duplication.
- [x] **Automated Tests**: 219 / 219 tests passing across backend and agent test suites.

---

## 🗄 1. Database Schema & Migration

### SQLAlchemy Model: `SecurityPolicy`
Defined in `backend/app/models/security_policy.py`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `UUID` | Primary Key |
| `policy_name` | `String(255)` | Descriptive policy name |
| `category` | `Enum` | Policy category (`USB`, `PROCESS`, `NETWORK`, `FIM`, `RANSOMWARE`) |
| `version` | `Integer` | Incremental version number (default `1`) |
| `enabled` | `Boolean` | Whether policy is active |
| `priority` | `Integer` | Priority weight for conflict resolution |
| `configuration` | `JSON/JSONB` | Dynamic JSON configuration payload |
| `created_by` | `String(100)` | Administrator username |
| `created_at` | `DateTime` | Creation timestamp |
| `updated_at` | `DateTime` | Last update timestamp |

Alembic Migration: `014_create_security_policies.py`.

---

## ⚙️ 2. Policy Categories & Schemas

Defined in `backend/app/schemas/security_policy.py`:

### A. USB Security Policy (`USBPolicyConfigSchema`)
- `enable_usb_monitoring`: Monitor USB device insertion/removal.
- `enable_auto_scanning`: Automatically scan connected removable drives.
- `scan_removable_only`: Limit scanning strictly to removable media.
- `max_file_size_mb`: File size limit for inspection (default `50 MB`).
- `ignored_extensions`: Ignored extensions (`[".tmp", ".log", ".bak", ".sys"]`).
- `enable_sha256_hashing`: SHA-256 calculation toggle.
- `block_unauthorized_usbs`: Block unauthorized USB drives.
- `auto_quarantine_suspicious`: Move suspicious executables to vault.
- `read_only_mode`: Force write-protection on USB storage.

### B. Process Security Policy (`ProcessPolicyConfigSchema`)
- `monitor_powershell`: Monitor PowerShell execution and encoded commands.
- `monitor_lolbins`: Monitor Living-off-the-Land binaries (`certutil`, `bitsadmin`).
- `cpu_threshold_percent`: CPU usage alert limit (default `80.0%`).
- `memory_threshold_mb`: Memory usage alert limit (default `500 MB`).
- `blocklisted_processes`: Prohibited binary names (`mimikatz.exe`, `psexec.exe`).
- `auto_kill_blocklisted`: Automatically terminate blocklisted binaries.
- `parent_child_rules_enabled`: Parent-child lineage anomaly detection.

### C. Network Security Policy (`NetworkPolicyConfigSchema`)
- `allowed_ports`: List of explicitly permitted destination ports.
- `blocked_ports`: Prohibited destination ports (`[4444, 1337, 6667, 31337]`).
- `blocklisted_ips`: Known C2 IP addresses (`["198.51.100.99", "203.0.113.5"]`).
- `monitor_external_connections`: Flag to monitor public IP sockets.
- `beacon_interval_threshold_seconds`: C2 beaconing interval limit (`60.0s`).
- `auto_block_c2_connections`: Automatically sever connections matching C2 criteria.

### D. File Integrity & Ransomware Policy (`FIMPolicyConfigSchema`)
- `protected_folders`: Monitored folders (`["Desktop", "Downloads", "Documents", "Startup"]`).
- `excluded_folders`: Excluded subfolders (`[".git", "node_modules", "tmp", "Cache"]`).
- `hash_algorithm`: Hashing algorithm (`"SHA-256"`).
- `ransomware_modification_threshold`: Max file modifications/min (`20`).
- `ransomware_entropy_threshold`: Shannon entropy limit (`7.2`).
- `ignore_temporary_files`: Auto-ignore swap files (`.tmp`, `.swp`, `~$`).
- `auto_quarantine_ransomware`: Auto-quarantine files upon ransomware detection.

---

## 📡 3. Policy Distribution API & Agent Sync

### Backend API Endpoints (`backend/app/api/policies.py`)

- `GET /api/v1/policies/latest`: Aggregates active security policies across all categories into `UnifiedSecurityPolicySyncResponse`.
- `GET /api/v1/policies/sync?device_id=...`: Alias endpoint for endpoint synchronization.
- `GET /api/v1/policies/history`: Retrieves version history across categories.
- `PATCH /api/v1/policies/{id}/toggle`: Enables or disables a security policy.
- `POST /api/v1/policies/{id}/clone`: Clones target policy into a draft copy.
- `POST /api/v1/policies/{id}/rollback`: Sets policy as active highest priority version.

### Agent PolicySyncManager Daemon (`agent/policy_sync.py`)

The agent runs a `PolicySyncManager` background thread that periodically polls `/api/v1/policies/latest`, checks the global version sequence number, and invokes dynamic callbacks to update collectors without restarting:
- `USBScanPipelineWorker.update_policy(usb_cfg)`
- `ProcessMonitor.update_policy(proc_cfg)`
- `NetworkMonitor.update_policy(net_cfg)`
- `AgentIntegrityEngine.update_policy(fim_cfg)`

---

## 💻 4. Interactive Policy Dashboard UI (`/policies`)

Located at `frontend/src/pages/PolicyDashboard.tsx`:

- **Category Tabs**: Switch between USB, Process, Network, File Integrity, Ransomware, and Version History.
- **Form Controls**: Checkboxes, ranges, sliders, text tag lists for live rule editing.
- **Audit & Version History**: Displays all policy versions with creator, priority, status badges, and action buttons:
  - **Enable / Disable**: Toggle policy active status.
  - **Clone**: Create a clone of existing policy rules.
  - **Rollback**: Instantly revert endpoint rules to an older policy version.
  - **Compare JSON**: Interactive modal displaying policy JSON configuration diffs.

---

## 🧪 5. Testing & Verification

Comprehensive test suites added to `backend/tests`:
- `test_security_policy_model.py`: Model creation and JSON serialization tests.
- `test_usb_policy.py`: USB policy API & worker tests.
- `test_process_policy.py`: Process policy API & monitor tests.
- `test_network_policy.py`: Network policy API & monitor tests.
- `test_fim_policy.py`: FIM policy API & integrity engine tests.
- `test_policy_distribution.py`: Unified sync API & `PolicySyncManager` tests.
- `test_e2e_day16_security_policy_management.py`: Full end-to-end integration tests.

### Test Execution Command
```bash
PYTHONPATH=backend:.:agent backend/venv/bin/pytest backend/tests agent/tests
```
**Results**: `219 passed, 0 failed` (100% pass rate).
