# SentinelX EDR — Day 11: File Integrity Monitoring (FIM)

## Overview
Day 11 implements **File Integrity Monitoring (FIM)** into **SentinelX EDR**. FIM detects unauthorized modifications, deletions, creations, double-extension masquerading, and ransomware-like mass file encryption on critical system and user paths.

---

## Deliverables Summary

| Deliverable | Component / File | Description |
| :--- | :--- | :--- |
| **File Integrity Inventory** | [`file_integrity_record.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/models/file_integrity_record.py) | Database baseline schema storing SHA-256, byte size, modification timestamp, owner, and executable permissions. |
| **Real-Time Monitoring** | [`file_watcher.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/agent/collectors/file_watcher.py) | Watchdog + Directory Poller engine monitoring target folders (`Desktop`, `Downloads`, `Documents`, `Startup`). |
| **Hash Verification** | [`integrity_engine.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/agent/integrity_engine.py) | Real-time diffing engine computing cryptographic SHA-256 and size mismatches against baseline. |
| **Detection Rules** | [`fim_detector.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/agent/detectors/fim_detector.py), [`fim_rules.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/detection/rules/fim_rules.py) | Heuristic rules for Executable in Downloads, Double Extension Masquerade, Startup Modification, and Ransomware Mass Modification. |
| **Dashboard** | [`IntegrityDashboard.tsx`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/frontend/src/pages/IntegrityDashboard.tsx) | `/integrity` console featuring 5 metrics cards (`Files Monitored`, `Modified`, `Deleted`, `Created`, `Suspicious`) and event table. |
| **Response Actions** | [`file_integrity_service.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/services/file_integrity_service.py) | Active response controls (`Restore Baseline`, `Quarantine`, `Ignore`, `Allowlist`, `Recalculate Baseline`). |
| **Chronological Timeline** | [`api/file_integrity.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/api/file_integrity.py) | `GET /api/v1/fim/timeline/{device_id}` audit trail visualizer (Created ➔ SHA Changed ➔ Alert ➔ Quarantined). |
| **Tests & Verification** | [`simulate_fim_test.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/simulate_fim_test.py), [`test_e2e_day11_phase8_full_validation.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/tests/test_e2e_day11_phase8_full_validation.py) | Automated test suites passing 100%. |

---

## Detection Rules & MITRE ATT&CK Mapping

1. **Executable Dropped in Downloads** (`FIM_EXECUTABLE_IN_DOWNLOADS`)
   - **Severity**: `HIGH`
   - **MITRE ATT&CK**: `T1204.002` (User Execution: Malicious File)
   - **Trigger**: Executable binary created or modified in Downloads directory.

2. **Double Extension Masquerade** (`FIM_DOUBLE_EXTENSION_MASQUERADE`)
   - **Severity**: `CRITICAL`
   - **MITRE ATT&CK**: `T1036.007` (Masquerading: Double File Extension)
   - **Trigger**: File disguising executable payload with double extension (e.g., `invoice.docx.exe`).

3. **Startup Location Modification** (`FIM_STARTUP_MODIFICATION`)
   - **Severity**: `HIGH`
   - **MITRE ATT&CK**: `T1547.001` (Persistence: Registry Run Keys / Startup Folder)
   - **Trigger**: File creation or modification in persistent autostart locations.

4. **Mass File Modification / Ransomware Heuristic** (`FIM_MASS_FILE_MODIFICATION`)
   - **Severity**: `CRITICAL`
   - **MITRE ATT&CK**: `T1486` (Impact: Data Encrypted for Impact)
   - **Trigger**: Rapid filesystem modifications exceeding threshold (e.g., ≥ 10 files in 10s).

---

## Response Actions

- **Restore Baseline (Simulation)**: Reverts file metadata/checksum back to clean baseline state.
- **Quarantine File**: Moves suspicious file to secure quarantine vault.
- **Ignore Change**: Suppresses integrity alert for target path.
- **Allowlist**: Adds file path and SHA-256 hash to enterprise allowlist.
- **Recalculate Baseline**: Re-hashes disk file and updates baseline database record.

---

## API Endpoints

- `GET /api/v1/fim/records` — Query baseline inventory records.
- `POST /api/v1/fim/baseline/{device_id}` — Ingest baseline file inventory from agent.
- `POST /api/v1/fim/verify/{device_id}` — Real-time event verification & diffing.
- `POST /api/v1/fim/respond/{device_id}` — Execute response action controls.
- `GET /api/v1/fim/timeline/{device_id}` — Get step-by-step chronological audit trail for a file.
