# SentinelX EDR — USB Event Monitoring & Forensics Module

SentinelX EDR is an Enterprise Endpoint Detection and Response (EDR) solution featuring real-time USB hardware device monitoring, metadata forensic extraction, automatic event reporting with network fault-tolerance, and an interactive security console dashboard.

---

## 🌟 Key Architecture & Features

- **USB Detection Engine (`agent/detectors`)**:
  - Native Win32 API removable drive enumeration via `ctypes` (`GetLogicalDriveStringsW`, `GetDriveTypeW`, `GetVolumeInformationW`, `GetDiskFreeSpaceExW`).
  - Event listener architecture detecting USB `INSERT` and `REMOVE` events.
  - State deduplication preventing duplicate event spamming.

- **USB Metadata Collector (`agent/collectors`)**:
  - Extracts volume label, drive letter, filesystem (`FAT32`, `NTFS`, `exFAT`), capacity, free space, volume serial number, and UTC ISO 8601 timestamps into structured JSON payloads.

- **Fault-Tolerant HTTP API Client (`agent/api`)**:
  - Zero-user-interaction automated upload to backend `POST /api/v1/usb/events`.
  - Exponential backoff retry logic (`1s`, `2s`, `4s`) for transient network drops.

- **FastAPI & PostgreSQL Backend (`backend/`)**:
  - PostgreSQL database table `usb_events` with indexed queries.
  - REST API endpoints for event creation, listing with pagination and filtering, and event detail lookup.

- **Threat Detection Engine (`backend/app/services/threat_engine.py` & `agent/threat_engine.py`)**:
  - Signature matching against known malicious SHA-256 fingerprints (e.g. EICAR malware test string).
  - Deceptive double extension detection (e.g., `invoice.pdf.exe`).
  - Hidden executable and script detection on removable media.
  - USB AutoRun script configuration detection (`autorun.inf`).
  - Suspicious script payload detection (`.vbs`, `.ps1`, `.bat`, `.cmd`, `.scr`, `.hta`).
  - Anomalous OS process masquerading detection (`svchost.exe`, `lsass.exe`).

- **Interactive Threat Console Dashboard (`frontend/src/pages/ThreatDashboard.tsx`)**:
  - Real-time **Threat Dashboard** (`/threats`) featuring severity metrics overview, status management, forensic inspection modal, and incident remediation actions.

---

## 📖 Complete Documentation & Flow

- 📄 **[docs/THREAT_DETECTION_ENGINE.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/THREAT_DETECTION_ENGINE.md)** — Day 6 Threat Detection Engine Architecture
- 📄 **[docs/USB_SCANNING_PIPELINE.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/USB_SCANNING_PIPELINE.md)** — Day 5 File Scanning Pipeline
- 📄 **[docs/USB_PIPELINE.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/USB_PIPELINE.md)** — Day 1-4 USB Event Pipeline

---

## 🧪 Running Unit & Integration Test Suites

### Backend Test Suite
```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest
```

### Agent Test Suite
```bash
cd agent
PYTHONPATH=. ../backend/venv/bin/pytest
```

### Day 6 Threat Detection Verification Script
```bash
cd agent
PYTHONPATH=. ../backend/venv/bin/python verify_threat_engine.py --mock
```
