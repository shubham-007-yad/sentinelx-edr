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

- **Security Console Dashboard (`frontend/`)**:
  - Real-time **USB Activity** audit console (`/usb-activity`) featuring metrics overview, endpoint filtering, event type filtering, and paginated event table view.

---

## 📖 Complete Documentation & Flow

Detailed architecture diagrams, sequence flow diagrams, API specifications, performance optimizations, and error handling notes are available in:
📄 **[docs/USB_PIPELINE.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/USB_PIPELINE.md)**

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

### Manual & Real USB Verification Script
```bash
cd agent
PYTHONPATH=. ../backend/venv/bin/python verify_usb_real.py --mock
```
