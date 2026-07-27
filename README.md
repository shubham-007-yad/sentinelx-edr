# SentinelX EDR — Threat Detection Engine & Forensics Module

SentinelX EDR is an Enterprise Endpoint Detection and Response (EDR) solution featuring real-time USB hardware device monitoring, metadata forensic extraction, background file hashing, a modular Threat Detection Engine, centralized threat scoring, and an interactive security console dashboard.

---

## 🔄 Complete End-to-End Threat Detection Flow

```
Insert USB  ──>  Scan Files  ──>  Run Detection Rules  ──>  Create Threat Records  ──>  Display Threats
```

---

## 🌟 Architecture & Completed Phases (Phases 1–8)

- **Phase 1 — Modular Detection Engine (`app/detection`)**:
  - Plugin-based rule engine (`BaseRule`, `RuleResult`, `DetectionEngine`) allowing modular rule registration.
- **Phase 2 — Known Malware Signature Matching**:
  - `KnownMalwareRule` evaluating file SHA-256 hashes against threat intelligence databases.
- **Phase 3 — Dangerous Extension & Hidden File Detection**:
  - `DangerousExtensionRule` and `HiddenExecutableRule` flagging dangerous executables/scripts (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, etc.) and hidden binaries on removable drives.
- **Phase 4 — Double Extension Deception Detection**:
  - `DoubleExtensionRule` identifying dual-extension spoofing attempts (e.g. `invoice.pdf.exe`).
- **Phase 5 — AutoRun Script Detection**:
  - `AutoRunRule` detecting `autorun.inf` and AutoRun configuration persistence mechanisms.
- **Phase 6 — Centralized Threat Scoring**:
  - `ThreatScorer` standardizing severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and numeric risk scores (`25`, `50`, `75`, `100`) with dynamic runtime score adjustments.
- **Phase 7 — Threat APIs & Interactive Dashboard (`/threats`)**:
  - REST API endpoints (`GET /api/v1/threats`, `GET /api/v1/threats/{id}`, `PATCH /api/v1/threats/{id}/status`, `GET /api/v1/threats/summary`).
  - Frontend Threat Dashboard with filters (`Severity`, `Status`, `Threat type`, `Search`) and 6 required columns (`File name`, `Threat type`, `Severity`, `Rule`, `Status`, `Detection time`).
- **Phase 8 — Testing & Documentation**:
  - Complete end-to-end integration test suite (`test_e2e_phase8_complete_flow.py`) verifying the complete flow from USB insertion to threat display.
  - Comprehensive documentation in [`docs/PHASE_8_TESTING_AND_DOCUMENTATION.md`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/PHASE_8_TESTING_AND_DOCUMENTATION.md).

---

## 📖 Key Documentation

- 📄 **[docs/PHASE_8_TESTING_AND_DOCUMENTATION.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/PHASE_8_TESTING_AND_DOCUMENTATION.md)** — Complete Architecture, Rules, APIs & Test Scenarios
- 📄 **[docs/THREAT_DETECTION_ENGINE.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/THREAT_DETECTION_ENGINE.md)** — Threat Detection Engine Specification
- 📄 **[docs/USB_SCANNING_PIPELINE.md](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/docs/USB_SCANNING_PIPELINE.md)** — File Scanning Pipeline

---

## 🧪 Running Unit & Integration Test Suites

### Run Complete Pytest Suite (50 Tests):
```bash
PYTHONPATH=backend backend/venv/bin/pytest backend/tests
```

### Run Phase 8 End-to-End Complete Flow Test:
```bash
PYTHONPATH=backend backend/venv/bin/pytest backend/tests/test_e2e_phase8_complete_flow.py
```
