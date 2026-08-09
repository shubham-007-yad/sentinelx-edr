# Day 14 — Ransomware Detection & Behavioral Analytics Architecture

SentinelX EDR includes signature-less Ransomware Detection & Behavioral Analytics. Rather than relying on static file hashes or known signatures, SentinelX observes real-time filesystem, process, network, and system behavior across rolling time windows to detect and neutralize zero-day ransomware attacks.

---

## 🏗 System Architecture & Telemetry Pipeline

```
File Integrity Monitor (FIM) ──┐
Process Monitor Daemon        ──┼──> Telemetry Framework ──> Behavior Correlation Engine ──> Ransomware Detection Engine ──> Threat & Response Engine
Network Socket Monitor        ──┘
```

---

## 🔬 Core Components & Implementation

### 1. Behavioral Correlation Engine (`backend/app/detection/behavior/`)
- Maintains rolling 60-second sliding time windows grouped by process `(device_id, pid)`.
- Calculates Shannon Entropy $H(X) = - \sum P(x) \log_2 P(x)$ on file payloads ($0.0 - 8.0$ bits per byte).
- Tracks shadow copy deletion commands (`vssadmin delete shadows`, `wbadmin`, `bcdedit`).
- Identifies dropped ransom notes (`READ_ME.txt`, `HOW_TO_DECRYPT.html`).

### 2. Process-Level File Activity Aggregator (`ProcessFileAggregator`)
- Aggregates file actions per process: Created, Modified, Deleted, Renamed.
- Tracks extension mutations (e.g., `.docx` $\rightarrow$ `.docx.locked`).
- Records SHA-256 hash transformations.
- Measures mutation velocity (e.g., 500 files modified in 30 seconds $\rightarrow$ `16.67 files/sec`).

### 3. Modular Ransomware Rules (`ransomware_rules.py`)
- **Rule 1 — `MassFileModificationRule`**: 300 files modified in 20s (`CRITICAL`).
- **Rule 2 — `MassExtensionRenameRule`**: Rapid extension swaps across files (`CRITICAL`).
- **Rule 3 — `EntropyIncreaseRule`**: Payload entropy $\ge 7.5$ (`CRITICAL`).
- **Rule 4 — `DeleteOriginalAfterRewriteRule`**: Original file wipe workflow (`HIGH`).
- **Rule 5 — `KnownRansomwareExtensionRule`**: Configurable extension list (`CRITICAL`).

### 4. Multi-Vector Correlation Scoring Engine (`RansomwareCorrelationScorer`)
Combines evidence dynamically into a single **Composite Correlation Score ($0 - 100$)**:
- Mass rename: **35 pts**
- Entropy increase: **30 pts**
- Original deletion: **20 pts**
- High file count: **15 pts**
- Shadow copy wipe: **+25 pts (Bonus)**
- Known ransomware extension: **+30 pts (Bonus)**

### 5. Automated Response Engine (`RansomwareResponseEngine`)
Executes automated multi-stage containment when score $\ge 80$ (`CRITICAL`):
- **Suspend Process**: `SIGSTOP` / process freeze.
- **Terminate Process**: `SIGKILL` / `taskkill /F /PID`.
- **Isolate Endpoint**: Network interface drop.
- **Quarantine Files**: Encrypted file vaulting to `.quarantine/` (`chmod 000`).
- **Notify SOC**: WebSocket broadcast & high-priority alert.

### 6. Interactive SOC Ransomware Dashboard (`/ransomware`)
- Summary Metrics Cards (Suspicious Processes, Files Modified, Endpoints Affected, Critical Incidents).
- Attack Storyline Timeline Trace (10:02 Mass modification $\rightarrow$ 10:03 Extensions changed $\rightarrow$ 10:04 Critical Alert $\rightarrow$ 10:04 Endpoint isolated).
- Live Process Risk Matrix & One-Click SOC Containment Actions (**Kill PID**, **Isolate Endpoint**, **Attack Simulator**).

---

## 🧪 Phase 8 Validation Test Suite

Run the full Phase 8 validation test suite:

```bash
PYTHONPATH=backend:.:agent backend/venv/bin/pytest backend/tests/test_e2e_day14_phase8_full_validation.py
```

Run the end-to-end simulation runner:

```bash
PYTHONPATH=backend:.:agent backend/venv/bin/python simulate_ransomware_test.py
```
