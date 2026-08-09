# Day 17 — Executive Reporting & Security Analytics

## 🎯 Strategic Goal
Transform SentinelX EDR from a raw detection platform into a high-level decision-support platform tailored for CISOs, IT Managers, and Executive Leadership.

---

## 🏗️ System Architecture & Data Flow

```
Unified Telemetry Data (Processes, Network, USB, FIM, Events)
          │
          ▼
   Threat, Alert, & Response Databases
          │
          ▼
   Analytics Engine (backend/app/analytics/)
   ├── engine.py (Facade Orchestrator)
   ├── aggregation.py (Telemetry Aggregator)
   ├── metrics.py (Signal-Weighted Risk Engine & SLAs)
   ├── trends.py (Multi-Stream Time-Series Trends)
   ├── mitre.py (12-Tactic ATT&CK Matrix Heatmap)
   └── reporting.py (Executive & Technical Report Packages)
          │
          ▼
   Executive Dashboard APIs (/api/v1/analytics/ & /api/v1/scheduled-reports/)
          │
          ▼
   Export Formats (PDF, CSV, JSON)
```

---

## 📦 Key Deliverables Completed

### 1. Analytics Engine (`backend/app/analytics/`)
- Unified orchestrator [`AnalyticsEngine`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/analytics/engine.py) providing aggregated executive metrics, endpoint risk scores, MITRE matrix insights, multi-stream trends, and report generation.

### 2. Executive Dashboard (`/api/v1/analytics/dashboard` & `/top-metrics`)
- Top Executive KPI cards: *Total Endpoints*, *Online Endpoints*, *Total Incidents*, *Critical Incidents*, *Threats Today*, *Alerts Today*, *Responses Executed*, *Average Response Time (MTTR)*.

### 3. Trend Analysis (`/api/v1/analytics/trends/charts`)
- Time-series trend data across 6 core streams:
  1. Threats per day / hour
  2. Alerts per day / hour
  3. Endpoint activity
  4. USB insertions
  5. Network detections
  6. Process detections
- Granularity support: `24h` (hourly), `7d` (daily), `30d` (daily), and `custom` date ranges.

### 4. MITRE ATT&CK Matrix Analytics (`/api/v1/analytics/mitre-matrix`)
- 12-Tactic Enterprise Matrix Heatmap grid columns with dynamic cell heat levels (`CRITICAL`, `HIGH`, `MEDIUM`, `INACTIVE`).
- Technique frequency counts, top tactics breakdown, and tactic/technique coverage percentages.

### 5. Endpoint Risk Scoring (`/api/v1/analytics/endpoint-risk`)
- Dynamic signal-weighted risk scoring algorithm (0 to 100):
  - *Critical Alerts*: +40
  - *Ransomware Behavior*: +25
  - *IOC Matches*: +20
  - *Suspicious PowerShell*: +15
  - *Isolation / Offline Penalty*: +15
- Outputs contributing factors breakdown and recommended analyst actions.

### 6. Report Generation (`/api/v1/analytics/report/`)
- **Executive Report**: High-level posture, KPIs, trends, endpoint health, and top risks.
- **Technical Report**: Full incident list, event timelines, IOC indicators, and response logs.
- **Export Formats**: Multi-page styled ReportLab PDF, tabular CSV, and structured JSON.

### 7. Scheduled Report Configuration (`/api/v1/scheduled-reports`)
- Database model [`ScheduledReportConfig`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/app/models/scheduled_report_config.py) supporting `DAILY`, `WEEKLY`, and `MONTHLY` report automation.
- CRUD endpoints and on-demand trigger execution (`POST /scheduled-reports/{id}/run-now`).

### 8. Automated Tests
- Comprehensive test coverage across 4 test suites:
  - [`tests/test_analytics_engine.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/tests/test_analytics_engine.py)
  - [`tests/test_analytics_api.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/tests/test_analytics_api.py)
  - [`tests/test_scheduled_reports.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/tests/test_scheduled_reports.py)
  - [`tests/test_e2e_day17_executive_reporting_and_analytics.py`](file:///home/rebelshub/Desktop/sentinelx-edr/SentinelX-EDR/backend/tests/test_e2e_day17_executive_reporting_and_analytics.py)
- Status: **100% PASSED** (4 passed in 3m 24s).

---

## 🚀 API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/analytics/top-metrics` | Top 8 Executive KPI cards |
| `GET` | `/api/v1/analytics/dashboard` | Full Executive Dashboard summary payload |
| `GET` | `/api/v1/analytics/endpoint-risk` | Endpoint risk rankings (0-100) & signals |
| `GET` | `/api/v1/analytics/mitre-matrix` | 12-tactic ATT&CK Matrix Heatmap & coverage % |
| `GET` | `/api/v1/analytics/trends/charts` | Multi-stream time-series trends (24h/7d/30d/custom) |
| `GET` | `/api/v1/analytics/response-performance` | MTTA, MTTR, and SLA compliance metrics |
| `GET` | `/api/v1/analytics/report` | Executive Summary Report JSON |
| `GET` | `/api/v1/analytics/report/technical` | Technical Incident Report JSON |
| `GET` | `/api/v1/analytics/report/pdf` | Download Executive / Technical PDF report |
| `GET` | `/api/v1/analytics/export-csv` | Download CSV data export streams |
| `POST` | `/api/v1/scheduled-reports` | Create scheduled report configuration |
| `GET` | `/api/v1/scheduled-reports` | List scheduled report configurations |
| `POST` | `/api/v1/scheduled-reports/{id}/run-now` | Execute scheduled report on-demand |
