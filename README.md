# SentinelX EDR — Enterprise Endpoint Detection, Response & Forensics Platform (v1.0.0)

[![SentinelX CI/CD Pipeline](https://github.com/sentinelx-edr/sentinelx/actions/workflows/ci.yml/badge.svg)](https://github.com/sentinelx-edr/sentinelx/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/sentinelx-edr/sentinelx)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 1. Project Overview

**SentinelX EDR** is a next-generation Enterprise Endpoint Detection and Response (EDR) platform designed for real-time security monitoring, proactive threat hunting, behavioral ransomware detection, and automated active response containment.

Built to defend modern corporate networks against advanced cyber threats (APTs, Living-off-the-Land attacks, rogue USB payloads, and mass file encryption), SentinelX provides security operation center (SOC) teams with full incident visibility from initial telemetry collection to automated endpoint isolation.

---

## 2. Platform Architecture

```
                               ┌─────────────────────────┐
                               │  SentinelX Agent Engine │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │   Telemetry Envelope    │
                               │      (schema v1.0)      │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │  Unified Telemetry API  │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │   PostgreSQL / Redis    │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │    Detection Engines    │
                               │  ├── USB & File Scan    │
                               │  ├── File Integrity     │
                               │  ├── Process & LOLBins  │
                               │  ├── Network Sockets    │
                               │  ├── Security Events    │
                               │  ├── IOC Intelligence   │
                               │  └── Ransomware Engine  │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │ Threat / Correlation    │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │      Alert Engine       │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │     Response Engine     │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │   React SOC Dashboard   │
                               └─────────────────────────┘
```

---

## 3. Major Security Capabilities

- 🔌 **USB Monitoring & Payload Scanning**: Real-time USB insertion detection, double-extension executable rules (`invoice.pdf.exe`), and SHA256 malware hash matching.
- 🛡️ **File Integrity Monitoring (FIM)**: Real-time file system modification tracking, diff comparison, and baseline hash validation.
- ⚙️ **Live Process & LOLBin Monitoring**: Parent-child execution tracking, suspicious command-line detection (`powershell.exe -EncodedCommand`), and process termination.
- 🌐 **Network Telemetry & IP Containment**: Active socket monitoring, DNS anomaly detection, and automated remote IP blocking.
- ☣️ **Ransomware Behavioral Early Detection**: Rapid file encryption detection (.locked extensions), entropy spike analysis, and emergency endpoint network isolation.
- 🔍 **Incident Investigation & Timeline Reconstruction**: Correlation of multi-vector telemetry events into unified incident timelines using a single `correlation_id`.
- ⚡ **Automated Active Response Engine**: Immediate file quarantine, host network isolation (`STRICT_NETWORK_BLOCK`), process termination, and user account disabling.
- 📜 **Centralized Policy Distribution**: Enterprise security policy management with live agent sync, versioning, cloning, and rollback capability.
- 📡 **Fleet Management & Remote Command Center**: Real-time agent health monitoring, diagnostics collection, and remote command queueing.

---

## 4. Technology Stack

- **Frontend**: React 18, TypeScript, Vite, Vanilla CSS Design System
- **Backend API Gateway**: FastAPI (Python 3.12), Pydantic v2
- **Database & ORM**: PostgreSQL 16, SQLAlchemy 2.0, Alembic
- **Task Queue & Caching**: Redis 7, Celery / Background Worker Engine
- **Real-Time Communication**: WebSockets & Redis Pub/Sub
- **Containerization & Web Server**: Docker, Docker Compose, Nginx (Reverse Proxy & TLS)

---

## 5. Installation Guide

### Option A: Docker Compose (Recommended)

1. **Clone Repository & Setup Environment**:
   ```bash
   git clone https://github.com/sentinelx-edr/sentinelx.git
   cd sentinelx
   cp .env.example .env
   cp backend/.env.example backend/.env
   ```

2. **Launch Production Stack**:
   ```bash
   docker compose -f docker-compose.prod.yml up --build -d
   ```
   - **SOC Console UI**: `https://localhost` (Nginx TLS :443)
   - **Backend API**: `https://localhost/api/v1`

### Option B: Local Standalone Setup

1. **Backend Service**:
   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   alembic upgrade head
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

2. **Frontend Console**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## 6. Endpoint Agent Installation & Connection

1. **Install Agent Dependencies**:
   ```bash
   cd agent
   pip install -r requirements.txt
   ```

2. **Configure Backend Connection**:
   Update `agent/config.py` or specify environment variables:
   ```python
   BACKEND_URL = "http://localhost:8000/api/v1"
   AGENT_VERSION = "v1.0.0"
   ```

3. **Start Endpoint Agent Daemon**:
   ```bash
   python main.py
   ```
   The agent automatically registers with the backend API (`POST /devices/register`), receives a `device_id`, sends heartbeats every 30s, and starts local telemetry collectors.

---

## 7. Role-Based Access Control (RBAC) Matrix

| Security Feature | ADMIN | ANALYST | VIEWER |
| :--- | :---: | :---: | :---: |
| **User Administration & Role Assignment** | ✅ | ❌ | ❌ |
| **Security Policy Creation & Rollback** | ✅ | ❌ | ❌ |
| **Fleet Commands & Remote Upgrades** | ✅ | ❌ | ❌ |
| **USB Central Policy Mutation** | ✅ | ❌ | ❌ |
| **Threat Resolution & Alert Triage** | ✅ | ✅ | ❌ |
| **Case Investigation Creation** | ✅ | ✅ | ❌ |
| **Active Response Containment** | ✅ | ✅ | ❌ |
| **Read-Only Telemetry & Dashboards** | ✅ | ✅ | ✅ |

---

## 8. Security Architecture & Hardening

- 🔑 **JWT Token Authentication**: OAuth2 Password Bearer flow with HS256 algorithm enforcement, 30-minute access token expiration, and subject identification.
- 🛡️ **Role-Based Authorization**: Route-level dependency checks (`get_current_admin`, `get_current_analyst`, `get_current_viewer`) preventing privilege escalation.
- ✍️ **HMAC Command Signing**: All remote commands queued for endpoint agents carry SHA256 HMAC payload signatures to guarantee message integrity.
- 🔒 **TLS Encryption & CORS Control**: Nginx HTTPS/TLS 1.3 encryption for REST and WebSocket channels, with strict CORS domain origin limits.
- ⏱️ **Rate Limiting**: Redis-backed sliding window rate limiters protecting authentication, telemetry ingestion, and command APIs.
- 🕵️ **Log Redaction & Secrets Protection**: Centralized `SensitiveDataFilter` automatically redacting passwords, JWT tokens, API keys, and connection strings from application logs.

---

## 9. Detection Architecture Pipeline

```
           [ Telemetry Ingestion ]
           Standardized Envelope v1.0
                      │
                      ▼
            [ Detection Engine ]
            Rule & Pattern Matching
                      │
                      ▼
              [ Threat Record ]
          Categorized Threat Entry
                      │
                      ▼
               [ Alert Engine ]
         Severity-Based Notification
                      │
                      ▼
             [ Response Engine ]
       Automated / Manual Containment
```

---

## 10. Verification & Test Results

```
Backend Core Tests      → PASS (100%)
Endpoint Agent Tests    → PASS (100%)
Security & RBAC Audit   → PASS (100%)
Integration Tests       → PASS (100%)
Frontend Build          → PASS (100% - 0 Errors)
```

- **Phase 1 (Architecture Freeze)**: `1/1 PASSED`
- **Phase 2 (12-Stage Lifecycle)**: `1/1 PASSED`
- **Phase 3 (Three-Role Security)**: `3/3 PASSED`
- **Phase 4 (Final Security Audit)**: `4/4 PASSED`
- **Phase 5 (Final Attack Simulations)**: `3/3 PASSED`
- **Phase 6 (Frontend Build)**: `0 ERRORS`
- **Phase 7 (Agent Test Suite)**: `59/59 PASSED`

**Overall Status**: **`SENTINELX EDR v1.0.0 RELEASED & ENTERPRISE-READY`** 🚀
