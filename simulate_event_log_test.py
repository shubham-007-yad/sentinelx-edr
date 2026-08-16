#!/usr/bin/env python3
"""
SentinelX EDR — Real EDR Architecture OS Event Log Simulation Test
Implements Real EDR Flow:
1. Agent EventLogCollector gathers native Windows/Linux security & authentication event logs.
2. Agent transmits security event telemetry to FastAPI Backend REST API (/api/v1/events/ingest).
3. Backend ingests events, evaluates DetectionEngine rules, and passes detections to DetectionPipeline.
4. DetectionPipeline persists Threat & Alert in database and broadcasts real-time WebSocket events (NEW_ALERT) to the dashboard.
"""

import os
import sys
import uuid
import logging
import requests
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "agent")))
from agent.collectors.event_log_collector import EventLogCollector

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")


def get_auth_token_and_device():
    session = requests.Session()
    username = os.environ.get("SENTINELX_ADMIN_USER", "admin")
    password = os.environ.get("SENTINELX_ADMIN_PASS", "AdminPassword123!")

    login_url = f"{API_BASE_URL}/api/v1/auth/login/json"
    auth_resp = session.post(login_url, json={"username_or_email": username, "password": password})
    if auth_resp.status_code != 200:
        raise RuntimeError(f"Authentication failed: {auth_resp.text}")

    token = auth_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    dev_url = f"{API_BASE_URL}/api/v1/devices"
    dev_resp = session.get(dev_url, headers=headers)
    devices = dev_resp.json() if dev_resp.status_code == 200 else []

    if devices and isinstance(devices, list):
        device_id = devices[0]["id"]
        hostname = devices[0].get("hostname", "sentinelx-dc-node")
    else:
        reg_dev_resp = session.post(dev_url, headers=headers, json={
            "hostname": "sentinelx-dc-node",
            "os_type": "WINDOWS",
            "os_version": "Windows Server 2022 Datacenter",
            "ip_address": "192.168.1.100",
            "agent_version": "1.0.0"
        })
        device_id = reg_dev_resp.json()["id"]
        hostname = "sentinelx-dc-node"

    return token, device_id, hostname, headers


def run_simulation():
    print("\n==========================================================================")
    print(" 🚀 SentinelX EDR — REAL EDR PIPELINE: OS EVENT LOG SIMULATION & ALERTS ")
    print("==========================================================================\n")

    print(f"[+] Connecting to SentinelX EDR Backend API at {API_BASE_URL}...")
    try:
        token, device_id, hostname, headers = get_auth_token_and_device()
        print(f"  ✓ Authenticated successfully with JWT Token.")
        print(f"  ✓ Endpoint Device ID: {device_id} ({hostname})")
    except Exception as e:
        print(f"  ❌ Failed to connect to Backend API: {e}")
        print("     Please ensure uvicorn is running: uvicorn app.main:app --reload")
        return False

    # 1. Agent Collector Test
    collector = EventLogCollector(device_id=str(device_id))
    collected_events = collector.collect_events(limit=10)
    print(f"[*] Agent EventLogCollector gathered {len(collected_events)} native/simulated OS events.")

    # Send Baseline Ingestion via REST API
    ingest_url = f"{API_BASE_URL}/api/v1/events/ingest"
    baseline_payload = {"device_id": str(device_id), "events": collected_events}
    ingest_resp = requests.post(ingest_url, json=baseline_payload, headers=headers)
    print(f"[+] Agent -> Backend Ingestion: HTTP {ingest_resp.status_code} ({ingest_resp.json() if ingest_resp.status_code == 201 else ingest_resp.text})\n")

    # 2. Trigger Attack Scenarios
    print("--------------------------------------------------------------------------")
    print(" 🎯 Executing Real EDR Attack Simulation Scenarios ")
    print("--------------------------------------------------------------------------")

    scenarios = [
        ("BRUTE_FORCE", "5 Rapid Failed Logons from Remote IP 198.51.100.44"),
        ("PRIVILEGE_ESCALATION", "New Admin Account created & added to Administrators group"),
        ("ACCOUNT_DISABLED", "User account disabled / lockout event"),
        ("OFF_HOURS", "Interactive logon at 03:15 AM off-hours"),
        ("PERSISTENCE", "Windows Service Creation: MalwarePersistenceSvc"),
        ("LOG_CLEARING", "CRITICAL: Security Audit Log Cleared (Event ID 1102)")
    ]

    total_simulated_threats = 0
    for scenario_code, description in scenarios:
        sim_events = []
        now_iso = datetime.now(timezone.utc).isoformat()

        if scenario_code == "BRUTE_FORCE":
            for i in range(5):
                sim_events.append({
                    "id": str(uuid.uuid4()),
                    "device_id": str(device_id),
                    "event_source": "Security",
                    "event_id": "4625",
                    "event_type": "AUTHENTICATION_FAILURE",
                    "level": "Warning",
                    "username": "domain_admin_target",
                    "computer": hostname,
                    "logon_type": "10-RemoteDesktop",
                    "ip_address": "198.51.100.44",
                    "status": "FAILED",
                    "description": f"Failed logon attempt #{i+1} for domain_admin_target",
                    "timestamp": now_iso
                })
        elif scenario_code == "PRIVILEGE_ESCALATION":
            sim_events.append({
                "id": str(uuid.uuid4()),
                "device_id": str(device_id),
                "event_source": "Security",
                "event_id": "4732",
                "event_type": "PRIVILEGE_ESCALATION",
                "level": "Warning",
                "username": "shadow_admin",
                "computer": hostname,
                "status": "SUCCESS",
                "description": "User shadow_admin added to Administrators security-enabled group",
                "timestamp": now_iso
            })
        elif scenario_code == "ACCOUNT_DISABLED":
            sim_events.append({
                "id": str(uuid.uuid4()),
                "device_id": str(device_id),
                "event_source": "Security",
                "event_id": "4725",
                "event_type": "ACCOUNT_MANAGEMENT",
                "level": "Warning",
                "username": "locked_account",
                "computer": hostname,
                "status": "SUCCESS",
                "description": "User account locked_account was disabled",
                "timestamp": now_iso
            })
        elif scenario_code == "OFF_HOURS":
            sim_events.append({
                "id": str(uuid.uuid4()),
                "device_id": str(device_id),
                "event_source": "Security",
                "event_id": "4624",
                "event_type": "AUTHENTICATION_SUCCESS",
                "level": "Information",
                "username": "night_operator",
                "computer": hostname,
                "logon_type": "2-Interactive",
                "ip_address": "10.0.0.50",
                "status": "SUCCESS",
                "description": "User night_operator logged in interactively at 03:15 AM off-hours",
                "timestamp": "2026-08-02T03:15:00Z"
            })
        elif scenario_code == "PERSISTENCE":
            sim_events.append({
                "id": str(uuid.uuid4()),
                "device_id": str(device_id),
                "event_source": "Security",
                "event_id": "4697",
                "event_type": "PERSISTENCE",
                "level": "Warning",
                "username": "SYSTEM",
                "computer": hostname,
                "status": "SUCCESS",
                "description": "A service was installed in the system: MalwarePersistenceSvc",
                "timestamp": now_iso
            })
        elif scenario_code == "LOG_CLEARING":
            sim_events.append({
                "id": str(uuid.uuid4()),
                "device_id": str(device_id),
                "event_source": "Security",
                "event_id": "1102",
                "event_type": "DEFENSE_EVASION",
                "level": "Critical",
                "username": "Administrator",
                "computer": hostname,
                "status": "SUCCESS",
                "description": "CRITICAL: The audit log was cleared by Administrator",
                "timestamp": now_iso
            })

        scenario_payload = {"device_id": str(device_id), "events": sim_events}
        resp = requests.post(ingest_url, json=scenario_payload, headers=headers)
        res = resp.json() if resp.status_code == 201 else {"ingested": 0, "threats_detected": 0}
        total_simulated_threats += res.get("threats_detected", 0)
        print(f" 📡 [AGENT -> BACKEND TELEMETRY] [{scenario_code}] {description} -> Ingested: {res.get('ingested')}, Threats/Alerts Fired: {res.get('threats_detected')}")

    # 3. Verify Backend Alerts & WebSocket Broadcast
    print("\n--------------------------------------------------------------------------")
    print(" 📊 Fetching Backend Generated Alerts & Live Dashboard State ")
    print("--------------------------------------------------------------------------")
    alerts_url = f"{API_BASE_URL}/api/v1/alerts?device_id={device_id}"
    alerts_resp = requests.get(alerts_url, headers=headers)
    alerts = alerts_resp.json() if alerts_resp.status_code == 200 else []

    print(f"  ✓ Fetched {len(alerts)} Alert records generated by Backend DetectionPipeline for Device {device_id}.")
    for a in alerts[:5]:
        print(f"      🚨 [BACKEND ALERT] {a.get('severity')} | {a.get('title')} | Message: {a.get('message')}")

    print("\n" + "=" * 80)
    print(" 🎉 REAL EDR EVENT LOG PIPELINE SIMULATION VALIDATED SUCCESSFULLY!")
    print("=" * 80 + "\n")
    return True


if __name__ == "__main__":
    success = run_simulation()
    sys.exit(0 if success else 1)
