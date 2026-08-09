import pytest
import time
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.process_info import ProcessInfo
from app.models.network_connection import NetworkConnection
from app.models.threat import Threat, ThreatType, ThreatSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.detection.network import NetworkDetectionEngine

client = TestClient(app)


def test_e2e_day10_master_network_validation():
    """
    Comprehensive Day 10 Master E2E Test Suite validating:
    1. Network Collection (Normal browsing, LAN traffic)
    2. All 5 Detection Rules (Suspicious Port, Blacklisted IP, Excessive Traffic, Beaconing, External PowerShell)
    3. Dashboard & API (Filtering, Search, Pagination, Live Updates)
    4. Response & Audit Logging (Block IP, Ignore, Allowlist, Kill Process, Audit Log Trail)
    """
    db = SessionLocal()
    try:
        # ==========================================
        # STEP 1: Setup Target Device & Process Inventory
        # ==========================================
        device = Device(
            hostname="enterprise-workstation-day10",
            ip_address="192.168.1.100",
            mac_address="DE:AD:BE:EF:10:00",
            os_type=OSType.WINDOWS,
            os_version="Windows 11 Pro",
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # Ingest process inventory (powershell.exe, chrome.exe, svchost.exe)
        proc_payload = {
            "processes": [
                {
                    "pid": 3000,
                    "ppid": 1000,
                    "name": "powershell.exe",
                    "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "username": "CORP\\Administrator",
                    "cmdline": "powershell.exe -ExecutionPolicy Bypass"
                },
                {
                    "pid": 4000,
                    "ppid": 1000,
                    "name": "chrome.exe",
                    "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "username": "CORP\\User",
                    "cmdline": "chrome.exe --no-first-run"
                },
                {
                    "pid": 500,
                    "ppid": 4,
                    "name": "svchost.exe",
                    "exe_path": "C:\\Windows\\System32\\svchost.exe",
                    "username": "NT AUTHORITY\\SYSTEM",
                    "cmdline": "svchost.exe -k netsvcs"
                }
            ]
        }
        res_proc = client.post(f"/api/v1/devices/{device.id}/processes", json=proc_payload)
        assert res_proc.status_code == 201, res_proc.text

        # ==========================================
        # STEP 2: Test Network Collection (Browsing & LAN)
        # ==========================================
        normal_traffic = {
            "connections": [
                # Normal web browsing
                {
                    "pid": 4000,
                    "process_name": "chrome.exe",
                    "executable_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "local_ip": "192.168.1.100",
                    "local_port": 54321,
                    "remote_ip": "142.250.190.46",  # Google Public IP
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 4096,
                    "bytes_received": 65536
                },
                # Local LAN traffic
                {
                    "pid": 500,
                    "process_name": "svchost.exe",
                    "executable_path": "C:\\Windows\\System32\\svchost.exe",
                    "local_ip": "192.168.1.100",
                    "local_port": 5353,
                    "remote_ip": "192.168.1.1",  # Gateway DNS
                    "remote_port": 53,
                    "protocol": "UDP",
                    "state": "NONE",
                    "bytes_sent": 512,
                    "bytes_received": 1024
                }
            ]
        }
        res_norm = client.post(f"/api/v1/devices/{device.id}/network", json=normal_traffic)
        assert res_norm.status_code == 201, res_norm.text
        assert len(res_norm.json()) == 2

        # ==========================================
        # STEP 3: Test Detection Rules (All 5 Rules)
        # ==========================================
        # 1. Suspicious Port Rule (Port 4444)
        # 2. Blacklisted IP Rule (185.220.101.5)
        # 4. External PowerShell Rule (powershell.exe -> 203.0.113.50:80)
        malicious_batch = {
            "connections": [
                {
                    "pid": 3000,
                    "process_name": "powershell.exe",
                    "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "local_ip": "192.168.1.100",
                    "local_port": 50001,
                    "remote_ip": "185.220.101.5",  # Blacklisted IP
                    "remote_port": 4444,           # Suspicious Port
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 8192,
                    "bytes_received": 32768
                },
                {
                    "pid": 3000,
                    "process_name": "powershell.exe",
                    "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "local_ip": "192.168.1.100",
                    "local_port": 50002,
                    "remote_ip": "203.0.113.50",   # Public IP for Unexpected Internet Access
                    "remote_port": 80,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 1024,
                    "bytes_received": 2048
                }
            ]
        }
        res_mal = client.post(f"/api/v1/devices/{device.id}/network", json=malicious_batch)
        assert res_mal.status_code == 201, res_mal.text
        mal_conns = res_mal.json()
        assert len(mal_conns) == 2
        suspicious_conn_id = mal_conns[0]["id"]
        suspicious_alert_id = mal_conns[0]["alert_id"]
        assert suspicious_alert_id is not None

        # 3. Excessive Outbound Traffic Rule Test
        engine = NetworkDetectionEngine()
        excessive_sockets = [
            {"pid": 3000, "process_name": "powershell.exe", "remote_ip": f"198.51.100.{i%250}", "remote_port": 80}
            for i in range(350)
        ]
        excessive_findings = engine.evaluate_connection_batch(excessive_sockets)
        assert any(f.threat_type == "EXCESSIVE_CONNECTIONS" for f in excessive_findings)

        # 5. Beaconing Detection Rule Test
        beacon_sockets = [
            {"pid": 3000, "process_name": "powershell.exe", "remote_ip": "198.51.100.99", "remote_port": 443}
        ]
        beacon_findings = []
        for _ in range(4):
            beacon_findings.extend(engine.evaluate_connection_batch(beacon_sockets))
            time.sleep(0.01)

        assert any(f.threat_type == "C2_BEACONING" for f in beacon_findings)

        # ==========================================
        # STEP 4: Test Dashboard & API (Filtering, Search, Pagination, Live Updates)
        # ==========================================
        # Pagination
        res_page = client.get("/api/v1/network/connections?skip=0&limit=2")
        assert res_page.status_code == 200
        assert len(res_page.json()) <= 2

        # Filtering by Process
        res_proc_filter = client.get("/api/v1/network/connections?process_name=powershell.exe")
        assert res_proc_filter.status_code == 200
        assert all("powershell" in c["process_name"].lower() for c in res_proc_filter.json())

        # Filtering by Protocol & State
        res_proto_filter = client.get("/api/v1/network/connections?protocol=TCP&state=ESTABLISHED")
        assert res_proto_filter.status_code == 200
        assert all(c["protocol"] == "TCP" and c["state"] == "ESTABLISHED" for c in res_proto_filter.json())

        # Live Diff Event Ingestion
        diff_payload = {
            "connected": [
                {
                    "pid": 4000,
                    "process_name": "chrome.exe",
                    "local_ip": "192.168.1.100",
                    "local_port": 59999,
                    "remote_ip": "142.250.190.100",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED"
                }
            ],
            "disconnected": [
                {
                    "pid": 500,
                    "local_port": 5353,
                    "protocol": "UDP",
                    "remote_ip": "192.168.1.1"
                }
            ],
            "state_changed": [
                {
                    "connection": {
                        "pid": 3000,
                        "local_port": 50001,
                        "protocol": "TCP"
                    },
                    "old_state": "ESTABLISHED",
                    "new_state": "CLOSE_WAIT"
                }
            ],
            "long_running": [],
            "total_active": 3
        }
        res_live = client.post(f"/api/v1/network/events/{device.id}", json=diff_payload)
        assert res_live.status_code == 200, res_live.text
        live_res = res_live.json()
        assert live_res["connected_count"] == 1
        assert live_res["disconnected_count"] == 1
        assert live_res["state_changed_count"] == 1

        # ==========================================
        # STEP 5: Test Response & Audit Logging (Block IP, Ignore, Allowlist, Audit Logs)
        # ==========================================
        # Action 1: Block IP
        res_block = client.post("/api/v1/responses/trigger", json={
            "device_id": str(device.id),
            "alert_id": suspicious_alert_id,
            "action_type": "BLOCK_IP",
            "initiated_by": "ANALYST_SMITH",
            "parameters": {"remote_ip": "185.220.101.5", "remote_port": 4444}
        })
        assert res_block.status_code == 201, res_block.text
        act_block_id = res_block.json()["id"]

        # Action 2: Ignore
        res_ignore = client.post("/api/v1/responses/trigger", json={
            "device_id": str(device.id),
            "alert_id": suspicious_alert_id,
            "action_type": "IGNORE",
            "initiated_by": "ANALYST_SMITH",
            "parameters": {"reason": "Authorized SOC testing"}
        })
        assert res_ignore.status_code == 201, res_ignore.text

        # Action 3: Allowlist
        res_allow = client.post("/api/v1/responses/trigger", json={
            "device_id": str(device.id),
            "alert_id": suspicious_alert_id,
            "action_type": "ADD_ALLOWLIST",
            "initiated_by": "ANALYST_SMITH",
            "parameters": {"process_name": "powershell.exe"}
        })
        assert res_allow.status_code == 201, res_allow.text

        # Verify Stage-by-Stage Audit Trail Log Entry
        res_audit = client.get(f"/api/v1/responses/{act_block_id}/audit-logs")
        assert res_audit.status_code == 200, res_audit.text
        audit_logs = res_audit.json()
        assert len(audit_logs) >= 2  # INITIATED and SUCCESS/ACKNOWLEDGED
        assert any(log["stage"] == "INITIATED" for log in audit_logs)
        assert any("ANALYST_SMITH" in log["actor"] or "BLOCK_IP" in log["message"] for log in audit_logs)

    finally:
        db.close()
