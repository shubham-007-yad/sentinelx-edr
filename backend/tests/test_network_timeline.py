import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.threat import Threat, ThreatType, ThreatSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus

client = TestClient(app)


def test_connection_investigation_timeline():
    db = SessionLocal()
    try:
        # 1. Device setup
        device = Device(
            hostname="compromised-host-01",
            ip_address="192.168.1.150",
            mac_address="DE:AD:BE:EF:00:03",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Ingest Process powershell.exe
        proc_payload = {
            "processes": [
                {
                    "pid": 5120,
                    "ppid": 1024,
                    "name": "powershell.exe",
                    "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "username": "CORP\\User",
                    "cmdline": "powershell.exe -enc BeaconPayload"
                }
            ]
        }
        res_proc = client.post(f"/api/v1/devices/{device.id}/processes", json=proc_payload)
        assert res_proc.status_code == 201

        # 3. Ingest malicious connection to 198.51.100.25 with 12 MB transfer
        net_payload = {
            "connections": [
                {
                    "pid": 5120,
                    "process_name": "powershell.exe",
                    "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "local_ip": "192.168.1.150",
                    "local_port": 49152,
                    "remote_ip": "198.51.100.25",
                    "remote_port": 4444,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 12582912,  # 12 MB
                    "bytes_received": 524288
                }
            ]
        }
        res_net = client.post(f"/api/v1/devices/{device.id}/network", json=net_payload)
        assert res_net.status_code == 201
        conn_id = res_net.json()[0]["id"]
        alert_id = res_net.json()[0]["alert_id"]

        # 4. Trigger response action (Blocked by analyst)
        res_block = client.post("/api/v1/responses/trigger", json={
            "device_id": str(device.id),
            "alert_id": alert_id,
            "action_type": "BLOCK_IP",
            "initiated_by": "ANALYST",
            "parameters": {"remote_ip": "198.51.100.25"}
        })
        assert res_block.status_code == 201

        # 5. Fetch Connection Timeline
        res_timeline = client.get(f"/api/v1/network/connections/{conn_id}/timeline")
        assert res_timeline.status_code == 200, res_timeline.text
        t_data = res_timeline.json()
        assert t_data["connection_id"] == conn_id

        items = t_data["timeline"]
        assert len(items) >= 5

        # Verify step 1: Process started
        assert "powershell.exe started" in items[0]["title"]
        assert items[0]["event_type"] == "PROCESS_STARTED"

        # Verify step 2: Connected to 198.51.100.25
        assert "Connected to 198.51.100.25" in items[1]["title"]
        assert items[1]["event_type"] == "NETWORK_CONNECTED"

        # Verify step 3: Transferred MB
        assert "Transferred" in items[2]["title"]
        assert items[2]["event_type"] == "DATA_TRANSFERRED"

        # Verify step 4 & 5: Threat finding / Alert generated
        assert any("Alert generated" in item["title"] for item in items)

        # Verify step 6: Blocked by analyst
        assert any("Blocked by analyst" in item["title"] for item in items)

    finally:
        db.close()
