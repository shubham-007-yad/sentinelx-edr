import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.process_info import ProcessInfo

client = TestClient(app)


def test_live_process_events_flow():
    db = SessionLocal()
    try:
        # 1. Create test device
        device = Device(
            hostname="live-proc-host",
            ip_address="192.168.1.180",
            mac_address="AA:BB:CC:DD:EE:88",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04",
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Ingest initial process via events API
        payload1 = {
            "created": [
                {
                    "pid": 5001,
                    "ppid": 1,
                    "name": "bash",
                    "exe_path": "/bin/bash",
                    "username": "root",
                    "cpu_percent": 1.0,
                    "memory_percent": 0.5,
                    "start_time": "2026-07-30T10:00:00Z",
                    "cmdline": "/bin/bash"
                }
            ],
            "terminated": [],
            "long_running": [],
            "total_active": 1
        }

        resp1 = client.post(f"/api/v1/devices/{device.id}/processes/events", json=payload1)
        assert resp1.status_code == 200, resp1.text
        data1 = resp1.json()
        assert data1["created_count"] == 1
        assert data1["terminated_count"] == 0

        # Check DB
        procs = db.query(ProcessInfo).filter(ProcessInfo.device_id == device.id).all()
        assert len(procs) == 1
        assert procs[0].pid == 5001

        # 3. Post second event with 1 new process and 1 terminated process
        payload2 = {
            "created": [
                {
                    "pid": 5002,
                    "ppid": 5001,
                    "name": "nc",
                    "exe_path": "/usr/bin/nc",
                    "username": "root",
                    "cpu_percent": 5.0,
                    "memory_percent": 0.2,
                    "start_time": "2026-07-30T10:01:00Z",
                    "cmdline": "nc -lvp 4444"
                }
            ],
            "terminated": [
                {
                    "pid": 5001,
                    "ppid": 1,
                    "name": "bash",
                    "exe_path": "/bin/bash",
                    "username": "root"
                }
            ],
            "long_running": [
                {
                    "pid": 5002,
                    "ppid": 5001,
                    "name": "nc"
                }
            ],
            "total_active": 1
        }

        resp2 = client.post(f"/api/v1/devices/{device.id}/processes/events", json=payload2)
        assert resp2.status_code == 200, resp2.text
        data2 = resp2.json()
        assert data2["created_count"] == 1
        assert data2["terminated_count"] == 1
        assert data2["long_running_count"] == 1

        # Verify DB reflects process termination and new creation
        procs2 = db.query(ProcessInfo).filter(ProcessInfo.device_id == device.id).all()
        assert len(procs2) == 1
        assert procs2[0].pid == 5002
        assert procs2[0].name == "nc"

    finally:
        db.close()
