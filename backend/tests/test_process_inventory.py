import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.process_info import ProcessInfo

client = TestClient(app)


def test_process_inventory_flow():
    db = SessionLocal()
    try:
        # 1. Create test device
        device = Device(
            hostname="test-proc-host",
            ip_address="192.168.1.150",
            mac_address="AA:BB:CC:DD:EE:99",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04",
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Post process inventory batch
        payload = {
            "processes": [
                {
                    "pid": 1001,
                    "ppid": 1,
                    "name": "systemd",
                    "exe_path": "/sbin/init",
                    "username": "root",
                    "cpu_percent": 0.5,
                    "memory_percent": 1.2,
                    "start_time": "2026-07-30T10:00:00Z",
                    "cmdline": "/sbin/init splash"
                },
                {
                    "pid": 2048,
                    "ppid": 1001,
                    "name": "python3",
                    "exe_path": "/usr/bin/python3",
                    "username": "user",
                    "cpu_percent": 12.4,
                    "memory_percent": 3.8,
                    "start_time": "2026-07-30T10:05:00Z",
                    "cmdline": "python3 main.py --verbose"
                }
            ]
        }

        response = client.post(f"/api/v1/devices/{device.id}/processes", json=payload)
        assert response.status_code == 201, response.text
        data = response.json()
        assert len(data) == 2
        names = [p["name"] for p in data]
        assert "systemd" in names
        assert "python3" in names

        # 3. Query processes by device ID
        resp_get = client.get(f"/api/v1/devices/{device.id}/processes")
        assert resp_get.status_code == 200
        procs = resp_get.json()
        assert len(procs) == 2

        # 4. Query processes with name filter
        resp_filter = client.get(f"/api/v1/processes?name=python3")
        assert resp_filter.status_code == 200
        filter_data = resp_filter.json()
        assert len(filter_data) >= 1
        assert any(p["name"] == "python3" for p in filter_data)
    finally:
        db.close()
