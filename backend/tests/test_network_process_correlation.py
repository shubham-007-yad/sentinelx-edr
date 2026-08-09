import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.process_info import ProcessInfo
from app.models.threat import Threat
from app.models.alert import Alert

client = TestClient(app)


def test_network_process_correlation_pivot():
    db = SessionLocal()
    try:
        # 1. Register test managed device
        device = Device(
            hostname="victim-workstation-01",
            ip_address="192.168.1.105",
            mac_address="DE:AD:BE:EF:00:01",
            os_type=OSType.WINDOWS,
            os_version="Windows 11 Enterprise",
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Ingest running process inventory snapshot (powershell.exe, PID 4000)
        proc_payload = {
            "processes": [
                {
                    "pid": 4000,
                    "ppid": 1000,
                    "name": "powershell.exe",
                    "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "username": "CORP\\Administrator",
                    "cpu_percent": 15.2,
                    "memory_percent": 4.5,
                    "start_time": "2026-07-31T18:00:00Z",
                    "cmdline": "powershell.exe -ExecutionPolicy Bypass -enc AAAA..."
                }
            ]
        }
        resp_proc = client.post(f"/api/v1/devices/{device.id}/processes", json=proc_payload)
        assert resp_proc.status_code == 201, resp_proc.text

        # 3. Ingest malicious network connection telemetry (powershell.exe connecting to 185.220.101.5:4444)
        net_payload = {
            "connections": [
                {
                    "pid": 4000,
                    "process_name": "powershell.exe",
                    "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "local_ip": "192.168.1.105",
                    "local_port": 51234,
                    "remote_ip": "185.220.101.5",
                    "remote_port": 4444,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 2048,
                    "bytes_received": 8192
                }
            ]
        }
        resp_net = client.post(f"/api/v1/devices/{device.id}/network", json=net_payload)
        assert resp_net.status_code == 201, resp_net.text
        conns_data = resp_net.json()
        assert len(conns_data) == 1

        conn_id = conns_data[0]["id"]
        assert conns_data[0]["threat_id"] is not None
        assert conns_data[0]["alert_id"] is not None
        assert conns_data[0]["process_id"] is not None

        # 4. Perform 360° Correlated Analyst Pivot Query
        resp_pivot = client.get(f"/api/v1/network/connections/{conn_id}/correlated")
        assert resp_pivot.status_code == 200, resp_pivot.text
        pivot_data = resp_pivot.json()

        # Validate Process correlation
        assert pivot_data["pid"] == 4000
        assert pivot_data["process_name"] == "powershell.exe"
        assert pivot_data["username"] == "CORP\\Administrator"
        assert "ExecutionPolicy Bypass" in pivot_data["cmdline"]

        # Validate Device correlation
        assert pivot_data["device_id"] == str(device.id)
        assert pivot_data["device_hostname"] == "victim-workstation-01"

        # Validate Threat & Alert correlation
        assert pivot_data["threat_id"] is not None
        assert pivot_data["alert_id"] is not None
        assert pivot_data["remote_ip"] == "185.220.101.5"
        assert pivot_data["remote_port"] == 4444

        # Validate Analyst Response capabilities available for pivot
        assert "TERMINATE_PROCESS" in pivot_data["available_response_actions"]
        assert "ISOLATE_DEVICE" in pivot_data["available_response_actions"]

    finally:
        db.close()
