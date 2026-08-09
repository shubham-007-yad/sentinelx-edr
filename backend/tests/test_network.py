import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.network_connection import NetworkConnection

client = TestClient(app)


def test_network_connection_inventory_flow():
    db = SessionLocal()
    try:
        # 1. Create test device
        device = Device(
            hostname="test-net-host",
            ip_address="192.168.1.180",
            mac_address="11:22:33:44:55:66",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04",
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Ingest network connection snapshot payload
        payload = {
            "connections": [
                {
                    "pid": 1234,
                    "process_name": "nginx",
                    "executable_path": "/usr/sbin/nginx",
                    "local_ip": "0.0.0.0",
                    "local_port": 80,
                    "remote_ip": None,
                    "remote_port": None,
                    "protocol": "TCP",
                    "state": "LISTEN",
                    "bytes_sent": 1024,
                    "bytes_received": 2048
                },
                {
                    "pid": 5678,
                    "process_name": "curl",
                    "executable_path": "/usr/bin/curl",
                    "local_ip": "192.168.1.180",
                    "local_port": 54321,
                    "remote_ip": "93.184.216.34",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 512,
                    "bytes_received": 4096
                }
            ]
        }

        response = client.post(f"/api/v1/devices/{device.id}/network", json=payload)
        assert response.status_code == 201, response.text
        data = response.json()
        assert len(data) == 2
        states = [c["state"] for c in data]
        assert "LISTEN" in states
        assert "ESTABLISHED" in states

        # 3. Query network connections by device ID
        resp_get_device = client.get(f"/api/v1/devices/{device.id}/network")
        assert resp_get_device.status_code == 200
        conns_device = resp_get_device.json()
        assert len(conns_device) == 2

        # 4. Query network connections globally with filters
        resp_filter_state = client.get("/api/v1/network/connections?state=LISTEN")
        assert resp_filter_state.status_code == 200
        listen_conns = resp_filter_state.json()
        assert any(c["process_name"] == "nginx" for c in listen_conns)

        resp_filter_ip = client.get("/api/v1/network/connections?remote_ip=93.184.216.34")
        assert resp_filter_ip.status_code == 200
        remote_ip_conns = resp_filter_ip.json()
        assert any(c["process_name"] == "curl" for c in remote_ip_conns)

    finally:
        db.close()


def test_live_network_events_flow():
    db = SessionLocal()
    try:
        device = Device(
            hostname="test-live-net-host",
            ip_address="192.168.1.185",
            mac_address="11:22:33:44:55:77",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04",
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        events_payload = {
            "connected": [
                {
                    "pid": 8888,
                    "process_name": "nc",
                    "executable_path": "/usr/bin/nc",
                    "local_ip": "192.168.1.185",
                    "local_port": 44444,
                    "remote_ip": "10.0.0.5",
                    "remote_port": 4444,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "bytes_sent": 100,
                    "bytes_received": 200
                }
            ],
            "disconnected": [],
            "state_changed": [],
            "long_running": [],
            "total_active": 1,
            "timestamp": "2026-07-31T12:00:00Z"
        }

        resp = client.post(f"/api/v1/devices/{device.id}/network/events", json=events_payload)
        assert resp.status_code == 200, resp.text
        res_data = resp.json()
        assert res_data["connected_count"] == 1
        assert res_data["disconnected_count"] == 0

        # Query connections to ensure inserted
        get_resp = client.get(f"/api/v1/devices/{device.id}/network")
        assert get_resp.status_code == 200
        conns = get_resp.json()
        assert len(conns) == 1
        assert conns[0]["process_name"] == "nc"

        # Now send disconnect event
        disc_payload = {
            "connected": [],
            "disconnected": [
                {
                    "pid": 8888,
                    "local_port": 44444,
                    "remote_ip": "10.0.0.5",
                    "protocol": "TCP"
                }
            ],
            "state_changed": [],
            "long_running": [],
            "total_active": 0,
            "timestamp": "2026-07-31T12:01:00Z"
        }

        disc_resp = client.post(f"/api/v1/devices/{device.id}/network/events", json=disc_payload)
        assert disc_resp.status_code == 200
        disc_data = disc_resp.json()
        assert disc_data["disconnected_count"] == 1

        # Query connections to ensure removed
        get_resp2 = client.get(f"/api/v1/devices/{device.id}/network")
        assert len(get_resp2.json()) == 0

    finally:
        db.close()
