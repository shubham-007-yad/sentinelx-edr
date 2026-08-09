import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, HealthStatus, CommandStatus, OSType
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.services import fleet_service, device_service
from app.schemas.device import DeviceCreate

client = TestClient(app)


def test_fleet_inventory_model_properties():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        device = Device(
            hostname="test-fleet-host-1",
            ip_address="192.168.1.50",
            mac_address="AA:BB:CC:DD:EE:11",
            os_type=OSType.WINDOWS,
            os_version="11 Enterprise",
            agent_version="1.0.0",
            applied_policy_version=3,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            last_command_status=CommandStatus.EXECUTED,
            last_checkin=datetime.now(timezone.utc),
            last_heartbeat=datetime.now(timezone.utc)
        )
        db_session.add(device)
        db_session.commit()
        db_session.refresh(device)

        assert device.hostname == "test-fleet-host-1"
        assert device.policy_version == 3
        assert device.operating_system == "WINDOWS (11 Enterprise)"
        assert device.health_status == HealthStatus.HEALTHY
        assert device.last_command_status == CommandStatus.EXECUTED
    finally:
        db_session.close()


def test_fleet_metrics_calculation():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev1 = Device(
            hostname="dev-online-healthy",
            os_type=OSType.LINUX,
            agent_version="1.0.0",
            applied_policy_version=1,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY
        )
        dev2 = Device(
            hostname="dev-offline-outdated",
            os_type=OSType.WINDOWS,
            agent_version="0.9.0", # outdated
            applied_policy_version=1,
            status=DeviceStatus.OFFLINE,
            health_status=HealthStatus.HEALTHY
        )
        dev3 = Device(
            hostname="dev-unhealthy",
            os_type=OSType.LINUX,
            agent_version="1.0.0",
            applied_policy_version=1,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.UNHEALTHY
        )
        db_session.add_all([dev1, dev2, dev3])
        db_session.commit()

        metrics = fleet_service.get_fleet_metrics(db_session)
        assert metrics.total_agents >= 3
        assert metrics.online >= 2
        assert metrics.offline >= 1
        assert metrics.outdated >= 1
        assert metrics.unhealthy >= 1
    finally:
        db_session.close()


def test_fleet_api_endpoints():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="fleet-api-node",
            ip_address="10.0.0.15",
            mac_address="00:11:22:33:44:55",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04",
            agent_version="1.0.0",
            policy_version=1,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            last_command_status=CommandStatus.NONE
        )
        created_dev = device_service.register_device(db_session, dev_in)

        # Test GET /api/v1/fleet/metrics
        response = client.get("/api/v1/fleet/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "total_agents" in data
        assert "online" in data
        assert "offline" in data

        # Test GET /api/v1/fleet/devices with OS, Version, Status, Policy, Search filters
        response = client.get(f"/api/v1/fleet/devices?search=fleet-api-node&os_type=LINUX&version=1.0.0&status=ONLINE&policy=1")
        assert response.status_code == 200
        devices = response.json()
        assert len(devices) >= 1
        assert devices[0]["hostname"] == "fleet-api-node"
        assert devices[0]["operating_system"] == "LINUX (Ubuntu 22.04)"
        assert devices[0]["health_status"] == "HEALTHY"

        # Test GET /api/v1/fleet/summary
        response = client.get("/api/v1/fleet/summary")
        assert response.status_code == 200
        summary = response.json()
        assert "metrics" in summary
        assert "recent_devices" in summary

        # Test GET /api/v1/fleet/export CSV endpoint
        export_resp = client.get("/api/v1/fleet/export")
        assert export_resp.status_code == 200
        assert "text/csv" in export_resp.headers["content-type"]
        assert "Hostname" in export_resp.text
        assert "fleet-api-node" in export_resp.text
    finally:
        db_session.close()


def test_bulk_operations_and_export():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev1 = Device(hostname="bulk-node-1", os_type=OSType.LINUX, status=DeviceStatus.ONLINE)
        dev2 = Device(hostname="bulk-node-2", os_type=OSType.WINDOWS, status=DeviceStatus.ONLINE)
        db_session.add_all([dev1, dev2])
        db_session.commit()

        # Obtain auth token for admin
        auth_resp = client.post("/api/v1/auth/login/json", json={
            "username_or_email": "admin",
            "password": "AdminPassword123!"
        })
        token = auth_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Batch command dispatch
        batch_payload = {
            "device_ids": [str(dev1.id), str(dev2.id)],
            "command_type": "REFRESH_POLICY",
            "payload": {"policy_version": 3, "policy_label": "v3.2"}
        }
        res = client.post("/api/v1/fleet/commands/batch", json=batch_payload, headers=headers)
        assert res.status_code == 201
        cmds = res.json()
        assert len(cmds) == 2
        assert cmds[0]["command_type"] == "REFRESH_POLICY"

        # Export filtered devices
        export_res = client.get(f"/api/v1/fleet/export?device_ids={dev1.id},{dev2.id}")
        assert export_res.status_code == 200
        assert "bulk-node-1" in export_res.text
        assert "bulk-node-2" in export_res.text
    finally:
        db_session.close()


def test_agent_diagnostic_package():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev = Device(
            hostname="diag-node-1",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04 LTS",
            agent_version="1.0.0",
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            service_status="RUNNING"
        )
        db_session.add(dev)
        db_session.commit()
        db_session.refresh(dev)

        # 1. Test GET /api/v1/fleet/devices/{device_id}/diagnostics
        resp = client.get(f"/api/v1/fleet/devices/{dev.id}/diagnostics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hostname"] == "diag-node-1"
        assert "configuration" in data
        assert "installed_collectors" in data
        assert len(data["installed_collectors"]) >= 5
        assert "agent_logs" in data
        assert len(data["agent_logs"]) >= 4

        # 2. Test GET /api/v1/fleet/devices/{device_id}/diagnostics/download
        dl_resp = client.get(f"/api/v1/fleet/devices/{dev.id}/diagnostics/download")
        assert dl_resp.status_code == 200
        assert "application/json" in dl_resp.headers["content-type"]
        assert "diag-node-1" in dl_resp.text
    finally:
        db_session.close()


