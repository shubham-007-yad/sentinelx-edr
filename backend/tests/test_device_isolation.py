import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType

client = TestClient(app)


def setup_db():
    Base.metadata.create_all(bind=engine)
    return SessionLocal()


def test_device_isolation_flow():
    db = setup_db()
    try:
        # 1. Register Device via API
        hostname = f"node-iso-{str(uuid.uuid4())[:8]}"
        mac = f"00:50:56:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
        reg_res = client.post("/api/v1/devices/register", json={
            "hostname": hostname,
            "mac_address": mac,
            "os_type": "LINUX",
            "os_version": "Ubuntu 22.04"
        })
        assert reg_res.status_code == 201
        device_data = reg_res.json()
        device_id_str = device_data["id"]

        # 2. Isolate Device via API
        response = client.post(f"/api/v1/devices/{device_id_str}/isolate")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ISOLATED"

        # 3. Verify Heartbeat preserves ISOLATED state
        hb_res = client.post("/api/v1/devices/heartbeat", json={
            "device_id": device_id_str,
            "status": "ONLINE"
        })
        assert hb_res.status_code == 200
        assert hb_res.json()["status"] == "ISOLATED"

        # 4. Attempt USB Event upload -> Should be BLOCKED (403 Forbidden)
        usb_event_payload = {
            "device_id": device_id_str,
            "event_type": "INSERT",
            "drive_letter": "/dev/sdb1",
            "volume_label": "MALICIOUS_DRIVE"
        }
        event_res = client.post("/api/v1/usb/events", json=usb_event_payload)
        assert event_res.status_code == 403
        assert "ISOLATED" in event_res.json()["detail"]

        # 5. Create dummy USB event directly in DB to test scan blocking
        device_uuid = uuid.UUID(device_id_str)
        event_db = USBEvent(
            device_id=device_uuid,
            event_type=USBEventType.INSERT,
            drive_letter="/dev/sdb1",
            volume_label="TEST"
        )
        db.add(event_db)
        db.commit()

        # 6. Attempt USB Scan Upload -> Should be BLOCKED (403 Forbidden)
        scan_payload = [{
            "usb_event_id": str(event_db.id),
            "file_name": "payload.exe",
            "full_path": "/media/usb/payload.exe",
            "extension": ".exe",
            "file_size": 4096,
            "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "is_hidden": False
        }]
        scan_res = client.post("/api/v1/usb/scans", json=scan_payload)
        assert scan_res.status_code == 403
        assert "Scan jobs are blocked" in scan_res.json()["detail"]

        # 7. Un-isolate Device via API
        unisolate_res = client.post(f"/api/v1/devices/{device_id_str}/unisolate")
        assert unisolate_res.status_code == 200
        assert unisolate_res.json()["status"] == "ONLINE"

        # 8. Retry USB Event upload after un-isolation -> Should SUCCEED (201 Created)
        retry_event_res = client.post("/api/v1/usb/events", json=usb_event_payload)
        assert retry_event_res.status_code == 201

    finally:
        db.close()
