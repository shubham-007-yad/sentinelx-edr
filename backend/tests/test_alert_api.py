import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus

client = TestClient(app)


def get_admin_headers():
    db = SessionLocal()
    init_db(db)
    db.close()
    res = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": "admin", "password": "AdminPassword123!"}
    )
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_alerts_api_endpoints():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Create Device, Event, Scan, Threat, Alert
        device = Device(
            hostname="api-alert-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()

        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="/dev/sdc1",
            volume_label="API_DRIVE"
        )
        db.add(usb_event)
        db.commit()

        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="autorun.inf",
            full_path="/media/usb/autorun.inf",
            extension=".inf",
            file_size=1024,
            sha256="99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff",
            is_hidden=True
        )
        db.add(scan_result)
        db.commit()

        threat = Threat(
            scan_result_id=scan_result.id,
            threat_type=ThreatType.AUTORUN_SCRIPT,
            severity=ThreatSeverity.CRITICAL,
            rule_name="Critical AutoRun Threat",
            description="AutoRun script file detected",
            status=ThreatStatus.NEW
        )
        db.add(threat)
        db.commit()

        alert = Alert(
            threat_id=threat.id,
            device_id=device.id,
            title="Critical AutoRun Threat",
            message="AutoRun script file detected: autorun.inf",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.UNREAD
        )
        db.add(alert)
        db.commit()
        alert_id = str(alert.id)

    finally:
        db.close()

    headers = get_admin_headers()

    # 1. Get Unread Count
    res_count = client.get("/api/v1/alerts/unread-count", headers=headers)
    assert res_count.status_code == 200
    assert res_count.json()["unread_count"] >= 1

    # 2. List Alerts
    res_list = client.get("/api/v1/alerts", headers=headers)
    assert res_list.status_code == 200
    alerts_data = res_list.json()
    assert any(a["id"] == alert_id for a in alerts_data)

    # 3. Mark single alert as read
    res_read = client.patch(f"/api/v1/alerts/{alert_id}/read", headers=headers)
    assert res_read.status_code == 200
    assert res_read.json()["status"] == "READ"

    # 4. Mark all as read
    res_all = client.patch("/api/v1/alerts/mark-all-read", headers=headers)
    assert res_all.status_code == 200
    assert res_all.json()["unread_count"] == 0
