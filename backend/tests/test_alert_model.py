import uuid
import pytest
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus


def test_create_alert_model_relationship():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Create Device
        device = Device(
            hostname="alert-test-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()

        # 2. Create USB Event
        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="/dev/sdb1",
            volume_label="ALERT_TEST_DRIVE"
        )
        db.add(usb_event)
        db.commit()

        # 3. Create USB Scan Result
        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="malicious_payload.exe",
            full_path="/media/usb/malicious_payload.exe",
            extension=".exe",
            file_size=10240,
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            is_hidden=False
        )
        db.add(scan_result)
        db.commit()

        # 4. Create Threat
        threat = Threat(
            scan_result_id=scan_result.id,
            threat_type=ThreatType.KNOWN_MALWARE,
            severity=ThreatSeverity.CRITICAL,
            rule_name="Malware Signature Matched",
            description="Known malware signature found in file payload.",
            status=ThreatStatus.NEW
        )
        db.add(threat)
        db.commit()

        # 5. Create Alert
        alert = Alert(
            threat_id=threat.id,
            device_id=device.id,
            title="Critical Malware Detected",
            message="Known malware signature found on device alert-test-host.",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.UNREAD
        )
        db.add(alert)
        db.commit()

        db.refresh(alert)
        db.refresh(threat)
        db.refresh(device)

        # Assertions
        assert alert.id is not None
        assert alert.threat_id == threat.id
        assert alert.device_id == device.id
        assert alert.title == "Critical Malware Detected"
        assert alert.message == "Known malware signature found on device alert-test-host."
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.status == AlertStatus.UNREAD
        assert alert.created_at is not None
        assert alert.read_at is None
        assert alert.acknowledged_at is None

        # Verify Relationships
        assert len(threat.alerts) == 1
        assert threat.alerts[0].id == alert.id
        assert len(device.alerts) == 1
        assert device.alerts[0].id == alert.id
        assert alert.threat.id == threat.id
        assert alert.device.id == device.id

        # Verify repr
        assert f"<Alert id={alert.id}" in repr(alert)

    finally:
        db.close()
