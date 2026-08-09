import uuid
import pytest
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus


def test_create_response_action_model_relationship():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Create Device
        device = Device(
            hostname="response-test-host",
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
            volume_label="RESPONSE_TEST_DRIVE"
        )
        db.add(usb_event)
        db.commit()

        # 3. Create USB Scan Result
        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="suspicious.sh",
            full_path="/media/usb/suspicious.sh",
            extension=".sh",
            file_size=2048,
            sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            is_hidden=False
        )
        db.add(scan_result)
        db.commit()

        # 4. Create Threat
        threat = Threat(
            scan_result_id=scan_result.id,
            threat_type=ThreatType.AUTORUN_SCRIPT,
            severity=ThreatSeverity.HIGH,
            rule_name="Autorun Script Found",
            description="Autorun script detected on USB.",
            status=ThreatStatus.NEW
        )
        db.add(threat)
        db.commit()

        # 5. Create Alert
        alert = Alert(
            threat_id=threat.id,
            device_id=device.id,
            title="High Severity Threat Detected",
            message="Autorun script detected on USB.",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.UNREAD
        )
        db.add(alert)
        db.commit()

        # 6. Create ResponseAction
        action = ResponseAction(
            alert_id=alert.id,
            device_id=device.id,
            action_type=ResponseActionType.QUARANTINE,
            status=ResponseActionStatus.PENDING,
            initiated_by="AUTOMATIC",
            result="Pending execution"
        )
        db.add(action)
        db.commit()

        db.refresh(action)
        db.refresh(alert)
        db.refresh(device)

        # Assertions
        assert action.id is not None
        assert action.alert_id == alert.id
        assert action.device_id == device.id
        assert action.action_type == ResponseActionType.QUARANTINE
        assert action.status == ResponseActionStatus.PENDING
        assert action.initiated_by == "AUTOMATIC"
        assert action.started_at is not None
        assert action.result == "Pending execution"

        # Verify Relationships
        assert len(alert.response_actions) == 1
        assert alert.response_actions[0].id == action.id
        assert len(device.response_actions) == 1
        assert device.response_actions[0].id == action.id
        assert action.alert.id == alert.id
        assert action.device.id == device.id

        # Verify repr
        assert f"<ResponseAction id={action.id}" in repr(action)

    finally:
        db.close()
