import uuid
import pytest
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus


def test_create_threat_model_relationship():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Device
        device = Device(
            hostname="phase1-test-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()

        # 2. USB Event
        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="/dev/sdb1",
            volume_label="PHASE1_DRIVE"
        )
        db.add(usb_event)
        db.commit()

        # 3. USB Scan Result
        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="suspicious_script.vbs",
            full_path="/media/usb/suspicious_script.vbs",
            extension=".vbs",
            file_size=2048,
            sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            is_hidden=True
        )
        db.add(scan_result)
        db.commit()

        # 4. Threat
        threat = Threat(
            scan_result_id=scan_result.id,
            threat_type=ThreatType.SUSPICIOUS_EXTENSION,
            severity=ThreatSeverity.HIGH,
            rule_name="Suspicious VBS Script Executable",
            description="VBScript executable detected on removable media.",
            status=ThreatStatus.NEW
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)
        db.refresh(scan_result)

        # Verify fields and relationships
        assert threat.id is not None
        assert threat.scan_result_id == scan_result.id
        assert threat.threat_type == ThreatType.SUSPICIOUS_EXTENSION
        assert threat.severity == ThreatSeverity.HIGH
        assert threat.rule_name == "Suspicious VBS Script Executable"
        assert threat.status == ThreatStatus.NEW
        assert threat.detected_at is not None
        assert len(scan_result.threats) == 1
        assert scan_result.threats[0].id == threat.id

    finally:
        db.close()
