import uuid
import pytest
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.services.alert_service import (
    create_alert_from_threat,
    create_alerts_for_threats,
    get_alerts,
    get_alert_by_id,
    mark_alert_as_read,
    mark_alert_as_acknowledged,
)


def test_alert_generation_service_lifecycle():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Setup Device, USBEvent, USBScanResult, Threat
        device = Device(
            hostname="phase2-host",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()

        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="E:",
            volume_label="SECURE_USB"
        )
        db.add(usb_event)
        db.commit()

        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="invoice.pdf.exe",
            full_path="E:\\invoice.pdf.exe",
            extension=".exe",
            file_size=512000,
            sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            is_hidden=False
        )
        db.add(scan_result)
        db.commit()

        threat = Threat(
            scan_result_id=scan_result.id,
            threat_type=ThreatType.DOUBLE_EXTENSION,
            severity=ThreatSeverity.CRITICAL,
            rule_name="Double Extension Executable",
            description="Double extension file detected",
            status=ThreatStatus.NEW
        )
        db.add(threat)
        db.commit()

        # 1. Test create_alert_from_threat
        alert = create_alert_from_threat(db, threat)

        assert alert is not None
        assert alert.id is not None
        assert alert.threat_id == threat.id
        assert alert.device_id == device.id
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.title == "Critical Threat Detected"
        assert alert.message == "Double extension file detected: invoice.pdf.exe"
        assert alert.status == AlertStatus.UNREAD

        # 2. Test duplicate prevention
        duplicate_alert = create_alert_from_threat(db, threat)
        assert duplicate_alert.id == alert.id
        
        all_alerts_for_threat = db.query(Alert).filter(Alert.threat_id == threat.id).all()
        assert len(all_alerts_for_threat) == 1

        # 3. Test mark_alert_as_read
        updated_read = mark_alert_as_read(db, alert.id)
        assert updated_read.status == AlertStatus.READ
        assert updated_read.read_at is not None

        # 4. Test mark_alert_as_acknowledged
        updated_ack = mark_alert_as_acknowledged(db, alert.id)
        assert updated_ack.status == AlertStatus.ACKNOWLEDGED
        assert updated_ack.acknowledged_at is not None

        # 5. Test get_alerts filtering
        alerts_list = get_alerts(db, status=AlertStatus.ACKNOWLEDGED)
        assert len(alerts_list) >= 1
        assert alerts_list[0].id == alert.id

    finally:
        db.close()
