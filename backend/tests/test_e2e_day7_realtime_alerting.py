import uuid
import asyncio
import pytest
from fastapi.testclient import TestClient
from app.main import app
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
    mark_alert_as_read,
    mark_alert_as_acknowledged,
    bulk_mark_as_read,
    bulk_acknowledge,
)
from app.core.websocket_manager import ConnectionManager

client = TestClient(app)


def test_phase8_single_alert_generation():
    """Verify single alert generation from a detected threat."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = Device(hostname="DESKTOP-01", os_type=OSType.WINDOWS, status=DeviceStatus.ONLINE)
        db.add(device)
        db.commit()

        usb_event = USBEvent(device_id=device.id, event_type=USBEventType.INSERT, drive_letter="E:", volume_label="WORK_USB")
        db.add(usb_event)
        db.commit()

        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="invoice.pdf.exe",
            full_path="E:\\invoice.pdf.exe",
            extension=".exe",
            file_size=204800,
            sha256="aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900",
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

        alert = create_alert_from_threat(db, threat)
        assert alert is not None
        assert alert.threat_id == threat.id
        assert alert.device_id == device.id
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.title == "Critical Threat Detected"
        assert alert.message == "Double extension file detected: invoice.pdf.exe"
        assert alert.status == AlertStatus.UNREAD
    finally:
        db.close()


def test_phase8_multiple_simultaneous_threats():
    """Verify alert generation for multiple simultaneous threats from a single scan."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = Device(hostname="DESKTOP-MULTI", os_type=OSType.LINUX, status=DeviceStatus.ONLINE)
        db.add(device)
        db.commit()

        usb_event = USBEvent(device_id=device.id, event_type=USBEventType.INSERT, drive_letter="/dev/sdd1", volume_label="MULTI_THREAT_USB")
        db.add(usb_event)
        db.commit()

        # Scan 1: autorun.inf
        scan1 = USBScanResult(usb_event_id=usb_event.id, file_name="autorun.inf", full_path="/media/usb/autorun.inf", extension=".inf", file_size=512, sha256="1111111111111111111111111111111111111111111111111111111111111111", is_hidden=True)
        # Scan 2: installer.exe
        scan2 = USBScanResult(usb_event_id=usb_event.id, file_name="installer.exe", full_path="/media/usb/installer.exe", extension=".exe", file_size=1048576, sha256="2222222222222222222222222222222222222222222222222222222222222222", is_hidden=False)
        db.add_all([scan1, scan2])
        db.commit()

        threat1 = Threat(scan_result_id=scan1.id, threat_type=ThreatType.AUTORUN_SCRIPT, severity=ThreatSeverity.CRITICAL, rule_name="AutoRun Script Detected", description="AutoRun script file detected", status=ThreatStatus.NEW)
        threat2 = Threat(scan_result_id=scan2.id, threat_type=ThreatType.KNOWN_MALWARE, severity=ThreatSeverity.HIGH, rule_name="High Severity Threat", description="Known malware signature detected", status=ThreatStatus.NEW)
        db.add_all([threat1, threat2])
        db.commit()

        alerts = create_alerts_for_threats(db, [threat1, threat2])
        assert len(alerts) == 2
        alert_ids = {a.id for a in alerts}
        assert len(alert_ids) == 2
    finally:
        db.close()


def test_phase8_duplicate_prevention():
    """Verify that duplicate alerts are not created for the same threat."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = Device(hostname="DESKTOP-DUP", os_type=OSType.WINDOWS, status=DeviceStatus.ONLINE)
        db.add(device)
        db.commit()

        usb_event = USBEvent(device_id=device.id, event_type=USBEventType.INSERT, drive_letter="F:", volume_label="TEST_DRIVE")
        db.add(usb_event)
        db.commit()

        scan_result = USBScanResult(usb_event_id=usb_event.id, file_name="payload.exe", full_path="F:\\payload.exe", extension=".exe", file_size=5000, sha256="3333333333333333333333333333333333333333333333333333333333333333", is_hidden=False)
        db.add(scan_result)
        db.commit()

        threat = Threat(scan_result_id=scan_result.id, threat_type=ThreatType.KNOWN_MALWARE, severity=ThreatSeverity.CRITICAL, rule_name="Malware Signature", description="Malware payload", status=ThreatStatus.NEW)
        db.add(threat)
        db.commit()

        # Call create_alert_from_threat twice
        alert1 = create_alert_from_threat(db, threat)
        alert2 = create_alert_from_threat(db, threat)

        assert alert1.id == alert2.id
        total_alerts_for_threat = db.query(Alert).filter(Alert.threat_id == threat.id).count()
        assert total_alerts_for_threat == 1
    finally:
        db.close()


def test_phase8_multiple_clients_and_websocket_reconnect():
    """Verify that multiple simultaneous dashboard clients receive the same broadcast alert and reconnects work."""
    async def _run():
        manager = ConnectionManager()

        class MockWS:
            def __init__(self, client_id):
                self.client_id = client_id
                self.received = []

            async def accept(self):
                pass

            async def send_json(self, data):
                self.received.append(data)

            async def send_text(self, data):
                self.received.append(data)

        client1 = MockWS("analyst_1")
        client2 = MockWS("analyst_2")

        # 1. Connect multiple simultaneous clients
        await manager.connect(client1)
        await manager.connect(client2)
        assert len(manager.active_connections) == 2

        # 2. Broadcast alert
        alert_payload = {
            "title": "Critical Threat Detected",
            "severity": "CRITICAL",
            "device": "DESKTOP-01",
            "file": "invoice.pdf.exe",
            "time": "2026-07-28T13:42:18Z"
        }
        await manager.broadcast_alert(alert_payload)

        # Both clients receive the exact same alert
        assert len(client1.received) == 1
        assert client1.received[0]["data"] == alert_payload
        assert len(client2.received) == 1
        assert client2.received[0]["data"] == alert_payload

        # 3. Simulate client 1 disconnect & reconnect
        manager.disconnect(client1)
        assert len(manager.active_connections) == 1

        client1_reconnected = MockWS("analyst_1_reconnected")
        await manager.connect(client1_reconnected)
        assert len(manager.active_connections) == 2

        # Broadcast second alert
        alert2_payload = {
            "title": "High Severity Threat",
            "severity": "HIGH",
            "device": "DESKTOP-01",
            "file": "installer.exe",
            "time": "2026-07-28T13:45:00Z"
        }
        await manager.broadcast_alert(alert2_payload)

        assert len(client1_reconnected.received) == 1
        assert client1_reconnected.received[0]["data"] == alert2_payload
        assert len(client2.received) == 2
        assert client2.received[1]["data"] == alert2_payload

    asyncio.run(_run())


def test_phase8_alert_status_updates():
    """Verify single and bulk alert status updates (UNREAD -> READ -> ACKNOWLEDGED)."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = Device(hostname="DESKTOP-STATUS", os_type=OSType.LINUX, status=DeviceStatus.ONLINE)
        db.add(device)
        db.commit()

        usb_event = USBEvent(device_id=device.id, event_type=USBEventType.INSERT, drive_letter="/dev/sde1", volume_label="STATUS_TEST")
        db.add(usb_event)
        db.commit()

        scan = USBScanResult(usb_event_id=usb_event.id, file_name="script.vbs", full_path="/media/script.vbs", extension=".vbs", file_size=1000, sha256="4444444444444444444444444444444444444444444444444444444444444444", is_hidden=False)
        db.add(scan)
        db.commit()

        threat = Threat(scan_result_id=scan.id, threat_type=ThreatType.SUSPICIOUS_EXTENSION, severity=ThreatSeverity.MEDIUM, rule_name="Suspicious Script", description="VBS script detected", status=ThreatStatus.NEW)
        db.add(threat)
        db.commit()

        alert = create_alert_from_threat(db, threat)
        assert alert.status == AlertStatus.UNREAD

        # Single Mark as Read
        updated_read = mark_alert_as_read(db, alert.id)
        assert updated_read.status == AlertStatus.READ
        assert updated_read.read_at is not None

        # Single Mark as Acknowledged
        updated_ack = mark_alert_as_acknowledged(db, alert.id)
        assert updated_ack.status == AlertStatus.ACKNOWLEDGED
        assert updated_ack.acknowledged_at is not None

        # Bulk Actions
        count_read = bulk_mark_as_read(db, [alert.id])
        assert count_read == 1
        assert alert.status == AlertStatus.READ

        count_ack = bulk_acknowledge(db, [alert.id])
        assert count_ack == 1
        assert alert.status == AlertStatus.ACKNOWLEDGED
    finally:
        db.close()
