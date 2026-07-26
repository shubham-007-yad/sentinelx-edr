import uuid
import pytest
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult


def test_usb_scan_result_model_creation():
    db = SessionLocal()
    try:
        device = Device(
            hostname="test-scan-host",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="E:",
            volume_label="SECURE_FLASH"
        )
        db.add(usb_event)
        db.commit()
        db.refresh(usb_event)

        scan_result = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="malware_sample.exe",
            full_path="E:\\malware_sample.exe",
            extension=".exe",
            file_size=1048576,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_hidden=False
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)

        assert scan_result.id is not None
        assert scan_result.usb_event_id == usb_event.id
        assert scan_result.file_name == "malware_sample.exe"
        assert scan_result.full_path == "E:\\malware_sample.exe"
        assert scan_result.extension == ".exe"
        assert scan_result.file_size == 1048576
        assert scan_result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert scan_result.is_hidden is False
        assert scan_result.scanned_at is not None

        # Verify relationship from usb_event
        db.refresh(usb_event)
        assert len(usb_event.scan_results) == 1
        assert usb_event.scan_results[0].id == scan_result.id
        assert usb_event.scan_results[0].usb_event == usb_event

    finally:
        db.close()


def test_usb_scan_result_cascade_delete():
    db = SessionLocal()
    try:
        device = Device(
            hostname="test-cascade-scan-host",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="E:",
            volume_label="SECURE_FLASH"
        )
        db.add(usb_event)
        db.commit()
        db.refresh(usb_event)

        scan1 = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="file1.txt",
            full_path="E:\\file1.txt",
            extension=".txt",
            file_size=100,
            sha256="a" * 64
        )
        scan2 = USBScanResult(
            usb_event_id=usb_event.id,
            file_name="file2.pdf",
            full_path="E:\\file2.pdf",
            extension=".pdf",
            file_size=500,
            sha256="b" * 64
        )
        db.add_all([scan1, scan2])
        db.commit()

        scan1_id = scan1.id
        scan2_id = scan2.id

        # Delete usb_event
        db.delete(usb_event)
        db.commit()

        # Check scan results deleted
        assert db.query(USBScanResult).filter(USBScanResult.id == scan1_id).first() is None
        assert db.query(USBScanResult).filter(USBScanResult.id == scan2_id).first() is None

    finally:
        db.close()
