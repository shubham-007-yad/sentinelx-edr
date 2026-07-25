import uuid
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType


def test_usb_event_model_creation():
    db = SessionLocal()
    try:
        device = Device(
            hostname="test-usb-host",
            ip_address="192.168.1.100",
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
            volume_label="SECURE_FLASH",
            filesystem="FAT32",
            total_size=16000000000,
            free_space=8000000000,
            serial_number="USB-XYZ-9876"
        )
        db.add(usb_event)
        db.commit()
        db.refresh(usb_event)

        assert usb_event.id is not None
        assert usb_event.device_id == device.id
        assert usb_event.event_type == USBEventType.INSERT
        assert usb_event.drive_letter == "E:"
        assert usb_event.volume_label == "SECURE_FLASH"
        assert usb_event.filesystem == "FAT32"
        assert usb_event.total_size == 16000000000
        assert usb_event.free_space == 8000000000
        assert usb_event.serial_number == "USB-XYZ-9876"
        assert usb_event.detected_at is not None

        # Verify relationship from device
        db.refresh(device)
        assert len(device.usb_events) == 1
        assert device.usb_events[0].id == usb_event.id
        assert device.usb_events[0].device == device

    finally:
        db.close()


def test_usb_event_cascade_delete():
    db = SessionLocal()
    try:
        device = Device(
            hostname="test-cascade-host",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        event1 = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="F:",
            volume_label="DRIVE_1"
        )
        event2 = USBEvent(
            device_id=device.id,
            event_type=USBEventType.REMOVE,
            drive_letter="F:",
            volume_label="DRIVE_1"
        )
        db.add_all([event1, event2])
        db.commit()

        event1_id = event1.id
        event2_id = event2.id

        # Delete device
        db.delete(device)
        db.commit()

        # Check events deleted
        deleted_event1 = db.query(USBEvent).filter(USBEvent.id == event1_id).first()
        deleted_event2 = db.query(USBEvent).filter(USBEvent.id == event2_id).first()
        assert deleted_event1 is None
        assert deleted_event2 is None

    finally:
        db.close()
