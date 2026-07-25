import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.usb_event import USBEvent, USBEventType
from app.models.device import Device, DeviceStatus, OSType

client = TestClient(app)


def test_full_usb_lifecycle_integration():
    """
    End-to-End USB Lifecycle Integration Test:
    1. Endpoint Registration: Agent registers PC-01 endpoint device with backend.
    2. USB Insert: Agent detects real/simulated USB insertion, collects metadata, and POSTs to /api/v1/usb/events.
    3. Backend Persistence: Backend validates device and stores INSERT USB event in PostgreSQL.
    4. API & Dashboard Verification: GET /api/v1/usb/events returns stored INSERT event with metadata.
    5. USB Remove: Agent detects USB removal and POSTs REMOVE event to /api/v1/usb/events.
    6. Removal Verification: GET /api/v1/usb/events verifies stored REMOVE event.
    """
    # 1. Device Registration (Endpoint PC-01)
    hostname = f"PC-01-{str(uuid.uuid4())[:6]}"
    mac = f"00:11:22:33:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"

    reg_response = client.post("/api/v1/devices/register", json={
        "hostname": hostname,
        "mac_address": mac,
        "os_type": "WINDOWS",
        "ip_address": "192.168.1.105",
        "agent_version": "1.0.0"
    })
    assert reg_response.status_code == 201
    device_data = reg_response.json()
    device_id = device_data["id"]
    assert device_data["hostname"] == hostname
    assert device_data["status"] == "ONLINE"

    # 2. USB Insertion Event (Insert USB -> Agent detects -> Collect metadata -> POST /api/v1/usb/events)
    insert_payload = {
        "device_id": device_id,
        "event_type": "INSERT",
        "drive_letter": "E:",
        "volume_label": "KINGSTON_32G",
        "filesystem": "FAT32",
        "total_size": 32017047552,
        "free_space": 15872184320,
        "serial_number": "KNG-USB-998877"
    }

    insert_res = client.post("/api/v1/usb/events", json=insert_payload)
    assert insert_res.status_code == 201
    inserted_event = insert_res.json()

    assert inserted_event["id"] is not None
    assert inserted_event["device_id"] == device_id
    assert inserted_event["event_type"] == "INSERT"
    assert inserted_event["drive_letter"] == "E:"
    assert inserted_event["volume_label"] == "KINGSTON_32G"
    assert inserted_event["filesystem"] == "FAT32"
    assert inserted_event["total_size"] == 32017047552
    assert inserted_event["free_space"] == 15872184320
    assert inserted_event["serial_number"] == "KNG-USB-998877"

    insert_event_id = inserted_event["id"]

    # 3. Direct DB Verification of Inserted Event
    db = SessionLocal()
    try:
        db_insert_evt = db.query(USBEvent).filter(USBEvent.id == insert_event_id).first()
        assert db_insert_evt is not None
        assert str(db_insert_evt.device_id) == device_id
        assert db_insert_evt.event_type == USBEventType.INSERT
        assert db_insert_evt.drive_letter == "E:"
        assert db_insert_evt.volume_label == "KINGSTON_32G"
    finally:
        db.close()

    # 4. API & Dashboard Verification (GET /api/v1/usb/events)
    list_res = client.get(f"/api/v1/usb/events?device_id={device_id}")
    assert list_res.status_code == 200
    events_list = list_res.json()
    assert len(events_list) == 1
    assert events_list[0]["id"] == insert_event_id
    assert events_list[0]["event_type"] == "INSERT"

    # Detail API verification (GET /api/v1/usb/events/{id})
    detail_res = client.get(f"/api/v1/usb/events/{insert_event_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["drive_letter"] == "E:"

    # 5. USB Removal Event (Remove USB -> Agent detects -> POST /api/v1/usb/events)
    remove_payload = {
        "device_id": device_id,
        "event_type": "REMOVE",
        "drive_letter": "E:",
        "volume_label": "KINGSTON_32G",
        "filesystem": "FAT32",
        "total_size": 32017047552,
        "free_space": 15872184320,
        "serial_number": "KNG-USB-998877"
    }

    remove_res = client.post("/api/v1/usb/events", json=remove_payload)
    assert remove_res.status_code == 201
    removed_event = remove_res.json()

    assert removed_event["id"] is not None
    assert removed_event["device_id"] == device_id
    assert removed_event["event_type"] == "REMOVE"
    assert removed_event["drive_letter"] == "E:"

    remove_event_id = removed_event["id"]

    # 6. Verify Complete Dashboard Data Feed (GET /api/v1/usb/events)
    list_after_remove = client.get(f"/api/v1/usb/events?device_id={device_id}")
    assert list_after_remove.status_code == 200
    all_device_events = list_after_remove.json()

    assert len(all_device_events) == 2
    # Events ordered by detected_at desc -> Most recent (REMOVE) first
    assert all_device_events[0]["event_type"] == "REMOVE"
    assert all_device_events[1]["event_type"] == "INSERT"
