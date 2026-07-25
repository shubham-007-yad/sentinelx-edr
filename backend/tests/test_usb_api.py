import uuid
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_create_and_get_usb_event_flow():
    # 1. Register a test device
    mac = f"00:11:22:99:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
    hostname = f"usb-test-host-{str(uuid.uuid4())[:8]}"

    reg_res = client.post("/api/v1/devices/register", json={
        "hostname": hostname,
        "mac_address": mac,
        "os_type": "WINDOWS"
    })
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]

    # 2. Create USB Insert Event (POST /api/v1/usb/events)
    payload_insert = {
        "device_id": device_id,
        "event_type": "INSERT",
        "drive_letter": "E:",
        "volume_label": "FLASH_DRIVE",
        "filesystem": "FAT32",
        "total_size": 32017047552,
        "free_space": 15872184320,
        "serial_number": "SN-USB-9999"
    }

    res_insert = client.post("/api/v1/usb/events", json=payload_insert)
    assert res_insert.status_code == 201
    event_data = res_insert.json()

    assert "id" in event_data
    assert event_data["device_id"] == device_id
    assert event_data["event_type"] == "INSERT"
    assert event_data["drive_letter"] == "E:"
    assert event_data["volume_label"] == "FLASH_DRIVE"
    assert event_data["filesystem"] == "FAT32"
    assert event_data["total_size"] == 32017047552
    assert event_data["free_space"] == 15872184320
    assert event_data["serial_number"] == "SN-USB-9999"
    assert "detected_at" in event_data

    event_id = event_data["id"]

    # 3. Create USB Remove Event
    payload_remove = {
        "device_id": device_id,
        "event_type": "REMOVE",
        "drive_letter": "E:",
        "volume_label": "FLASH_DRIVE",
        "filesystem": "FAT32"
    }

    res_remove = client.post("/api/v1/usb/events", json=payload_remove)
    assert res_remove.status_code == 201
    assert res_remove.json()["event_type"] == "REMOVE"

    # 4. List all USB events (GET /api/v1/usb/events)
    res_list = client.get("/api/v1/usb/events")
    assert res_list.status_code == 200
    events_list = res_list.json()
    assert isinstance(events_list, list)
    assert len(events_list) >= 2

    # Filter by device_id
    res_filter_dev = client.get(f"/api/v1/usb/events?device_id={device_id}")
    assert res_filter_dev.status_code == 200
    dev_events = res_filter_dev.json()
    assert len(dev_events) == 2
    assert all(e["device_id"] == device_id for e in dev_events)

    # Filter by event_type
    res_filter_type = client.get(f"/api/v1/usb/events?device_id={device_id}&event_type=INSERT")
    assert res_filter_type.status_code == 200
    insert_events = res_filter_type.json()
    assert len(insert_events) == 1
    assert insert_events[0]["event_type"] == "INSERT"

    # 5. Get USB Event Detail by ID (GET /api/v1/usb/events/{id})
    res_detail = client.get(f"/api/v1/usb/events/{event_id}")
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["id"] == event_id
    assert detail_data["device_id"] == device_id
    assert detail_data["drive_letter"] == "E:"


def test_create_usb_event_device_not_found():
    random_device_id = str(uuid.uuid4())
    response = client.post("/api/v1/usb/events", json={
        "device_id": random_device_id,
        "event_type": "INSERT",
        "drive_letter": "Z:"
    })
    assert response.status_code == 404
    assert f"Device with ID '{random_device_id}' was not found." in response.json()["detail"]


def test_get_usb_event_by_id_not_found():
    random_event_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/usb/events/{random_event_id}")
    assert response.status_code == 404
    assert f"USB event with ID '{random_event_id}' was not found." in response.json()["detail"]
