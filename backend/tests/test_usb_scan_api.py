import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType

client = TestClient(app)


@pytest.fixture
def setup_usb_event():
    db = SessionLocal()
    try:
        device = Device(
            hostname="test-scan-api-host",
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
            volume_label="API_SCAN_FLASH"
        )
        db.add(usb_event)
        db.commit()
        db.refresh(usb_event)

        yield usb_event
    finally:
        db.close()


def test_create_and_list_usb_scans(setup_usb_event):
    usb_event_id = str(setup_usb_event.id)

    # 1. Upload bulk scan results
    scan_payload = [
        {
            "usb_event_id": usb_event_id,
            "file_name": "autorun.inf",
            "full_path": "E:\\autorun.inf",
            "extension": ".inf",
            "file_size": 128,
            "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "is_hidden": True
        },
        {
            "usb_event_id": usb_event_id,
            "file_name": "payload.exe",
            "full_path": "E:\\Tools\\payload.exe",
            "extension": ".exe",
            "file_size": 2048576,
            "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            "is_hidden": False
        },
        {
            "usb_event_id": usb_event_id,
            "file_name": "document.pdf",
            "full_path": "E:\\Docs\\document.pdf",
            "extension": ".pdf",
            "file_size": 512000,
            "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
            "is_hidden": False
        }
    ]

    response = client.post("/api/v1/usb/scans", json=scan_payload)
    assert response.status_code == 201
    scans_data = response.json()
    assert isinstance(scans_data, list)
    assert len(scans_data) == 3

    scan_id = scans_data[0]["id"]

    # 2. Get single scan detail by ID
    detail_resp = client.get(f"/api/v1/usb/scans/{scan_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == scan_id

    # 3. List with usb_event_id filter
    list_resp = client.get(f"/api/v1/usb/scans?usb_event_id={usb_event_id}")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 3

    # 4. Filter by extension (.exe)
    exe_resp = client.get(f"/api/v1/usb/scans?usb_event_id={usb_event_id}&extension=.exe")
    assert exe_resp.status_code == 200
    exe_data = exe_resp.json()
    assert len(exe_data) == 1
    assert exe_data[0]["file_name"] == "payload.exe"

    # 5. Filter by is_hidden (true)
    hidden_resp = client.get(f"/api/v1/usb/scans?usb_event_id={usb_event_id}&is_hidden=true")
    assert hidden_resp.status_code == 200
    hidden_data = hidden_resp.json()
    assert len(hidden_data) == 1
    assert hidden_data[0]["file_name"] == "autorun.inf"


def test_create_usb_scan_non_existent_event():
    fake_event_id = str(uuid.uuid4())
    scan_payload = {
        "usb_event_id": fake_event_id,
        "file_name": "test.txt",
        "full_path": "E:\\test.txt",
        "extension": ".txt",
        "file_size": 10,
        "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
        "is_hidden": False
    }

    response = client.post("/api/v1/usb/scans", json=scan_payload)
    assert response.status_code == 404
    assert f"USB Event with ID '{fake_event_id}' was not found" in response.json()["detail"]


def test_get_usb_scan_404():
    fake_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/usb/scans/{fake_id}")
    assert response.status_code == 404
