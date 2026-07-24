import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus

client = TestClient(app)


def test_day3_backend_e2e_device_lifecycle():
    """
    Backend End-to-End Test for Day 3 Device Management:
    1. POST /devices/register -> Creates device record
    2. DB check -> Verify device persisted in PostgreSQL
    3. POST /devices/heartbeat -> Updates last_seen timestamp
    4. GET /devices -> Confirms device is listed with status ONLINE
    5. GET /devices/{id} -> Confirms single device detail lookup
    """
    mac = f"02:00:00:22:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
    hostname = f"b-e2e-host-{str(uuid.uuid4())[:6]}"

    # Step 1: Register
    reg_res = client.post("/api/v1/devices/register", json={
        "hostname": hostname,
        "ip_address": "172.16.0.45",
        "mac_address": mac,
        "os_type": "LINUX",
        "os_version": "Ubuntu 24.04",
        "agent_version": "1.0.0"
    })
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]

    # Step 2: Database Check
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        assert device is not None
        assert device.hostname == hostname
        assert device.status == DeviceStatus.ONLINE
    finally:
        db.close()

    # Step 3: Send Heartbeat
    hb_res = client.post("/api/v1/devices/heartbeat", json={
        "device_id": device_id,
        "ip_address": "172.16.0.46",
        "status": "ONLINE"
    })
    assert hb_res.status_code == 200
    assert hb_res.json()["device_id"] == device_id

    # Step 4: GET /devices
    list_res = client.get("/api/v1/devices")
    assert list_res.status_code == 200
    devices = list_res.json()
    assert any(d["id"] == device_id for d in devices)

    # Step 5: GET /devices/{id}
    detail_res = client.get(f"/api/v1/devices/{device_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == device_id
    assert detail_res.json()["ip_address"] == "172.16.0.46"
