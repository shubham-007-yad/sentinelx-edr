import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.user import User, UserRole
from app.schemas.device import DeviceCreate, DeviceUpdate, DeviceOut

client = TestClient(app)


def test_device_model_creation():
    db = SessionLocal()
    try:
        user_uuid = uuid.uuid4()
        user = User(
            id=user_uuid,
            username=f"dev_owner_{str(user_uuid)[:8]}",
            email=f"dev_owner_{str(user_uuid)[:8]}@sentinelx.io",
            password_hash="hashed_pw_test",
            role=UserRole.ANALYST
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        device = Device(
            hostname="workstation-01",
            ip_address="192.168.1.50",
            mac_address="00:11:22:33:44:55",
            os_type=OSType.WINDOWS,
            os_version="Windows 11 Pro 22H2",
            agent_version="1.0.4",
            status=DeviceStatus.ONLINE,
            user_id=user.id
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        assert device.id is not None
        assert device.hostname == "workstation-01"
        assert device.os_type == OSType.WINDOWS
        assert device.status == DeviceStatus.ONLINE
        assert device.user_id == user.id
        assert device.user.username == user.username

        device_out = DeviceOut.model_validate(device)
        assert device_out.id == device.id
        assert device_out.hostname == "workstation-01"
        assert device_out.os_type == OSType.WINDOWS
        assert device_out.status == DeviceStatus.ONLINE

    finally:
        db.close()


def test_device_schema_validation():
    create_schema = DeviceCreate(
        hostname="  srv-linux-01  ",
        status="online",
        os_type="linux"
    )
    assert create_schema.hostname == "srv-linux-01"
    assert create_schema.status == DeviceStatus.ONLINE
    assert create_schema.os_type == OSType.LINUX

    update_schema = DeviceUpdate(
        status="isolated",
        os_type="windows"
    )
    assert update_schema.status == DeviceStatus.ISOLATED
    assert update_schema.os_type == OSType.WINDOWS


def test_device_registration_endpoint():
    mac = f"00:11:22:33:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
    hostname = f"test-host-{str(uuid.uuid4())[:8]}"

    payload = {
        "hostname": hostname,
        "ip_address": "10.0.0.15",
        "mac_address": mac,
        "os_type": "LINUX",
        "os_version": "Ubuntu 22.04 LTS",
        "agent_version": "1.2.0"
    }

    # 1. First registration
    response = client.post("/api/v1/devices/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["hostname"] == hostname
    assert data["mac_address"] == mac
    assert data["status"] == "ONLINE"
    assert data["os_type"] == "LINUX"
    device_id = data["id"]

    # 2. Re-registration (duplicate prevention test)
    payload_updated = {
        "hostname": hostname,
        "ip_address": "10.0.0.99",
        "mac_address": mac,
        "os_type": "LINUX",
        "os_version": "Ubuntu 22.04 LTS",
        "agent_version": "1.2.1"
    }
    re_response = client.post("/api/v1/devices/register", json=payload_updated)
    assert re_response.status_code == 201
    re_data = re_response.json()
    assert re_data["id"] == device_id
    assert re_data["ip_address"] == "10.0.0.99"
    assert re_data["agent_version"] == "1.2.1"


def test_device_registration_validation_error():
    response = client.post("/api/v1/devices/register", json={
        "ip_address": "192.168.1.1"
    })
    assert response.status_code == 422


def test_device_heartbeat_endpoint():
    mac = f"00:11:22:77:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
    hostname = f"hb-host-{str(uuid.uuid4())[:8]}"

    # Register device first
    reg_res = client.post("/api/v1/devices/register", json={
        "hostname": hostname,
        "mac_address": mac,
        "os_type": "LINUX"
    })
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]

    # Send heartbeat
    hb_res = client.post("/api/v1/devices/heartbeat", json={
        "device_id": device_id,
        "ip_address": "192.168.1.222",
        "status": "ONLINE"
    })
    assert hb_res.status_code == 200
    hb_data = hb_res.json()
    assert hb_data["device_id"] == device_id
    assert hb_data["status"] == "ONLINE"
    assert "last_seen" in hb_data
    assert hb_data["message"] == "Heartbeat recorded successfully"


def test_device_heartbeat_not_found():
    random_id = str(uuid.uuid4())
    hb_res = client.post("/api/v1/devices/heartbeat", json={
        "device_id": random_id,
        "status": "ONLINE"
    })
    assert hb_res.status_code == 404


def test_list_devices_endpoint():
    mac1 = f"00:11:22:88:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
    mac2 = f"00:11:22:99:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"

    client.post("/api/v1/devices/register", json={"hostname": f"list-host-1-{str(uuid.uuid4())[:4]}", "mac_address": mac1, "os_type": "WINDOWS"})
    client.post("/api/v1/devices/register", json={"hostname": f"list-host-2-{str(uuid.uuid4())[:4]}", "mac_address": mac2, "os_type": "LINUX"})

    response = client.get("/api/v1/devices")
    assert response.status_code == 200
    devices = response.json()
    assert isinstance(devices, list)
    assert len(devices) >= 2

    response_filter = client.get("/api/v1/devices?os_type=WINDOWS")
    assert response_filter.status_code == 200
    win_devices = response_filter.json()
    assert all(d["os_type"] == "WINDOWS" for d in win_devices)


def test_get_device_by_id_endpoint():
    mac = f"00:11:22:AA:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"
    reg_res = client.post("/api/v1/devices/register", json={"hostname": f"single-host-{str(uuid.uuid4())[:4]}", "mac_address": mac})
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]

    response = client.get(f"/api/v1/devices/{device_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == device_id
    assert data["mac_address"] == mac


def test_get_device_by_id_not_found():
    random_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/devices/{random_id}")
    assert response.status_code == 404
