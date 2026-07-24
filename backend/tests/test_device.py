import uuid
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.user import User, UserRole
from app.schemas.device import DeviceCreate, DeviceUpdate, DeviceOut


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
