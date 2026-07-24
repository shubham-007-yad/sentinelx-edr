from typing import Optional, List
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.device import Device, DeviceStatus, OSType
from app.schemas.device import DeviceCreate, DeviceUpdate


def get_device_by_id(db: Session, device_id: UUID) -> Optional[Device]:
    return db.query(Device).filter(Device.id == device_id).first()


def get_device_by_mac(db: Session, mac_address: str) -> Optional[Device]:
    if not mac_address:
        return None
    return db.query(Device).filter(Device.mac_address == mac_address.strip()).first()


def get_device_by_hostname(db: Session, hostname: str) -> Optional[Device]:
    if not hostname:
        return None
    return db.query(Device).filter(Device.hostname == hostname.strip()).first()


def register_device(db: Session, device_in: DeviceCreate) -> Device:
    """
    Register a new device or update an existing device if MAC address or hostname matches.
    Prevents duplicate device registrations in PostgreSQL database.
    """
    existing_device = None
    if device_in.mac_address:
        existing_device = get_device_by_mac(db, device_in.mac_address)

    if not existing_device and device_in.hostname:
        existing_device = get_device_by_hostname(db, device_in.hostname)

    now = datetime.now(timezone.utc)

    if existing_device:
        existing_device.hostname = device_in.hostname
        if device_in.ip_address:
            existing_device.ip_address = device_in.ip_address
        if device_in.mac_address:
            existing_device.mac_address = device_in.mac_address
        if device_in.os_type:
            existing_device.os_type = device_in.os_type
        if device_in.os_version:
            existing_device.os_version = device_in.os_version
        if device_in.agent_version:
            existing_device.agent_version = device_in.agent_version
        if device_in.user_id:
            existing_device.user_id = device_in.user_id

        existing_device.status = DeviceStatus.ONLINE
        existing_device.is_active = True
        existing_device.last_seen = now
        existing_device.updated_at = now

        db.add(existing_device)
        db.commit()
        db.refresh(existing_device)
        return existing_device

    db_device = Device(
        hostname=device_in.hostname,
        ip_address=device_in.ip_address,
        mac_address=device_in.mac_address,
        os_type=device_in.os_type or OSType.LINUX,
        os_version=device_in.os_version,
        agent_version=device_in.agent_version,
        status=DeviceStatus.ONLINE,
        is_active=True,
        last_seen=now,
        user_id=device_in.user_id
    )
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device


def get_devices(db: Session, skip: int = 0, limit: int = 100) -> List[Device]:
    return db.query(Device).offset(skip).limit(limit).all()
