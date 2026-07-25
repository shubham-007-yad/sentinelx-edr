import uuid
import enum
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class DeviceStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    ISOLATED = "ISOLATED"
    UNREGISTERED = "UNREGISTERED"


class OSType(str, enum.Enum):
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"
    OTHER = "OTHER"


class Device(Base):
    __tablename__ = "devices"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    hostname = Column(String(255), index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    mac_address = Column(String(17), nullable=True)
    os_type = Column(
        Enum(OSType, native_enum=True, name="ostype"),
        default=OSType.LINUX,
        nullable=False
    )
    os_version = Column(String(100), nullable=True)
    agent_version = Column(String(50), nullable=True)
    status = Column(
        Enum(DeviceStatus, native_enum=True, name="devicestatus"),
        default=DeviceStatus.OFFLINE,
        nullable=False
    )
    is_active = Column(Boolean, default=True, nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    user = relationship("User", back_populates="devices")
    usb_events = relationship("USBEvent", back_populates="device", cascade="all, delete-orphan")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<Device id={self.id} hostname={self.hostname} status={self.status}>"
