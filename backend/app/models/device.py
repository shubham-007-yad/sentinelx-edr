import uuid
import enum
from typing import Optional
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, Integer, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class DeviceStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    ISOLATED = "ISOLATED"
    UNREGISTERED = "UNREGISTERED"
    OUTDATED = "OUTDATED"
    UNHEALTHY = "UNHEALTHY"


class HealthStatus(str, enum.Enum):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    WARNING = "WARNING"
    DEGRADED = "DEGRADED"
    OUTDATED = "OUTDATED"


class CommandStatus(str, enum.Enum):
    NONE = "NONE"
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    EXECUTED = "EXECUTED"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


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
    applied_policy_version = Column(Integer, nullable=True, default=None)
    status = Column(
        Enum(DeviceStatus, native_enum=False, name="devicestatus"),
        default=DeviceStatus.OFFLINE,
        nullable=False
    )
    health_status = Column(
        Enum(HealthStatus, native_enum=False, name="healthstatus"),
        default=HealthStatus.HEALTHY,
        nullable=False
    )
    last_command_status = Column(
        Enum(CommandStatus, native_enum=False, name="commandstatus"),
        default=CommandStatus.NONE,
        nullable=False
    )

    # Phase 2 Agent Health Monitoring Metrics
    cpu_usage_percent = Column(Float, nullable=True, default=0.0)
    ram_usage_mb = Column(Float, nullable=True, default=0.0)
    ram_usage_percent = Column(Float, nullable=True, default=0.0)
    disk_usage_percent = Column(Float, nullable=True, default=0.0)
    agent_uptime_seconds = Column(Integer, nullable=True, default=0)
    service_status = Column(String(50), nullable=True, default="RUNNING")
    last_telemetry_upload = Column(DateTime(timezone=True), nullable=True)
    last_policy_sync = Column(DateTime(timezone=True), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    last_checkin = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    user = relationship("User", back_populates="devices")
    usb_events = relationship("USBEvent", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    response_actions = relationship("ResponseAction", back_populates="device", cascade="all, delete-orphan")
    processes = relationship("ProcessInfo", back_populates="device", cascade="all, delete-orphan")
    network_connections = relationship("NetworkConnection", back_populates="device", cascade="all, delete-orphan")
    file_integrity_records = relationship("FileIntegrityRecord", back_populates="device", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="device", cascade="all, delete-orphan")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    @property
    def policy_version(self) -> Optional[int]:
        return self.applied_policy_version

    @policy_version.setter
    def policy_version(self, value: Optional[int]) -> None:
        self.applied_policy_version = value

    @property
    def operating_system(self) -> str:
        if self.os_version:
            return f"{self.os_type.value} ({self.os_version})"
        return self.os_type.value if self.os_type else "UNKNOWN"

    def __repr__(self) -> str:
        return f"<Device id={self.id} hostname={self.hostname} status={self.status} health={self.health_status}>"
