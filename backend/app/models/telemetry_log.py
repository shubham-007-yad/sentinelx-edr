import uuid
import enum
from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class TelemetryCategoryEnum(str, enum.Enum):
    USB = "USB"
    FILE_INTEGRITY = "FILE_INTEGRITY"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    SECURITY_EVENT = "SECURITY_EVENT"
    IOC_INTELLIGENCE = "IOC_INTELLIGENCE"
    RANSOMWARE = "RANSOMWARE"


class UnifiedTelemetryLog(Base):
    """
    Unified Telemetry Log database model storing all standardized agent telemetry events.
    """
    __tablename__ = "telemetry_logs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    category = Column(
        SQLEnum(TelemetryCategoryEnum, native_enum=True, name="telemetrycategoryenum"),
        nullable=False,
        index=True
    )
    event_type = Column(
        String(100),
        nullable=False,
        index=True
    )
    source = Column(
        String(100),
        nullable=False,
        index=True
    )
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    correlation_id = Column(
        UUID(as_uuid=True),
        default=uuid.uuid4,
        index=True,
        nullable=True
    )
    tenant_id = Column(
        String(100),
        default="default_tenant",
        index=True,
        nullable=True
    )
    host_info = Column(
        JSONB,
        default={},
        nullable=False
    )
    payload = Column(
        JSONB,
        default={},
        nullable=False
    )


    device = relationship("Device", backref="telemetry_logs")

    def __repr__(self) -> str:
        return f"<UnifiedTelemetryLog id={self.id} category='{self.category}' event_type='{self.event_type}'>"
