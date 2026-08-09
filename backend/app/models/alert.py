import uuid
import enum
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    UNREAD = "UNREAD"
    READ = "READ"
    ACKNOWLEDGED = "ACKNOWLEDGED"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    threat_id = Column(
        UUID(as_uuid=True),
        ForeignKey("threats.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(
        Enum(AlertSeverity, native_enum=True, name="alertseverity"),
        nullable=False,
        index=True
    )
    status = Column(
        Enum(AlertStatus, native_enum=True, name="alertstatus"),
        default=AlertStatus.UNREAD,
        nullable=False,
        index=True
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    read_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    acknowledged_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    threat = relationship("Threat", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")
    response_actions = relationship("ResponseAction", back_populates="alert", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Alert id={self.id} title='{self.title}' severity='{self.severity}' status='{self.status}'>"
