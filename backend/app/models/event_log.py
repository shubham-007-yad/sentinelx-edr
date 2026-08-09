import uuid
import enum
from sqlalchemy import Column, String, Text, Integer, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class EventLevel(str, enum.Enum):
    INFORMATION = "Information"
    WARNING = "Warning"
    ERROR = "Error"
    CRITICAL = "Critical"


class EventType(str, enum.Enum):
    AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ACCOUNT_MANAGEMENT = "ACCOUNT_MANAGEMENT"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    PERSISTENCE = "PERSISTENCE"
    SYSTEM_EVENT = "SYSTEM_EVENT"


class SecurityEvent(Base):
    __tablename__ = "security_events"

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
    threat_id = Column(
        UUID(as_uuid=True),
        ForeignKey("threats.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    alert_id = Column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    event_source = Column(String(100), nullable=False, index=True)  # Security, System, Application, auth.log, syslog, journalctl
    event_id = Column(String(50), nullable=True, index=True)        # e.g., 4624, 4625, 4672, 4720, 1102, SSH_FAILED, etc.
    event_type = Column(String(100), nullable=False, default="SYSTEM_EVENT", index=True)
    level = Column(
        Enum(EventLevel, native_enum=False, name="eventlevel"),
        default=EventLevel.INFORMATION,
        nullable=False,
        index=True
    )
    username = Column(String(255), nullable=True, index=True)
    domain = Column(String(255), nullable=True)
    computer = Column(String(255), nullable=True, index=True)
    logon_type = Column(String(100), nullable=True)
    ip_address = Column(String(100), nullable=True, index=True)
    status = Column(String(50), nullable=True, default="SUCCESS")
    description = Column(Text, nullable=False)
    raw_event = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    device = relationship("Device", back_populates="security_events")
    threat = relationship("Threat", foreign_keys=[threat_id])
    alert = relationship("Alert", foreign_keys=[alert_id])

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent id={self.id} device_id={self.device_id} source='{self.event_source}' "
            f"event_id='{self.event_id}' user='{self.username}' level='{self.level}'>"
        )
