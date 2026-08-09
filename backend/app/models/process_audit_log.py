import uuid
import enum
from sqlalchemy import Column, String, Integer, Text, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class ProcessEventType(str, enum.Enum):
    PROCESS_STARTED = "PROCESS_STARTED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    RESPONSE_ACTION = "RESPONSE_ACTION"
    DETECTION_FOUND = "DETECTION_FOUND"


class ProcessAuditLog(Base):
    __tablename__ = "process_audit_logs"

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
    pid = Column(Integer, nullable=False, index=True)
    ppid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=False, index=True)
    event_type = Column(
        Enum(ProcessEventType, native_enum=True, name="processeventtype"),
        nullable=False,
        index=True
    )
    details = Column(Text, nullable=True)
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    device = relationship("Device", backref="process_audit_logs")

    def __repr__(self) -> str:
        return f"<ProcessAuditLog id={self.id} event_type='{self.event_type}' process_name='{self.process_name}' pid={self.pid}>"
