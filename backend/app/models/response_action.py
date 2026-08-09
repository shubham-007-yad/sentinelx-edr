import uuid
import enum
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class ResponseActionType(str, enum.Enum):
    QUARANTINE = "QUARANTINE"
    DELETE = "DELETE"
    ISOLATE = "ISOLATE"
    IGNORE = "IGNORE"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    MARK_TRUSTED = "MARK_TRUSTED"
    ADD_ALLOWLIST = "ADD_ALLOWLIST"
    BLOCK_IP = "BLOCK_IP"
    INVESTIGATE = "INVESTIGATE"
    RESTORE_BASELINE = "RESTORE_BASELINE"
    RECALCULATE_BASELINE = "RECALCULATE_BASELINE"
    IGNORE_CHANGE = "IGNORE_CHANGE"
    DISABLE_USER = "DISABLE_USER"
    FORCE_LOGOUT = "FORCE_LOGOUT"
    ALLOWLIST_EVENT = "ALLOWLIST_EVENT"



class ResponseActionStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    alert_id = Column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    action_type = Column(
        Enum(ResponseActionType, native_enum=True, name="responseactiontype"),
        nullable=False,
        index=True
    )
    status = Column(
        Enum(ResponseActionStatus, native_enum=True, name="responseactionstatus"),
        default=ResponseActionStatus.PENDING,
        nullable=False,
        index=True
    )
    initiated_by = Column(
        String(100),
        default="AUTOMATIC",
        nullable=False
    )
    started_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    completed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    result = Column(
        Text,
        nullable=True
    )

    alert = relationship("Alert", back_populates="response_actions")
    device = relationship("Device", back_populates="response_actions")
    audit_logs = relationship("ResponseAuditLog", back_populates="action", cascade="all, delete-orphan", order_by="ResponseAuditLog.timestamp.asc()")

    def __repr__(self) -> str:
        return f"<ResponseAction id={self.id} action_type='{self.action_type}' status='{self.status}'>"
