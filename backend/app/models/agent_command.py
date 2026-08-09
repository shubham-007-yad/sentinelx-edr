import uuid
import enum
from typing import Optional
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class AgentCommandType(str, enum.Enum):
    START_SCAN = "START_SCAN"
    RESTART_AGENT = "RESTART_AGENT"
    REFRESH_POLICY = "REFRESH_POLICY"
    COLLECT_DIAGNOSTICS = "COLLECT_DIAGNOSTICS"
    UPLOAD_LOGS = "UPLOAD_LOGS"
    RECONNECT = "RECONNECT"
    SHUTDOWN_AGENT = "SHUTDOWN_AGENT"
    UPDATE_CONFIG = "UPDATE_CONFIG"


class AgentCommandStatus(str, enum.Enum):
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AgentCommand(Base):
    __tablename__ = "agent_commands"

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
    issuer_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    command_type = Column(
        Enum(AgentCommandType, native_enum=False, name="agentcommandtype"),
        nullable=False,
        index=True
    )
    status = Column(
        Enum(AgentCommandStatus, native_enum=False, name="agentcommandstatus"),
        default=AgentCommandStatus.PENDING,
        nullable=False,
        index=True
    )
    payload = Column(JSON, nullable=True)
    result_output = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    execution_duration_ms = Column(Integer, nullable=True)

    queued_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    dispatched_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    acknowledged_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    device = relationship("Device")
    issuer = relationship("User")

    def __repr__(self) -> str:
        return f"<AgentCommand id={self.id} type={self.command_type} status={self.status} device={self.device_id}>"


class AgentCommandAuditLog(Base):
    __tablename__ = "agent_command_audit_logs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    command_id = Column(
        UUID(as_uuid=True),
        ForeignKey("agent_commands.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    issuer_username = Column(String(100), nullable=False)
    command_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    device = relationship("Device")
    command = relationship("AgentCommand")

    def __repr__(self) -> str:
        return f"<AgentCommandAuditLog id={self.id} command={self.command_type} status={self.status}>"
