import uuid
import enum
from sqlalchemy import Column, String, Text, Integer, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class AgentUpgradeStatus(str, enum.Enum):
    IDLE = "IDLE"
    AVAILABLE = "AVAILABLE"
    DOWNLOADING = "DOWNLOADING"
    INSTALLING = "INSTALLING"
    RESTARTING = "RESTARTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class RollbackStatus(str, enum.Enum):
    NONE = "NONE"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESSFUL = "SUCCESSFUL"
    FAILED = "FAILED"


class AgentUpgradeRecord(Base):
    __tablename__ = "agent_upgrades"

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
    current_version = Column(String(50), nullable=False)
    target_version = Column(String(50), nullable=False, default="1.2.0")
    status = Column(
        Enum(AgentUpgradeStatus, native_enum=True, name="agentupgradestatus"),
        default=AgentUpgradeStatus.AVAILABLE,
        nullable=False,
        index=True
    )
    rollback_status = Column(
        Enum(RollbackStatus, native_enum=True, name="rollbackstatus"),
        default=RollbackStatus.NONE,
        nullable=False,
        index=True
    )
    progress_percent = Column(Integer, default=0, nullable=False)
    logs = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    started_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    completed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    device = relationship("Device", backref="upgrade_records")

    def __repr__(self) -> str:
        return f"<AgentUpgradeRecord id={self.id} device_id={self.device_id} current='{self.current_version}' target='{self.target_version}' status='{self.status}'>"
