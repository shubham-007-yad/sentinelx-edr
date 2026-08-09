import uuid
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class ProcessInfo(Base):
    __tablename__ = "process_info"

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
    ppid = Column(Integer, nullable=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    exe_path = Column(String(1024), nullable=True)
    username = Column(String(255), nullable=True)
    cpu_percent = Column(Float, default=0.0, nullable=True)
    memory_percent = Column(Float, default=0.0, nullable=True)
    start_time = Column(String(255), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    cmdline = Column(Text, nullable=True)
    captured_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    device = relationship("Device", back_populates="processes")

    def __repr__(self) -> str:
        return f"<ProcessInfo id={self.id} device_id={self.device_id} pid={self.pid} name='{self.name}'>"
