import uuid
import enum
from sqlalchemy import Column, String, BigInteger, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class USBEventType(str, enum.Enum):
    INSERT = "INSERT"
    REMOVE = "REMOVE"


class USBEvent(Base):
    __tablename__ = "usb_events"

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
    event_type = Column(
        Enum(USBEventType, native_enum=True, name="usbeventtype"),
        nullable=False
    )
    drive_letter = Column(String(50), nullable=True)
    volume_label = Column(String(255), nullable=True)
    filesystem = Column(String(50), nullable=True)
    total_size = Column(BigInteger, nullable=True)
    free_space = Column(BigInteger, nullable=True)
    serial_number = Column(String(255), nullable=True)
    detected_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    device = relationship("Device", back_populates="usb_events")
    scan_results = relationship("USBScanResult", back_populates="usb_event", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<USBEvent id={self.id} device_id={self.device_id} event_type={self.event_type} drive_letter={self.drive_letter}>"
