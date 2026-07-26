import uuid
from sqlalchemy import Column, String, Text, BigInteger, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class USBScanResult(Base):
    __tablename__ = "usb_scan_results"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    usb_event_id = Column(
        UUID(as_uuid=True),
        ForeignKey("usb_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    file_name = Column(String(255), nullable=False)
    full_path = Column(Text, nullable=False)
    extension = Column(String(50), nullable=True)
    file_size = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    is_hidden = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=True)
    modified_at = Column(DateTime(timezone=True), nullable=True)
    scanned_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    usb_event = relationship("USBEvent", back_populates="scan_results")

    def __repr__(self) -> str:
        return f"<USBScanResult id={self.id} file_name='{self.file_name}' sha256='{self.sha256}'>"
