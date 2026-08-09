import uuid
from sqlalchemy import Column, String, BigInteger, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class FileIntegrityRecord(Base):
    __tablename__ = "file_integrity_records"

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
    file_path = Column(String(1024), nullable=False, index=True)
    file_name = Column(String(255), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    size = Column(BigInteger, default=0, nullable=False)
    last_modified = Column(DateTime(timezone=True), nullable=True)
    owner = Column(String(100), nullable=True)
    is_executable = Column(Boolean, default=False, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    device = relationship("Device", back_populates="file_integrity_records")

    def __repr__(self) -> str:
        return (
            f"<FileIntegrityRecord id={self.id} device_id={self.device_id} "
            f"path='{self.file_path}' sha256='{self.sha256}'>"
        )
