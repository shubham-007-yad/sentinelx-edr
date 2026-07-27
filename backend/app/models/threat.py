import uuid
import enum
from sqlalchemy import Column, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class ThreatSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, enum.Enum):
    KNOWN_MALWARE = "KNOWN_MALWARE"
    DOUBLE_EXTENSION = "DOUBLE_EXTENSION"
    HIDDEN_EXECUTABLE = "HIDDEN_EXECUTABLE"
    AUTORUN_SCRIPT = "AUTORUN_SCRIPT"
    SUSPICIOUS_EXTENSION = "SUSPICIOUS_EXTENSION"
    ANOMALOUS_FILE = "ANOMALOUS_FILE"


class ThreatStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class Threat(Base):
    __tablename__ = "threats"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    scan_result_id = Column(
        UUID(as_uuid=True),
        ForeignKey("usb_scan_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    threat_type = Column(
        Enum(ThreatType, native_enum=True, name="threattype"),
        nullable=False,
        index=True
    )
    severity = Column(
        Enum(ThreatSeverity, native_enum=True, name="threatseverity"),
        nullable=False,
        index=True
    )
    rule_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(
        Enum(ThreatStatus, native_enum=True, name="threatstatus"),
        default=ThreatStatus.NEW,
        nullable=False,
        index=True
    )
    detected_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    scan_result = relationship("USBScanResult", back_populates="threats")

    def __repr__(self) -> str:
        return f"<Threat id={self.id} rule_name='{self.rule_name}' severity='{self.severity}'>"
