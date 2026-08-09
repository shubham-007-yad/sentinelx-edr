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
    SUSPICIOUS_POWERSHELL = "SUSPICIOUS_POWERSHELL"
    SUSPICIOUS_CMD = "SUSPICIOUS_CMD"
    LOLBIN_ABUSE = "LOLBIN_ABUSE"
    SUSPICIOUS_PROCESS_BEHAVIOR = "SUSPICIOUS_PROCESS_BEHAVIOR"
    SUSPICIOUS_NETWORK_PORT = "SUSPICIOUS_NETWORK_PORT"
    BLACK_LISTED_IP = "BLACK_LISTED_IP"
    EXCESSIVE_CONNECTIONS = "EXCESSIVE_CONNECTIONS"
    UNEXPECTED_INTERNET_ACCESS = "UNEXPECTED_INTERNET_ACCESS"
    C2_BEACONING = "C2_BEACONING"
    FIM_EXECUTABLE_IN_DOWNLOADS = "FIM_EXECUTABLE_IN_DOWNLOADS"
    FIM_DOUBLE_EXTENSION_MASQUERADE = "FIM_DOUBLE_EXTENSION_MASQUERADE"
    FIM_STARTUP_MODIFICATION = "FIM_STARTUP_MODIFICATION"
    FIM_MASS_FILE_MODIFICATION = "FIM_MASS_FILE_MODIFICATION"
    BRUTE_FORCE_AUTHENTICATION = "BRUTE_FORCE_AUTHENTICATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNAUTHORIZED_ACCOUNT_CREATION = "UNAUTHORIZED_ACCOUNT_CREATION"
    DEFENSE_EVASION_LOG_CLEARING = "DEFENSE_EVASION_LOG_CLEARING"
    SUSPICIOUS_RDP_LOGON = "SUSPICIOUS_RDP_LOGON"
    PERSISTENCE_SERVICE_CREATION = "PERSISTENCE_SERVICE_CREATION"
    RANSOMWARE_BEHAVIOR = "RANSOMWARE_BEHAVIOR"
    AGENT_HEALTH_ISSUE = "AGENT_HEALTH_ISSUE"



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
        nullable=True,
        index=True
    )
    threat_type = Column(
        Enum(ThreatType, native_enum=False, name="threattype"),
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
    alerts = relationship("Alert", back_populates="threat", cascade="all, delete-orphan")

    @property
    def file_name(self) -> str:
        return self.scan_result.file_name if self.scan_result else ""

    @property
    def full_path(self) -> str:
        return self.scan_result.full_path if self.scan_result else ""

    @property
    def sha256(self) -> str:
        return self.scan_result.sha256 if self.scan_result else ""

    def __repr__(self) -> str:
        return f"<Threat id={self.id} rule_name='{self.rule_name}' severity='{self.severity}'>"
