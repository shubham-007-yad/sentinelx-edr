"""
Scheduled Report Configuration Database Model
"""

import uuid
import enum
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Enum as SQLEnum, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from app.db.database import Base


class ReportTypeEnum(str, enum.Enum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"
    COMPLIANCE = "COMPLIANCE"


class ReportFrequencyEnum(str, enum.Enum):
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"


class ReportExportFormatEnum(str, enum.Enum):
    PDF = "PDF"
    CSV = "CSV"
    JSON = "JSON"


class ScheduledReportConfig(Base):
    __tablename__ = "scheduled_report_configs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False
    )
    title = Column(String(255), nullable=False, index=True)
    report_type = Column(
        SQLEnum(ReportTypeEnum, native_enum=False, name="reporttypeenum"),
        default=ReportTypeEnum.EXECUTIVE,
        nullable=False,
        index=True
    )
    frequency = Column(
        SQLEnum(ReportFrequencyEnum, native_enum=False, name="reportfrequencyenum"),
        default=ReportFrequencyEnum.WEEKLY,
        nullable=False,
        index=True
    )
    timeframe_days = Column(Integer, default=7, nullable=False)
    export_format = Column(
        SQLEnum(ReportExportFormatEnum, native_enum=False, name="reportexportformatenum"),
        default=ReportExportFormatEnum.PDF,
        nullable=False
    )
    recipients = Column(JSONB, default=[], nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False, index=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(255), default="admin", nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<ScheduledReportConfig id={self.id} title='{self.title}' frequency='{self.frequency}'>"
