"""
Scheduled Report Pydantic Schemas
"""

from typing import List, Optional
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from app.models.scheduled_report_config import ReportTypeEnum, ReportFrequencyEnum, ReportExportFormatEnum


class ScheduledReportCreate(BaseModel):
    title: str
    report_type: ReportTypeEnum = ReportTypeEnum.EXECUTIVE
    frequency: ReportFrequencyEnum = ReportFrequencyEnum.WEEKLY
    timeframe_days: int = 7
    export_format: ReportExportFormatEnum = ReportExportFormatEnum.PDF
    recipients: List[str] = []
    is_enabled: bool = True


class ScheduledReportUpdate(BaseModel):
    title: Optional[str] = None
    report_type: Optional[ReportTypeEnum] = None
    frequency: Optional[ReportFrequencyEnum] = None
    timeframe_days: Optional[int] = None
    export_format: Optional[ReportExportFormatEnum] = None
    recipients: Optional[List[str]] = None
    is_enabled: Optional[bool] = None


class ScheduledReportOut(BaseModel):
    id: UUID
    title: str
    report_type: ReportTypeEnum
    frequency: ReportFrequencyEnum
    timeframe_days: int
    export_format: ReportExportFormatEnum
    recipients: List[str]
    is_enabled: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
