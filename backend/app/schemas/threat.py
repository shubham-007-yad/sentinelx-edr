from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from app.models.threat import ThreatSeverity, ThreatType, ThreatStatus


class ThreatBase(BaseModel):
    scan_result_id: UUID
    threat_type: ThreatType
    severity: ThreatSeverity
    rule_name: str
    description: str
    status: ThreatStatus = ThreatStatus.NEW


class ThreatRecordCreate(ThreatBase):
    pass


class ThreatRecordUpdateStatus(BaseModel):
    status: ThreatStatus


class ThreatRecordOut(ThreatBase):
    id: UUID
    detected_at: datetime
    file_name: Optional[str] = None
    full_path: Optional[str] = None
    sha256: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ThreatSeverityCount(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class ThreatStatsOut(BaseModel):
    total_threats: int
    open_threats: int
    resolved_threats: int
    false_positives: int
    quarantined: int
    severity_breakdown: ThreatSeverityCount
    threat_type_breakdown: Dict[str, int]
