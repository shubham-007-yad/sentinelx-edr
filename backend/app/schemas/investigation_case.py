from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field
from app.models.investigation_case import CaseSeverity, CaseStatus


class CaseNoteCreate(BaseModel):
    author: Optional[str] = "Analyst"
    note_text: str


class CaseNoteOut(BaseModel):
    id: UUID
    case_id: UUID
    author: str
    note_text: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseEvidenceCreate(BaseModel):
    evidence_type: str = "IOC_OR_ARTIFACT"
    title: str
    description: Optional[str] = None
    file_path_or_hash: Optional[str] = None
    added_by: Optional[str] = "Analyst"


class CaseEvidenceOut(BaseModel):
    id: UUID
    case_id: UUID
    evidence_type: str
    title: str
    description: Optional[str] = None
    file_path_or_hash: Optional[str] = None
    added_by: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LinkAlertsPayload(BaseModel):
    alert_ids: List[str]


class LinkTelemetryPayload(BaseModel):
    telemetry_ids: List[str]


class InvestigationCaseBase(BaseModel):
    title: str
    severity: CaseSeverity = CaseSeverity.MEDIUM
    status: CaseStatus = CaseStatus.OPEN
    assigned_to: Optional[str] = None
    correlation_id: Optional[str] = None
    summary: Optional[str] = None


class InvestigationCaseCreate(InvestigationCaseBase):
    pass


class InvestigationCaseUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[CaseSeverity] = None
    status: Optional[CaseStatus] = None
    assigned_to: Optional[str] = None
    correlation_id: Optional[str] = None
    summary: Optional[str] = None
    closed_at: Optional[datetime] = None


class InvestigationCaseOut(InvestigationCaseBase):
    id: UUID
    linked_alert_ids: List[str] = Field(default_factory=list)
    linked_telemetry_ids: List[str] = Field(default_factory=list)
    notes: List[CaseNoteOut] = Field(default_factory=list)
    evidence_items: List[CaseEvidenceOut] = Field(default_factory=list)
    created_at: datetime
    closed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
