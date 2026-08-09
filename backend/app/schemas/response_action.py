from datetime import datetime
from typing import Optional, List, Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from app.models.response_action import ResponseActionType, ResponseActionStatus


class ResponseAuditLogOut(BaseModel):
    id: UUID
    action_id: UUID
    timestamp: datetime
    stage: str
    actor: str
    message: str
    details: Optional[Any] = None

    model_config = ConfigDict(from_attributes=True)


class ResponseActionBase(BaseModel):
    alert_id: Optional[UUID] = None
    device_id: UUID
    action_type: ResponseActionType
    initiated_by: Optional[str] = "AUTOMATIC"


class ResponseActionCreate(ResponseActionBase):
    parameters: Optional[dict] = None


class ResponseActionUpdate(BaseModel):
    status: Optional[ResponseActionStatus] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None


class ResponseActionOut(BaseModel):
    id: UUID
    alert_id: Optional[UUID] = None
    device_id: UUID
    action_type: ResponseActionType
    status: ResponseActionStatus
    initiated_by: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    audit_logs: Optional[List[ResponseAuditLogOut]] = []

    model_config = ConfigDict(from_attributes=True)
