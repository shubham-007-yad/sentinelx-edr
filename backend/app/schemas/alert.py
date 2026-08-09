from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from app.models.alert import AlertSeverity, AlertStatus


class AlertOut(BaseModel):
    id: UUID
    threat_id: UUID
    device_id: UUID
    title: str
    message: str
    severity: AlertSeverity
    status: AlertStatus
    created_at: datetime
    read_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    device: Optional[str] = None
    file: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UnreadCountOut(BaseModel):
    unread_count: int


class AlertBulkActionInput(BaseModel):
    alert_ids: List[UUID]
