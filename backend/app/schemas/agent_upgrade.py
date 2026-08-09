from uuid import UUID
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.models.agent_upgrade import AgentUpgradeStatus, RollbackStatus


class AgentUpgradeTriggerRequest(BaseModel):
    device_ids: List[UUID]
    target_version: str = "1.2.0"


class AgentUpgradeStepUpdateRequest(BaseModel):
    upgrade_id: UUID
    status: AgentUpgradeStatus
    progress_percent: int
    log_entry: Optional[str] = None
    error_message: Optional[str] = None


class AgentUpgradeRollbackRequest(BaseModel):
    upgrade_id: UUID
    target_rollback_version: Optional[str] = None


class AgentUpgradeRecordOut(BaseModel):
    id: UUID
    device_id: UUID
    current_version: str
    target_version: str
    status: AgentUpgradeStatus
    rollback_status: RollbackStatus
    progress_percent: int
    logs: Optional[str] = None
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
