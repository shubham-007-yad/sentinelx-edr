from uuid import UUID
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.models.agent_command import AgentCommandType, AgentCommandStatus


class AgentCommandCreate(BaseModel):
    device_id: UUID
    command_type: AgentCommandType
    payload: Optional[Dict[str, Any]] = None


class AgentCommandBatchRequest(BaseModel):
    device_ids: List[UUID]
    command_type: AgentCommandType
    payload: Optional[Dict[str, Any]] = None


class AgentCommandAcknowledgeRequest(BaseModel):
    command_id: UUID
    status: AgentCommandStatus = AgentCommandStatus.SUCCESS
    result_output: Optional[str] = None
    error_message: Optional[str] = None
    execution_duration_ms: Optional[int] = None


class AgentCommandOut(BaseModel):
    id: UUID
    device_id: UUID
    issuer_id: Optional[UUID] = None
    command_type: AgentCommandType
    status: AgentCommandStatus
    payload: Optional[Dict[str, Any]] = None
    result_output: Optional[str] = None
    error_message: Optional[str] = None
    execution_duration_ms: Optional[int] = None
    queued_at: datetime
    dispatched_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AgentCommandAuditLogOut(BaseModel):
    id: UUID
    command_id: UUID
    device_id: UUID
    issuer_username: str
    command_type: str
    status: str
    details: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
