from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel
from app.schemas.device import DeviceOut
from app.schemas.agent_command import AgentCommandOut


class FleetMetricsOut(BaseModel):
    total_agents: int
    online: int
    offline: int
    outdated: int
    unhealthy: int


class FleetSummaryOut(BaseModel):
    metrics: FleetMetricsOut
    recent_devices: List[DeviceOut]
    timestamp: datetime


class SynchronizationMetadata(BaseModel):
    last_heartbeat: Optional[datetime] = None
    last_checkin: Optional[datetime] = None
    last_telemetry_upload: Optional[datetime] = None
    last_policy_sync: Optional[datetime] = None


class AgentCollectorStatus(BaseModel):
    name: str
    enabled: bool
    status: str
    events_collected_24h: int


class AgentDiagnosticPackageOut(BaseModel):
    device_id: UUID
    hostname: str
    os_type: str
    operating_system: str
    agent_version: str
    policy_version: int
    health_status: str
    status: str
    generated_at: datetime

    configuration: Dict[str, Any]
    installed_collectors: List[AgentCollectorStatus]
    synchronization: SynchronizationMetadata
    last_commands: List[AgentCommandOut]
    last_errors: List[Dict[str, Any]]
    agent_logs: List[str]
