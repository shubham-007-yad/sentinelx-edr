from uuid import UUID
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict, field_validator
from app.models.device import DeviceStatus, OSType, HealthStatus, CommandStatus


class DeviceBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[OSType] = OSType.LINUX
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    applied_policy_version: Optional[int] = None
    policy_version: Optional[int] = None
    status: Optional[DeviceStatus] = DeviceStatus.ONLINE
    health_status: Optional[HealthStatus] = HealthStatus.HEALTHY
    last_command_status: Optional[CommandStatus] = CommandStatus.NONE
    cpu_usage_percent: Optional[float] = 0.0
    ram_usage_mb: Optional[float] = 0.0
    ram_usage_percent: Optional[float] = 0.0
    disk_usage_percent: Optional[float] = 0.0
    agent_uptime_seconds: Optional[int] = 0
    service_status: Optional[str] = "RUNNING"
    last_telemetry_upload: Optional[datetime] = None
    last_policy_sync: Optional[datetime] = None
    is_active: Optional[bool] = True
    user_id: Optional[UUID] = None

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, v: Union[str, DeviceStatus, None]) -> Optional[DeviceStatus]:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for s in DeviceStatus:
                if s.value == v_upper or s.name == v_upper:
                    return s
            raise ValueError(f"Invalid status: '{v}'. Must be one of: {[s.value for s in DeviceStatus]}")
        return v

    @field_validator("health_status", mode="before")
    @classmethod
    def normalize_health_status(cls, v: Union[str, HealthStatus, None]) -> Optional[HealthStatus]:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for hs in HealthStatus:
                if hs.value == v_upper or hs.name == v_upper:
                    return hs
            raise ValueError(f"Invalid health_status: '{v}'. Must be one of: {[hs.value for hs in HealthStatus]}")
        return v

    @field_validator("last_command_status", mode="before")
    @classmethod
    def normalize_command_status(cls, v: Union[str, CommandStatus, None]) -> Optional[CommandStatus]:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for cs in CommandStatus:
                if cs.value == v_upper or cs.name == v_upper:
                    return cs
            raise ValueError(f"Invalid command_status: '{v}'. Must be one of: {[cs.value for cs in CommandStatus]}")
        return v

    @field_validator("os_type", mode="before")
    @classmethod
    def normalize_os_type(cls, v: Union[str, OSType, None]) -> Optional[OSType]:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for o in OSType:
                if o.value == v_upper or o.name == v_upper:
                    return o
            raise ValueError(f"Invalid os_type: '{v}'. Must be one of: {[o.value for o in OSType]}")
        return v

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v_stripped = v.strip()
        if not v_stripped:
            raise ValueError("Hostname cannot be empty.")
        if len(v_stripped) > 255:
            raise ValueError("Hostname cannot exceed 255 characters.")
        return v_stripped


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[OSType] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    applied_policy_version: Optional[int] = None
    policy_version: Optional[int] = None
    status: Optional[DeviceStatus] = None
    health_status: Optional[HealthStatus] = None
    last_command_status: Optional[CommandStatus] = None
    cpu_usage_percent: Optional[float] = None
    ram_usage_mb: Optional[float] = None
    ram_usage_percent: Optional[float] = None
    disk_usage_percent: Optional[float] = None
    agent_uptime_seconds: Optional[int] = None
    service_status: Optional[str] = None
    last_telemetry_upload: Optional[datetime] = None
    last_policy_sync: Optional[datetime] = None
    is_active: Optional[bool] = None
    user_id: Optional[UUID] = None
    last_seen: Optional[datetime] = None
    last_checkin: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None

    @field_validator("status", mode="before")
    @classmethod
    def normalize_optional_status(cls, v: Union[str, DeviceStatus, None]) -> Optional[DeviceStatus]:
        if v is not None:
            return DeviceBase.normalize_status(v)
        return v

    @field_validator("health_status", mode="before")
    @classmethod
    def normalize_optional_health_status(cls, v: Union[str, HealthStatus, None]) -> Optional[HealthStatus]:
        if v is not None:
            return DeviceBase.normalize_health_status(v)
        return v

    @field_validator("last_command_status", mode="before")
    @classmethod
    def normalize_optional_command_status(cls, v: Union[str, CommandStatus, None]) -> Optional[CommandStatus]:
        if v is not None:
            return DeviceBase.normalize_command_status(v)
        return v

    @field_validator("os_type", mode="before")
    @classmethod
    def normalize_optional_os_type(cls, v: Union[str, OSType, None]) -> Optional[OSType]:
        if v is not None:
            return DeviceBase.normalize_os_type(v)
        return v

    @field_validator("hostname")
    @classmethod
    def validate_optional_hostname(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return DeviceBase.validate_hostname(v)
        return v


class DeviceOut(DeviceBase):
    id: UUID
    operating_system: Optional[str] = None
    last_seen: Optional[datetime] = None
    last_checkin: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeviceHeartbeatRequest(BaseModel):
    device_id: UUID
    ip_address: Optional[str] = None
    agent_version: Optional[str] = None
    applied_policy_version: Optional[int] = None
    policy_version: Optional[int] = None
    status: Optional[DeviceStatus] = DeviceStatus.ONLINE
    health_status: Optional[HealthStatus] = None
    last_command_status: Optional[CommandStatus] = None
    cpu_usage_percent: Optional[float] = None
    ram_usage_mb: Optional[float] = None
    ram_usage_percent: Optional[float] = None
    disk_usage_percent: Optional[float] = None
    agent_uptime_seconds: Optional[int] = None
    service_status: Optional[str] = None
    last_telemetry_upload: Optional[datetime] = None
    last_policy_sync: Optional[datetime] = None

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, v: Union[str, DeviceStatus, None]) -> Optional[DeviceStatus]:
        if v is not None:
            return DeviceBase.normalize_status(v)
        return DeviceStatus.ONLINE


class DeviceHeartbeatResponse(BaseModel):
    message: str = "Heartbeat received"
    device_id: UUID
    status: DeviceStatus
    health_status: HealthStatus = HealthStatus.HEALTHY
    last_seen: datetime
    last_heartbeat: datetime

    model_config = ConfigDict(from_attributes=True)


class AgentHealthReportRequest(BaseModel):
    device_id: UUID
    cpu_usage_percent: float = 0.0
    ram_usage_mb: float = 0.0
    ram_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    agent_uptime_seconds: int = 0
    service_status: str = "RUNNING"
    last_telemetry_upload: Optional[datetime] = None
    last_policy_sync: Optional[datetime] = None
    policy_version: Optional[int] = None
    agent_version: Optional[str] = None

