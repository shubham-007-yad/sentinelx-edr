from uuid import UUID
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict, field_validator
from app.models.device import DeviceStatus, OSType


class DeviceBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[OSType] = OSType.LINUX
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    status: Optional[DeviceStatus] = DeviceStatus.OFFLINE
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
    status: Optional[DeviceStatus] = None
    is_active: Optional[bool] = None
    user_id: Optional[UUID] = None
    last_seen: Optional[datetime] = None

    @field_validator("status", mode="before")
    @classmethod
    def normalize_optional_status(cls, v: Union[str, DeviceStatus, None]) -> Optional[DeviceStatus]:
        if v is not None:
            return DeviceBase.normalize_status(v)
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
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
