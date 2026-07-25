from uuid import UUID
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict, field_validator
from app.models.usb_event import USBEventType


class USBEventBase(BaseModel):
    device_id: UUID
    event_type: USBEventType
    drive_letter: Optional[str] = None
    volume_label: Optional[str] = None
    filesystem: Optional[str] = None
    total_size: Optional[int] = None
    free_space: Optional[int] = None
    serial_number: Optional[str] = None
    detected_at: Optional[datetime] = None

    @field_validator("event_type", mode="before")
    @classmethod
    def normalize_event_type(cls, v: Union[str, USBEventType, None]) -> USBEventType:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for e in USBEventType:
                if e.value == v_upper or e.name == v_upper:
                    return e
            raise ValueError(f"Invalid event_type: '{v}'. Must be one of: {[e.value for e in USBEventType]}")
        if isinstance(v, USBEventType):
            return v
        raise ValueError("event_type is required.")


class USBEventCreate(USBEventBase):
    pass


class USBEventOut(USBEventBase):
    id: UUID
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)
