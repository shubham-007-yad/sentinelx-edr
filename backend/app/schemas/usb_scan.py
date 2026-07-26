from uuid import UUID
from datetime import datetime
from typing import Optional, List, Union
from pydantic import BaseModel, ConfigDict, Field


class USBScanResultBase(BaseModel):
    usb_event_id: UUID
    file_name: str
    full_path: str
    extension: Optional[str] = None
    file_size: int = Field(..., ge=0)
    sha256: str
    is_hidden: bool = False
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None


class USBScanResultCreate(USBScanResultBase):
    pass


class USBScanBatchCreate(BaseModel):
    usb_event_id: UUID
    files: List[USBScanResultCreate]


class USBScanResultOut(USBScanResultBase):
    id: UUID
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)
