from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict


class FileIntegrityRecordBase(BaseModel):
    file_path: str = Field(..., description="Absolute path of the monitored file")
    file_name: str = Field(..., description="Base name of the file")
    sha256: str = Field(..., description="SHA-256 hash of the file content")
    size: int = Field(0, description="File size in bytes")
    last_modified: Optional[datetime] = Field(None, description="Last modification timestamp")
    owner: Optional[str] = Field(None, description="File owner username or UID")
    is_executable: bool = Field(False, description="Flag indicating if file has executable permissions")


class FileIntegrityRecordCreate(FileIntegrityRecordBase):
    pass


class FileIntegrityRecordUpdate(BaseModel):
    sha256: Optional[str] = None
    size: Optional[int] = None
    last_modified: Optional[datetime] = None
    owner: Optional[str] = None
    is_executable: Optional[bool] = None


class FileIntegrityRecordOut(FileIntegrityRecordBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    created_at: datetime
    updated_at: datetime


class FileIntegrityBatchIngestRequest(BaseModel):
    records: List[FileIntegrityRecordCreate]


class FileChangeEventRequest(BaseModel):
    event_type: str = Field(..., description="Watcher event type: CREATED, MODIFIED, DELETED, RENAMED")
    file_path: str = Field(..., description="Absolute path of the changed file")
    file_name: str = Field(..., description="Base name of the file")
    old_path: Optional[str] = Field(None, description="Previous file path if RENAMED")
    sha256: str = Field("", description="Current SHA-256 hash")
    size: int = Field(0, description="Current byte size")
    is_executable: bool = Field(False, description="Whether file is executable")
    last_modified: Optional[str] = Field(None, description="ISO-8601 modification timestamp")
    owner: Optional[str] = Field(None, description="File owner")
    timestamp: Optional[str] = Field(None, description="Event observation timestamp")


class FileIntegrityEventOut(BaseModel):
    device_id: UUID
    file_path: str
    file_name: str
    event_type: str
    status: str  # CHANGED, UNCHANGED, NEW_FILE, DELETED
    is_changed: bool
    changes_detected: List[str]
    baseline_sha256: Optional[str] = None
    current_sha256: Optional[str] = None
    baseline_size: Optional[int] = None
    current_size: Optional[int] = None
    is_executable: bool = False
    details: str
    timestamp: datetime


class FIMResponseActionRequest(BaseModel):
    file_path: str = Field(..., description="Target file path for response action")
    action_type: str = Field(..., description="Action: RESTORE_BASELINE, QUARANTINE, IGNORE_CHANGE, ADD_ALLOWLIST, RECALCULATE_BASELINE")
    new_sha256: Optional[str] = Field(None, description="Optional new SHA-256 for recalculation")
    new_size: Optional[int] = Field(None, description="Optional new size")


class FIMResponseActionResponse(BaseModel):
    device_id: UUID
    file_path: str
    action_type: str
    status: str  # SUCCESS, FAILED
    message: str
    action_id: Optional[UUID] = None
    timestamp: datetime


class FIMTimelineItem(BaseModel):
    step: int
    timestamp: datetime
    event_type: str  # FILE_CREATED, SHA_CHANGED, ALERT_GENERATED, RESPONSE_EXECUTED, BASELINE_RESTORED
    title: str
    description: str
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    actor: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class FIMTimelineResponse(BaseModel):
    device_id: UUID
    file_path: str
    file_name: str
    current_sha256: str
    current_status: str
    timeline: List[FIMTimelineItem]
