from datetime import datetime
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict


class ProcessInfoCreate(BaseModel):
    pid: int = Field(..., description="Process ID")
    ppid: Optional[int] = Field(None, description="Parent Process ID")
    name: str = Field(..., description="Process binary name")
    exe_path: Optional[str] = Field(None, description="Absolute executable file path")
    username: Optional[str] = Field(None, description="User executing the process")
    cpu_percent: Optional[float] = Field(0.0, description="CPU usage percentage")
    memory_percent: Optional[float] = Field(0.0, description="Memory usage percentage")
    start_time: Optional[str] = Field(None, description="Human readable or raw start time string")
    started_at: Optional[datetime] = Field(None, description="ISO timestamp of process creation")
    cmdline: Optional[str] = Field(None, description="Command line arguments string")


class ProcessBatchIngestRequest(BaseModel):
    processes: List[ProcessInfoCreate] = Field(..., description="List of process inventory records")


class ProcessInfoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    pid: int
    ppid: Optional[int] = None
    name: str
    exe_path: Optional[str] = None
    username: Optional[str] = None
    cpu_percent: Optional[float] = 0.0
    memory_percent: Optional[float] = 0.0
    start_time: Optional[str] = None
    started_at: Optional[datetime] = None
    cmdline: Optional[str] = None
    captured_at: datetime


class ProcessEventDiffPayload(BaseModel):
    created: List[ProcessInfoCreate] = Field(default=[], description="Newly detected processes")
    terminated: List[ProcessInfoCreate] = Field(default=[], description="Terminated processes")
    long_running: List[ProcessInfoCreate] = Field(default=[], description="Long-running active processes")
    total_active: int = Field(0, description="Total count of active running processes")
    timestamp: Optional[str] = Field(None, description="Event diff timestamp")


class ProcessEventSummaryResponse(BaseModel):
    message: str
    created_count: int
    terminated_count: int
    long_running_count: int
    total_active: int


class ProcessAuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    pid: int
    ppid: Optional[int] = None
    process_name: str
    event_type: str
    details: Optional[str] = None
    timestamp: datetime

