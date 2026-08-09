from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class TimelineEventItem(BaseModel):
    event_id: str
    timestamp: datetime
    time_formatted: str
    correlation_id: str
    category: str  # USB, FILE_INTEGRITY, PROCESS, NETWORK, SECURITY_EVENT, THREAT, ALERT, RESPONSE
    title: str     # e.g., "USB inserted", "installer.exe detected", "Endpoint isolated"
    description: Optional[str] = None
    severity: str = "INFO"  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    source: Optional[str] = "SentinelX Telemetry Engine"
    device_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class UnifiedTimelineResponse(BaseModel):
    correlation_id: str
    total_events: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    timeline: List[TimelineEventItem]

    model_config = ConfigDict(from_attributes=True)


class SequenceEventItem(BaseModel):
    category: str
    title: str
    description: Optional[str] = None
    severity: str = "INFO"
    timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CorrelatedSequenceIngest(BaseModel):
    device_id: UUID
    correlation_id: Optional[str] = None
    events: List[SequenceEventItem]
