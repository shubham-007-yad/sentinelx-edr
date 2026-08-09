import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class TelemetryCategory(str, Enum):
    USB = "USB"
    FILE_INTEGRITY = "FILE_INTEGRITY"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    SECURITY_EVENT = "SECURITY_EVENT"
    IOC_INTELLIGENCE = "IOC_INTELLIGENCE"
    RANSOMWARE = "RANSOMWARE"


class BaseTelemetryEvent(BaseModel):
    """
    Standardized internal telemetry event envelope emitted by agent collectors.
    """
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4, description="Unique Telemetry Event UUID")
    device_id: uuid.UUID = Field(..., description="Target Endpoint Device UUID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC Event Timestamp")
    category: TelemetryCategory = Field(..., description="Telemetry Collector Category")
    event_type: str = Field(..., description="Specific Event Type (e.g. USB_INSERTED, PROCESS_STARTED)")
    source: str = Field(..., description="Collector Agent Module (e.g. USBCollector, ProcessMonitor)")
    correlation_id: Optional[uuid.UUID] = Field(default_factory=uuid.uuid4, description="Incident / Lifecycle Correlation UUID")
    tenant_id: Optional[str] = Field(default="default_tenant", description="Multi-tenant Organization ID")
    schema_version: str = Field(default="1.0", description="Telemetry Envelope Schema Version")
    host_info: Dict[str, Any] = Field(default_factory=dict, description="Endpoint metadata (hostname, IP, OS)")

    payload: Dict[str, Any] = Field(default_factory=dict, description="Collector-specific telemetry data payload")




class TelemetryIngestBatchRequest(BaseModel):
    device_id: uuid.UUID
    events: list[BaseTelemetryEvent]
