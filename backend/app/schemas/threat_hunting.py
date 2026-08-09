from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class ThreatHuntingQuery(BaseModel):
    query: Optional[str] = Field(None, description="Free text / keyword IOC search term")
    device_id: Optional[str] = Field(None, description="Filter by Device UUID")
    hostname: Optional[str] = Field(None, description="Filter by Device Hostname")
    username: Optional[str] = Field(None, description="Filter by User / Account name")
    process: Optional[str] = Field(None, description="Filter by Process name or cmdline (e.g. powershell.exe)")
    sha256: Optional[str] = Field(None, description="Filter by SHA-256 file hash")
    ip: Optional[str] = Field(None, description="Filter by source or destination IP address")
    domain: Optional[str] = Field(None, description="Filter by domain name or hostname")
    threat_type: Optional[str] = Field(None, description="Filter by threat type (e.g. DOUBLE_EXTENSION)")
    min_severity: Optional[str] = Field(None, description="Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)")
    correlation_id: Optional[str] = Field(None, description="Filter by Incident / Telemetry correlation_id")
    start_time: Optional[datetime] = Field(None, description="Filter events after start_time")
    end_time: Optional[datetime] = Field(None, description="Filter events before end_time")
    time_range_hours: Optional[float] = Field(None, description="Filter last N hours (e.g., 24.0 for Last 24 hours)")
    categories: Optional[List[str]] = Field(None, description="List of categories to search (USB, PROCESS, NETWORK, FIM, SECURITY_EVENT, THREAT, ALERT, RESPONSE)")
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class ThreatHuntMatch(BaseModel):
    event_id: str
    timestamp: datetime
    time_formatted: str
    category: str
    event_type: str
    severity: str
    title: str
    description: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    sha256: Optional[str] = None
    ip: Optional[str] = None
    correlation_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class ThreatHuntingResponse(BaseModel):
    total_matches: int
    applied_filters: Dict[str, Any]
    matches: List[ThreatHuntMatch]

    model_config = ConfigDict(from_attributes=True)
