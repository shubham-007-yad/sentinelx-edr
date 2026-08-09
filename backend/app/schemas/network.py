from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict


class NetworkConnectionCreate(BaseModel):
    pid: Optional[int] = Field(None, description="Process ID associated with socket")
    process_name: Optional[str] = Field(None, description="Process binary name")
    executable_path: Optional[str] = Field(None, description="Absolute executable path")
    local_ip: Optional[str] = Field(None, description="Local binding IP address")
    local_port: Optional[int] = Field(None, description="Local binding port")
    remote_ip: Optional[str] = Field(None, description="Remote destination IP address")
    remote_port: Optional[int] = Field(None, description="Remote destination port")
    protocol: str = Field("TCP", description="Transport protocol (TCP/UDP)")
    state: Optional[str] = Field("ESTABLISHED", description="Connection socket state (ESTABLISHED, LISTEN, etc.)")
    bytes_sent: Optional[int] = Field(0, description="Cumulative bytes sent")
    bytes_received: Optional[int] = Field(0, description="Cumulative bytes received")
    timestamp: Optional[datetime] = Field(None, description="Connection observation timestamp")


class NetworkConnectionBatchIngestRequest(BaseModel):
    connections: List[NetworkConnectionCreate] = Field(..., description="List of network connection inventory records")


class NetworkConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    process_id: Optional[UUID] = None
    threat_id: Optional[UUID] = None
    alert_id: Optional[UUID] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: str
    state: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    created_at: datetime
    updated_at: datetime


class NetworkStateChangeItem(BaseModel):
    connection: NetworkConnectionCreate = Field(..., description="Network connection details")
    old_state: str = Field(..., description="Previous socket state")
    new_state: str = Field(..., description="Updated socket state")


class NetworkEventDiffPayload(BaseModel):
    connected: List[NetworkConnectionCreate] = Field(default=[], description="Newly opened/connected sockets")
    disconnected: List[NetworkConnectionCreate] = Field(default=[], description="Closed/disconnected sockets")
    state_changed: List[NetworkStateChangeItem] = Field(default=[], description="Connections with state transitions")
    long_running: List[NetworkConnectionCreate] = Field(default=[], description="Long-lived active network sessions")
    total_active: int = Field(0, description="Total active connections in current snapshot")
    timestamp: Optional[str] = Field(None, description="Live event calculation timestamp")


class NetworkEventSummaryResponse(BaseModel):
    message: str
    connected_count: int
    disconnected_count: int
    state_changed_count: int
    long_running_count: int
    total_active: int


class NetworkCorrelatedPivotResponse(BaseModel):
    connection_id: UUID
    device_id: UUID
    device_hostname: Optional[str] = None
    device_ip: Optional[str] = None
    device_status: Optional[str] = None

    # Correlated Process Telemetry
    process_id: Optional[UUID] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    ppid: Optional[int] = None

    # Network Socket Telemetry
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: str
    state: Optional[str] = None

    # Correlated Threat & Alert Telemetry
    threat_id: Optional[UUID] = None
    threat_type: Optional[str] = None
    threat_severity: Optional[str] = None
    rule_name: Optional[str] = None
    threat_description: Optional[str] = None

    alert_id: Optional[UUID] = None
    alert_title: Optional[str] = None
    alert_message: Optional[str] = None
    alert_severity: Optional[str] = None
    alert_status: Optional[str] = None

    # Analyst Response Capabilities
    available_response_actions: List[str] = Field(
        default=["TERMINATE_PROCESS", "ISOLATE_DEVICE", "BLOCK_IP"],
        description="Response actions available for analyst pivot"
    )


class NetworkTimelineItem(BaseModel):
    timestamp: datetime
    time_formatted: str
    event_type: str = Field(..., description="PROCESS_STARTED, NETWORK_CONNECTED, DATA_TRANSFERRED, BEACON_DETECTED, ALERT_GENERATED, RESPONSE_EXECUTED")
    title: str
    description: str
    severity: str = Field("INFO", description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    icon: str = Field("⚡", description="Visual indicator emoji/icon")
    metadata: Optional[Dict[str, Any]] = None


class ConnectionTimelineResponse(BaseModel):
    connection_id: UUID
    device_id: UUID
    timeline: List[NetworkTimelineItem]
