"""
Executive Reporting & Security Analytics Pydantic Schemas
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ExecutiveTopMetricsOut(BaseModel):
    total_endpoints: int
    online_endpoints: int
    total_incidents: int
    critical_incidents: int
    threats_today: int
    alerts_today: int
    responses_executed: int
    average_response_time_minutes: float

    model_config = ConfigDict(from_attributes=True)


class ExecutiveDashboardSummaryOut(BaseModel):
    top_metrics: ExecutiveTopMetricsOut
    posture: Dict[str, Any]
    alerts_by_severity: Dict[str, int]
    alerts_by_status: Dict[str, int]
    incident_velocity: Dict[str, Any]
    sla_performance: Dict[str, Any]
    top_risk_endpoints: List[Dict[str, Any]]
    mitre_summary: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class EndpointRiskScoreOut(BaseModel):
    device_id: str
    hostname: str
    ip_address: Optional[str] = None
    status: str
    os_type: str
    risk_score: float
    risk_level: str
    active_alerts_count: int
    unresolved_threats: int
    alert_breakdown: Dict[str, int]
    contributing_factors: Optional[List[Dict[str, Any]]] = None
    recommended_actions: Optional[List[str]] = None
    last_seen: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class MitreAttackAnalyticsOut(BaseModel):
    timeframe_days: int
    total_observed_threats: int
    tactics_breakdown: List[Dict[str, Any]]
    top_techniques: List[Dict[str, Any]]

    model_config = ConfigDict(from_attributes=True)


class IncidentTrendsOut(BaseModel):
    daily_trends: List[Dict[str, Any]]
    velocity: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class ResponsePerformanceOut(BaseModel):
    mtta_minutes: float
    mttr_minutes: float
    mtta_sla_compliance_percent: float
    mttr_sla_compliance_percent: float
    acknowledged_count: int
    responded_count: int

    model_config = ConfigDict(from_attributes=True)
