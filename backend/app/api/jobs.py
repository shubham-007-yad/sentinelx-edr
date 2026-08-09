from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_admin, get_current_analyst, get_current_viewer
from app.models.user import User
from app.core.job_queue import enqueue_job, get_job, list_recent_jobs
from app.core.rate_limiter import rate_limit_commands, rate_limit_telemetry

router = APIRouter(prefix="/jobs", tags=["Background Jobs & Task Queue"])

class JobEnqueueResponse(BaseModel):
    job_id: str
    task_name: str
    queue_name: str
    status: str
    created_at: str

class ReportJobRequest(BaseModel):
    config_id: Optional[str] = None
    report_type: str = Field("executive", description="executive or technical")
    timeframe_days: int = Field(7, ge=1, le=365)
    export_format: str = Field("JSON", description="JSON, PDF, or CSV")

class FleetCommandJobRequest(BaseModel):
    device_id: Optional[str] = None
    target_scope: str = Field("all", description="all, group, or single")
    command_type: str = Field("HEALTH_CHECK", description="HEALTH_CHECK, ISOLATE, AGENT_UPDATE, KILL_PROCESS")
    parameters: Dict[str, Any] = Field(default_factory=dict)

class BulkPolicyJobRequest(BaseModel):
    policy_id: str
    device_ids: List[str] = Field(default_factory=list)

class TelemetryBatchJobRequest(BaseModel):
    telemetry_logs: List[Dict[str, Any]]

class ScheduledAnalyticsJobRequest(BaseModel):
    timeframe_days: int = Field(30, ge=1, le=365)

@router.post("/reports/generate", response_model=JobEnqueueResponse, status_code=status.HTTP_202_ACCEPTED)
def enqueue_report_job(req: ReportJobRequest, user: User = Depends(get_current_analyst)):
    job = enqueue_job("reports", "generate_report", req.model_dump(), created_by=user.username)
    return job

@router.post("/fleet/command", response_model=JobEnqueueResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(rate_limit_commands)])
def enqueue_fleet_command_job(req: FleetCommandJobRequest, admin: User = Depends(get_current_admin)):
    payload = req.model_dump()
    payload["issued_by"] = admin.username
    job = enqueue_job("fleet", "bulk_fleet_command", payload, created_by=admin.username)
    return job

@router.post("/policies/distribute", response_model=JobEnqueueResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(rate_limit_commands)])
def enqueue_policy_distribution_job(req: BulkPolicyJobRequest, admin: User = Depends(get_current_admin)):
    job = enqueue_job("policies", "bulk_policy_distribution", req.model_dump(), created_by=admin.username)
    return job

@router.post("/telemetry/process", response_model=JobEnqueueResponse, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(rate_limit_telemetry)])
def enqueue_telemetry_batch_job(req: TelemetryBatchJobRequest, user: User = Depends(get_current_analyst)):
    job = enqueue_job("telemetry", "process_telemetry_batch", req.model_dump(), created_by=user.username)
    return job

@router.post("/analytics/run", response_model=JobEnqueueResponse, status_code=status.HTTP_202_ACCEPTED)
def enqueue_scheduled_analytics_job(req: ScheduledAnalyticsJobRequest, user: User = Depends(get_current_analyst)):
    job = enqueue_job("analytics", "scheduled_analytics", req.model_dump(), created_by=user.username)
    return job

@router.get("", response_model=List[Dict[str, Any]])
def list_jobs(user: User = Depends(get_current_viewer)):
    return list_recent_jobs(limit=50)

@router.get("/{job_id}", response_model=Dict[str, Any])
def get_job_status_and_result(job_id: str, user: User = Depends(get_current_viewer)):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job
