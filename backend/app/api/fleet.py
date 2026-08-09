from uuid import UUID
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_admin, get_current_analyst, get_current_viewer, get_current_active_user
from app.models.device import DeviceStatus, HealthStatus, OSType
from app.models.user import User
from app.schemas.device import DeviceOut, AgentHealthReportRequest
from app.schemas.fleet import FleetMetricsOut, FleetSummaryOut, AgentDiagnosticPackageOut
from app.schemas.agent_command import (
    AgentCommandCreate, AgentCommandBatchRequest, AgentCommandAcknowledgeRequest,
    AgentCommandOut, AgentCommandAuditLogOut
)
from app.schemas.agent_upgrade import (
    AgentUpgradeTriggerRequest, AgentUpgradeRollbackRequest, AgentUpgradeRecordOut
)
from app.services import fleet_service, agent_health_service, agent_command_service, agent_upgrade_service
from app.core.rate_limiter import rate_limit_commands, rate_limit_telemetry

router = APIRouter(prefix="/fleet", tags=["Fleet Management"])


@router.get(
    "/metrics",
    response_model=FleetMetricsOut,
    status_code=status.HTTP_200_OK,
    summary="Get Fleet Overview Metrics",
    description="Retrieves aggregate metrics for all managed agents across the enterprise fleet."
)
def get_fleet_metrics(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    return fleet_service.get_fleet_metrics(db=db)


@router.get(
    "/devices",
    response_model=List[DeviceOut],
    status_code=status.HTTP_200_OK,
    summary="Get Fleet Device Inventory",
    description="Retrieves paginated fleet device inventory with operational metadata."
)
def get_fleet_devices(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    status: Optional[DeviceStatus] = Query(None, description="Filter by device status"),
    health_status: Optional[HealthStatus] = Query(None, description="Filter by health status"),
    os_type: Optional[OSType] = Query(None, description="Filter by operating system type"),
    version: Optional[str] = Query(None, description="Filter by agent version"),
    policy: Optional[int] = Query(None, description="Filter by policy version"),
    search: Optional[str] = Query(None, description="Search query by hostname, IP address, or agent version"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    return fleet_service.get_fleet_inventory(
        db=db,
        skip=skip,
        limit=limit,
        status=status,
        health_status=health_status,
        os_type=os_type,
        agent_version=version,
        policy_version=policy,
        search=search
    )


@router.get(
    "/summary",
    response_model=FleetSummaryOut,
    status_code=status.HTTP_200_OK,
    summary="Get Fleet Inventory Summary"
)
def get_fleet_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    return fleet_service.get_fleet_summary(db=db)


@router.get(
    "/export",
    status_code=status.HTTP_200_OK,
    summary="Export Fleet Inventory CSV"
)
def export_fleet_inventory(
    device_ids: Optional[str] = Query(None, description="Comma-separated UUID strings of devices to export"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    from fastapi.responses import Response
    ids_list = [d.strip() for d in device_ids.split(",") if d.strip()] if device_ids else None
    csv_content = fleet_service.export_fleet_inventory_csv(db=db, device_ids=ids_list)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=sentinelx_fleet_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        }
    )


@router.get(
    "/devices/{device_id}/diagnostics",
    response_model=AgentDiagnosticPackageOut,
    status_code=status.HTTP_200_OK,
    summary="Get Agent Diagnostic Package"
)
def get_agent_diagnostics(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    return fleet_service.generate_agent_diagnostic_package(db=db, device_id=device_id)


@router.get(
    "/devices/{device_id}/diagnostics/download",
    status_code=status.HTTP_200_OK,
    summary="Download Agent Diagnostic Bundle (JSON)"
)
def download_agent_diagnostics(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    from fastapi.responses import Response
    diag_data = fleet_service.generate_agent_diagnostic_package(db=db, device_id=device_id)
    json_str = diag_data.model_dump_json(indent=2)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=sentinelx_agent_diagnostics_{device_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        }
    )


@router.post(
    "/health/report",
    response_model=DeviceOut,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_telemetry)],
    summary="Ingest Agent Health Telemetry Report"
)
def ingest_agent_health_report(
    report: AgentHealthReportRequest,
    db: Session = Depends(get_db)
):
    try:
        return agent_health_service.ingest_agent_health_report(db=db, report=report)
    except ValueError as val_err:
        raise HTTPException(status_code=404, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Failed to ingest agent health report: {str(err)}")


@router.post(
    "/health/evaluate",
    status_code=status.HTTP_200_OK,
    summary="Run Fleet-Wide Health Evaluation"
)
def evaluate_fleet_health(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    return agent_health_service.evaluate_all_fleet_health(db=db)


# ----------------------------------------------------
# Remote Command Center Endpoints
# ----------------------------------------------------

@router.post(
    "/commands",
    response_model=AgentCommandOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_commands)],
    summary="Issue Remote Agent Command (Admin Only)"
)
def queue_remote_command(
    command_in: AgentCommandCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    try:
        return agent_command_service.queue_command(
            db=db,
            device_id=command_in.device_id,
            command_type=command_in.command_type,
            payload=command_in.payload,
            issuer=admin
        )
    except ValueError as val_err:
        raise HTTPException(status_code=404, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Failed to queue command: {str(err)}")


@router.post(
    "/commands/batch",
    response_model=List[AgentCommandOut],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_commands)],
    summary="Issue Batch Remote Agent Commands (Admin Only)"
)
def queue_batch_remote_commands(
    batch_in: AgentCommandBatchRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    return agent_command_service.queue_batch_commands(
        db=db,
        device_ids=batch_in.device_ids,
        command_type=batch_in.command_type,
        payload=batch_in.payload,
        issuer=admin
    )


@router.get(
    "/commands/pending/{device_id}",
    response_model=List[AgentCommandOut],
    status_code=status.HTTP_200_OK,
    summary="Poll Pending Agent Commands"
)
def poll_pending_commands(
    device_id: UUID,
    db: Session = Depends(get_db)
):
    return agent_command_service.get_pending_commands_for_device(db=db, device_id=device_id)


@router.post(
    "/commands/acknowledge",
    response_model=AgentCommandOut,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_commands)],
    summary="Acknowledge Remote Command Execution"
)
def acknowledge_command_execution(
    ack_in: AgentCommandAcknowledgeRequest,
    db: Session = Depends(get_db)
):
    try:
        return agent_command_service.acknowledge_command(db=db, ack_in=ack_in)
    except ValueError as val_err:
        raise HTTPException(status_code=404, detail=str(val_err))
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Failed to acknowledge command: {str(err)}")


@router.get(
    "/commands/history",
    response_model=List[AgentCommandOut],
    status_code=status.HTTP_200_OK,
    summary="Get Remote Command History"
)
def get_command_history(
    device_id: Optional[UUID] = Query(None, description="Filter history by target device UUID"),
    skip: int = Query(0, ge=0, description="Items to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    return agent_command_service.get_command_history(db=db, device_id=device_id, skip=skip, limit=limit)


@router.get(
    "/commands/audit-logs",
    response_model=List[AgentCommandAuditLogOut],
    status_code=status.HTTP_200_OK,
    summary="Get Remote Command Audit Logs"
)
def get_command_audit_logs(
    device_id: Optional[UUID] = Query(None, description="Filter audit logs by target device UUID"),
    skip: int = Query(0, ge=0, description="Items to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items to return"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    return agent_command_service.get_command_audit_logs(db=db, device_id=device_id, skip=skip, limit=limit)


# --------------------------------------------------------------------------
# Agent Upgrade Framework Endpoints
# --------------------------------------------------------------------------

@router.post(
    "/upgrade/trigger",
    response_model=List[AgentUpgradeRecordOut],
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Agent Version Upgrade (Admin Only)"
)
def trigger_agent_upgrade(
    req: AgentUpgradeTriggerRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    return agent_upgrade_service.trigger_agent_upgrades(
        db=db,
        device_ids=req.device_ids,
        target_version=req.target_version
    )


@router.post(
    "/upgrade/step",
    response_model=AgentUpgradeRecordOut,
    status_code=status.HTTP_200_OK,
    summary="Advance Agent Upgrade Simulation Step"
)
def advance_upgrade_step(
    upgrade_id: UUID = Query(..., description="Agent Upgrade record UUID"),
    db: Session = Depends(get_db)
):
    return agent_upgrade_service.advance_upgrade_simulation_step(db=db, upgrade_id=upgrade_id)


@router.post(
    "/upgrade/rollback",
    response_model=AgentUpgradeRecordOut,
    status_code=status.HTTP_200_OK,
    summary="Rollback Agent Upgrade (Admin Only)"
)
def rollback_agent_upgrade(
    req: AgentUpgradeRollbackRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    return agent_upgrade_service.rollback_agent_upgrade(
        db=db,
        upgrade_id=req.upgrade_id,
        target_rollback_version=req.target_rollback_version
    )


@router.get(
    "/upgrade/history",
    response_model=List[AgentUpgradeRecordOut],
    status_code=status.HTTP_200_OK,
    summary="Get Fleet Agent Upgrade History"
)
def get_upgrade_history(
    device_id: Optional[UUID] = Query(None, description="Filter upgrade history by device UUID"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    return agent_upgrade_service.get_upgrade_records(db=db, device_id=device_id, limit=limit)
