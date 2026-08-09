from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.models.device import Device
from app.schemas.process import (
    ProcessInfoCreate, ProcessBatchIngestRequest, ProcessInfoOut,
    ProcessEventDiffPayload, ProcessEventSummaryResponse, ProcessAuditLogOut
)
from app.schemas.security_policy import ProcessPolicyConfigSchema, SecurityPolicyCreate
from app.services import process_service, device_service
from app.services.policy_service import PolicyService
from app.models.security_policy import PolicyCategory

router = APIRouter(prefix="/processes", tags=["Processes"])


# ==================== PROCESS SECURITY POLICY ====================

@router.get(
    "/policy",
    response_model=ProcessPolicyConfigSchema,
    status_code=status.HTTP_200_OK,
    summary="Get active Process Security Policy",
    description="Retrieves the active process security policy configuration enforced across endpoints."
)
def get_process_security_policy(db: Session = Depends(get_db)):
    """
    Get active process security policy settings.
    """
    return PolicyService.get_active_process_policy(db=db)


@router.put(
    "/policy",
    response_model=ProcessPolicyConfigSchema,
    status_code=status.HTTP_200_OK,
    summary="Update Process Security Policy",
    description="Updates or creates central Process security policy configuration."
)
def update_process_security_policy(
    policy_in: ProcessPolicyConfigSchema,
    db: Session = Depends(get_db)
):
    """
    Update active process security policy settings.
    """
    active_policies = PolicyService.get_policies(db=db, category=PolicyCategory.PROCESS, enabled_only=True)
    if active_policies:
        active_policy = active_policies[0]
        updated = PolicyService.update_policy(
            db=db,
            policy_id=str(active_policy.id),
            payload=SecurityPolicyCreate(
                policy_name=active_policy.policy_name,
                category=PolicyCategory.PROCESS,
                version=active_policy.version,
                enabled=True,
                priority=active_policy.priority,
                configuration=policy_in.model_dump(),
                created_by="Admin"
            )
        )
        return updated.configuration
    else:
        created = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Central Process Security Policy",
                category=PolicyCategory.PROCESS,
                version=1,
                enabled=True,
                priority=100,
                configuration=policy_in.model_dump(),
                created_by="Admin"
            )
        )
        return created.configuration



@router.get(
    "/audit-logs",
    response_model=List[ProcessAuditLogOut],
    status_code=status.HTTP_200_OK,
    summary="List process audit event history",
    description="Retrieves historical process audit logs (started, terminated, response actions, detection findings)."
)
def list_process_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_id: Optional[UUID] = Query(None, description="Filter by Device UUID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    pid: Optional[int] = Query(None, description="Filter by PID"),
    process_name: Optional[str] = Query(None, description="Filter by process name"),
    db: Session = Depends(get_db)
):
    return process_service.get_process_audit_logs(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        event_type=event_type,
        pid=pid,
        process_name=process_name
    )


@router.post(
    "/{device_id}",
    response_model=List[ProcessInfoOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest process inventory snapshot",
    description="Ingests continuous running process inventory snapshot for a managed endpoint device."
)
def ingest_device_processes(
    device_id: UUID,
    payload: ProcessBatchIngestRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    processes = process_service.ingest_processes(
        db=db,
        device_id=device_id,
        processes_in=payload.processes
    )
    return processes


@router.post(
    "/events/{device_id}",
    response_model=ProcessEventSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest live process diff telemetry",
    description="Processes real-time process diff events (created, terminated, long-running)."
)
def ingest_live_process_events(
    device_id: UUID,
    payload: ProcessEventDiffPayload,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return process_service.process_live_events(
        db=db,
        device_id=device_id,
        events=payload
    )


@router.get(
    "",
    response_model=List[ProcessInfoOut],
    status_code=status.HTTP_200_OK,
    summary="List all running processes",
    description="Retrieves running process telemetry across endpoints with optional filtering."
)
def list_processes(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_id: Optional[UUID] = Query(None, description="Filter processes by Device UUID"),
    name: Optional[str] = Query(None, description="Filter process by executable/binary name"),
    db: Session = Depends(get_db)
):
    return process_service.get_all_processes(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        name=name
    )
