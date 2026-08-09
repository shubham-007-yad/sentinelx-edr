from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.file_integrity import (
    FileIntegrityRecordOut, FileIntegrityBatchIngestRequest,
    FileChangeEventRequest, FileIntegrityEventOut,
    FIMResponseActionRequest, FIMResponseActionResponse,
    FIMTimelineResponse
)
from app.schemas.security_policy import FIMPolicyConfigSchema, SecurityPolicyCreate
from app.services import file_integrity_service, device_service
from app.services.policy_service import PolicyService
from app.models.security_policy import PolicyCategory

router = APIRouter(prefix="/fim", tags=["File Integrity Monitoring"])


# ==================== FIM SECURITY POLICY ====================

@router.get(
    "/policy",
    response_model=FIMPolicyConfigSchema,
    status_code=status.HTTP_200_OK,
    summary="Get active FIM & Ransomware Security Policy",
    description="Retrieves the active File Integrity Monitoring and Ransomware policy configuration enforced across endpoints."
)
def get_fim_security_policy(db: Session = Depends(get_db)):
    """
    Get active FIM security policy settings.
    """
    return PolicyService.get_active_fim_policy(db=db)


@router.put(
    "/policy",
    response_model=FIMPolicyConfigSchema,
    status_code=status.HTTP_200_OK,
    summary="Update FIM & Ransomware Security Policy",
    description="Updates or creates central File Integrity Monitoring and Ransomware security policy configuration."
)
def update_fim_security_policy(
    policy_in: FIMPolicyConfigSchema,
    db: Session = Depends(get_db)
):
    """
    Update active FIM security policy settings.
    """
    active_policies = PolicyService.get_policies(db=db, category=PolicyCategory.FIM, enabled_only=True)
    if active_policies:
        active_policy = active_policies[0]
        updated = PolicyService.update_policy(
            db=db,
            policy_id=str(active_policy.id),
            payload=SecurityPolicyCreate(
                policy_name=active_policy.policy_name,
                category=PolicyCategory.FIM,
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
                policy_name="Central File Integrity & Ransomware Security Policy",
                category=PolicyCategory.FIM,
                version=1,
                enabled=True,
                priority=100,
                configuration=policy_in.model_dump(),
                created_by="Admin"
            )
        )
        return created.configuration



@router.get(
    "/records",
    response_model=List[FileIntegrityRecordOut],
    status_code=status.HTTP_200_OK,
    summary="List file integrity inventory records",
    description="Retrieves baseline file integrity inventory records across managed devices."
)
def list_file_integrity_records(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_id: Optional[UUID] = Query(None, description="Filter records by Device UUID"),
    file_path: Optional[str] = Query(None, description="Filter by file path substring"),
    file_name: Optional[str] = Query(None, description="Filter by file name substring"),
    sha256: Optional[str] = Query(None, description="Filter by SHA-256 hash"),
    is_executable: Optional[bool] = Query(None, description="Filter by executable status"),
    db: Session = Depends(get_db)
):
    return file_integrity_service.get_file_integrity_records(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        file_path=file_path,
        file_name=file_name,
        sha256=sha256,
        is_executable=is_executable
    )


@router.post(
    "/baseline/{device_id}",
    response_model=List[FileIntegrityRecordOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest baseline file inventory",
    description="Ingests or updates baseline file integrity inventory records sent by an endpoint agent."
)
def ingest_file_integrity_baseline(
    device_id: UUID,
    payload: FileIntegrityBatchIngestRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return file_integrity_service.batch_upsert_file_integrity_records(
        db=db,
        device_id=device_id,
        records_in=payload.records
    )


@router.post(
    "/verify/{device_id}",
    response_model=FileIntegrityEventOut,
    status_code=status.HTTP_200_OK,
    summary="Verify file change event against baseline",
    description="Computes SHA-256, size, and permission differences against baseline and generates an integrity event."
)
def verify_file_change_event(
    device_id: UUID,
    payload: FileChangeEventRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return file_integrity_service.verify_file_integrity_change(
        db=db,
        device_id=device_id,
        event=payload
    )


@router.post(
    "/respond/{device_id}",
    response_model=FIMResponseActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute file integrity response action",
    description="Executes response actions on target file: RESTORE_BASELINE, QUARANTINE, IGNORE_CHANGE, ADD_ALLOWLIST, RECALCULATE_BASELINE."
)
def execute_fim_response_endpoint(
    device_id: UUID,
    payload: FIMResponseActionRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return file_integrity_service.execute_fim_response_action(
        db=db,
        device_id=device_id,
        payload=payload
    )


@router.get(
    "/timeline/{device_id}",
    response_model=FIMTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get file activity chronological timeline",
    description="Retrieves step-by-step chronological audit trail for a file (Created -> SHA Changed -> Alert -> Quarantined)."
)
def get_file_integrity_timeline_endpoint(
    device_id: UUID,
    file_path: str = Query(..., description="Target file path to build timeline for"),
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return file_integrity_service.get_file_integrity_timeline(
        db=db,
        device_id=device_id,
        file_path=file_path
    )
