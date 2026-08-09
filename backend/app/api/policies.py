from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_admin, get_current_viewer
from app.models.user import User
from app.schemas.security_policy import SecurityPolicyOut, SecurityPolicyCreate, UnifiedSecurityPolicySyncResponse
from app.services.policy_service import PolicyService
from app.services import device_service
from app.models.security_policy import PolicyCategory

router = APIRouter(prefix="/policies", tags=["Policy Management & Distribution"])


@router.get(
    "/history",
    response_model=List[SecurityPolicyOut],
    status_code=status.HTTP_200_OK,
    summary="Get policy version history",
    description="Retrieves list of recorded security policies with version history."
)
def get_policies_history(
    category: Optional[PolicyCategory] = Query(None, description="Filter history by Policy Category"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    return PolicyService.get_policies(db=db, category=category, enabled_only=False)


@router.post(
    "",
    response_model=SecurityPolicyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a security policy (Admin Only)"
)
def create_policy_endpoint(
    payload: SecurityPolicyCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    return PolicyService.create_policy(db=db, payload=payload)


@router.patch(
    "/{id}/toggle",
    response_model=SecurityPolicyOut,
    status_code=status.HTTP_200_OK,
    summary="Enable or disable a security policy (Admin Only)"
)
def toggle_policy_status(
    id: UUID,
    enabled: bool = Query(..., description="Target status (true/false)"),
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    updated = PolicyService.toggle_policy(db=db, policy_id=str(id), enabled=enabled)
    if not updated:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return updated


@router.post(
    "/{id}/clone",
    response_model=SecurityPolicyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Clone a security policy (Admin Only)"
)
def clone_policy_endpoint(
    id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    cloned = PolicyService.clone_policy(db=db, policy_id=str(id))
    if not cloned:
        raise HTTPException(status_code=404, detail="Target policy not found.")
    return cloned


@router.post(
    "/{id}/rollback",
    response_model=SecurityPolicyOut,
    status_code=status.HTTP_200_OK,
    summary="Rollback to a specific policy version (Admin Only)"
)
def rollback_policy_endpoint(
    id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    rolled_back = PolicyService.rollback_policy(db=db, policy_id=str(id))
    if not rolled_back:
        raise HTTPException(status_code=404, detail="Target policy not found.")
    return rolled_back


@router.get(
    "/latest",
    response_model=UnifiedSecurityPolicySyncResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated latest active security policies"
)
def get_latest_security_policies(
    device_id: Optional[UUID] = Query(None, description="Optional requesting endpoint Device UUID"),
    applied_version: Optional[int] = Query(None, description="Current policy version applied on endpoint"),
    db: Session = Depends(get_db)
):
    if device_id and applied_version is not None:
        device_service.record_heartbeat(
            db=db,
            heartbeat_in=device_service.DeviceHeartbeatRequest(
                device_id=device_id,
                applied_policy_version=applied_version
            )
        )
    return PolicyService.get_unified_active_policy(db=db)


@router.get(
    "/sync",
    response_model=UnifiedSecurityPolicySyncResponse,
    status_code=status.HTTP_200_OK,
    summary="Sync endpoint security policy"
)
def sync_security_policies(
    device_id: Optional[UUID] = Query(None, description="Optional requesting endpoint Device UUID"),
    applied_version: Optional[int] = Query(None, description="Current policy version applied on endpoint"),
    db: Session = Depends(get_db)
):
    if device_id and applied_version is not None:
        device_service.record_heartbeat(
            db=db,
            heartbeat_in=device_service.DeviceHeartbeatRequest(
                device_id=device_id,
                applied_policy_version=applied_version
            )
        )
    return PolicyService.get_unified_active_policy(db=db)
