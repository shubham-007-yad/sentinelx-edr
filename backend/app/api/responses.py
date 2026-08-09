from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_analyst, get_current_viewer
from app.models.user import User
from app.models.response_action import ResponseActionType, ResponseActionStatus
from app.schemas.response_action import ResponseActionOut, ResponseActionCreate, ResponseActionUpdate, ResponseAuditLogOut
from app.services.response_service import (
    execute_response,
    update_response_action_status,
    retry_response_action,
    cancel_response_action,
    get_response_action_by_id,
    get_response_actions,
    get_audit_logs_by_action_id,
    InvalidDeviceError,
    PermissionDeniedError,
    DuplicateActionError
)
from app.core.rate_limiter import rate_limit_commands

router = APIRouter(prefix="/responses", tags=["Response Engine"])


@router.post(
    "/trigger",
    response_model=ResponseActionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_commands)]
)
def trigger_response_action(
    action_in: ResponseActionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    """
    Triggers a manual response action against a target endpoint device (Analyst/Admin only).
    """
    try:
        action = execute_response(
            db=db,
            device_id=action_in.device_id,
            action_type=action_in.action_type,
            alert_id=action_in.alert_id,
            initiated_by=user.username,
            user_role=user.role.value if hasattr(user.role, "value") else str(user.role),
            parameters=action_in.parameters
        )
        return action
    except InvalidDeviceError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DuplicateActionError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to execute response: {str(e)}")


@router.post("/{action_id}/retry", response_model=ResponseActionOut)
def retry_action_endpoint(
    action_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    """
    Retries execution of a failed response action (Analyst/Admin only).
    """
    action = retry_response_action(db=db, action_id=action_id)
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")
    return action


@router.post("/{action_id}/cancel", response_model=ResponseActionOut)
def cancel_action_endpoint(
    action_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst)
):
    """
    Cancels a pending response action (Analyst/Admin only).
    """
    action = cancel_response_action(db=db, action_id=action_id)
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")
    return action


@router.post("/{action_id}/status", response_model=ResponseActionOut)
def update_action_status(
    action_id: UUID,
    status_in: ResponseActionUpdate,
    db: Session = Depends(get_db)
):
    """
    Endpoint agent callback to update execution status.
    """
    if not status_in.status:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status field is required.")

    updated_action = update_response_action_status(
        db=db,
        action_id=action_id,
        status=status_in.status,
        result=status_in.result
    )
    if not updated_action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")

    return updated_action


@router.get("", response_model=List[ResponseActionOut])
def list_response_actions(
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    alert_id: Optional[UUID] = None,
    status_filter: Optional[ResponseActionStatus] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    """
    Retrieves response action history.
    """
    return get_response_actions(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        alert_id=alert_id,
        status=status_filter
    )


@router.get("/{action_id}", response_model=ResponseActionOut)
def get_response_action_details(
    action_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    """
    Retrieves details of a specific response action.
    """
    action = get_response_action_by_id(db=db, action_id=action_id)
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")
    return action


@router.get("/{action_id}/audit-logs", response_model=List[ResponseAuditLogOut])
def get_action_audit_logs(
    action_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    """
    Retrieves forensic audit trail entries for a response action.
    """
    action = get_response_action_by_id(db=db, action_id=action_id)
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")
    return get_audit_logs_by_action_id(db=db, action_id=action_id)
