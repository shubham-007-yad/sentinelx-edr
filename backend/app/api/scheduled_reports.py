from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_admin, get_current_analyst, get_current_viewer
from app.models.user import User
from app.schemas.scheduled_report import (
    ScheduledReportCreate,
    ScheduledReportUpdate,
    ScheduledReportOut,
)
from app.services import scheduled_report_service

router = APIRouter(prefix="/scheduled-reports", tags=["Scheduled Reports Management"])


@router.post(
    "",
    response_model=ScheduledReportOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scheduled report configuration (Admin Only)"
)
def create_scheduled_report(
    report_in: ScheduledReportCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    return scheduled_report_service.create_scheduled_report(
        db, report_in=report_in, created_by=admin.username
    )


@router.get(
    "",
    response_model=List[ScheduledReportOut],
    summary="List all scheduled report configurations"
)
def list_scheduled_reports(
    enabled_only: bool = Query(False, description="Filter for enabled reports only"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    return scheduled_report_service.get_scheduled_reports(db, enabled_only=enabled_only)


@router.get(
    "/{id}",
    response_model=ScheduledReportOut,
    summary="Get scheduled report configuration by ID"
)
def get_scheduled_report(
    id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    config = scheduled_report_service.get_scheduled_report_by_id(db, config_id=id)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report configuration not found"
        )
    return config


@router.patch(
    "/{id}",
    response_model=ScheduledReportOut,
    summary="Update scheduled report configuration (Admin Only)"
)
def update_scheduled_report(
    id: UUID,
    report_in: ScheduledReportUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    config = scheduled_report_service.get_scheduled_report_by_id(db, config_id=id)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report configuration not found"
        )
    return scheduled_report_service.update_scheduled_report(db, db_config=config, report_in=report_in)


@router.post(
    "/{id}/run-now",
    summary="Execute scheduled report immediately on demand (Analyst/Admin)"
)
def run_scheduled_report_now(
    id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    try:
        return scheduled_report_service.execute_scheduled_report(db, config_id=id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete scheduled report configuration (Admin Only)"
)
def delete_scheduled_report(
    id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    deleted = scheduled_report_service.delete_scheduled_report(db, config_id=id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report configuration not found"
        )
    return None
