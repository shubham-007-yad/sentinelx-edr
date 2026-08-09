from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_analyst, get_current_viewer
from app.models.user import User
from app.models.alert import AlertStatus, AlertSeverity
from app.schemas.alert import AlertOut, UnreadCountOut, AlertBulkActionInput
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["Alert Management"])


def _format_alert_out(alert) -> AlertOut:
    device_name = str(alert.device_id)
    if alert.device and hasattr(alert.device, "hostname") and alert.device.hostname:
        device_name = alert.device.hostname
    elif alert.threat and alert.threat.scan_result and alert.threat.scan_result.usb_event and alert.threat.scan_result.usb_event.device:
        device_name = alert.threat.scan_result.usb_event.device.hostname

    file_name = ""
    if alert.threat:
        file_name = alert.threat.file_name or (alert.threat.scan_result.file_name if alert.threat.scan_result else "")

    return AlertOut(
        id=alert.id,
        threat_id=alert.threat_id,
        device_id=alert.device_id,
        title=alert.title,
        message=alert.message,
        severity=alert.severity,
        status=alert.status,
        created_at=alert.created_at,
        read_at=alert.read_at,
        acknowledged_at=alert.acknowledged_at,
        device=device_name,
        file=file_name
    )


@router.get(
    "",
    response_model=List[AlertOut],
    summary="List all alerts",
    description="Retrieves a list of alerts with optional filtering by status, severity, device, or search."
)
def list_alerts(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[AlertStatus] = None,
    severity_filter: Optional[AlertSeverity] = None,
    device_id: Optional[UUID] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    alerts = alert_service.get_alerts(
        db,
        skip=skip,
        limit=limit,
        status=status_filter,
        severity=severity_filter,
        device_id=device_id,
        search=search
    )
    return [_format_alert_out(a) for a in alerts]


@router.get(
    "/unread-count",
    response_model=UnreadCountOut,
    summary="Get count of unread alerts"
)
def get_unread_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    count = alert_service.get_unread_count(db)
    return UnreadCountOut(unread_count=count)


@router.post(
    "/bulk-read",
    summary="Bulk mark selected alerts as READ"
)
def bulk_mark_read(
    bulk_input: AlertBulkActionInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    count = alert_service.bulk_mark_as_read(db, alert_ids=bulk_input.alert_ids)
    return {"message": f"Successfully marked {count} alert(s) as READ", "updated_count": count}


@router.post(
    "/bulk-acknowledge",
    summary="Bulk mark selected alerts as ACKNOWLEDGED"
)
def bulk_acknowledge_alerts(
    bulk_input: AlertBulkActionInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    count = alert_service.bulk_acknowledge(db, alert_ids=bulk_input.alert_ids)
    return {"message": f"Successfully acknowledged {count} alert(s)", "updated_count": count}


@router.patch(
    "/{alert_id}/read",
    response_model=AlertOut,
    summary="Mark an alert as read"
)
def mark_alert_read(
    alert_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    alert = alert_service.mark_alert_as_read(db, alert_id=alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    return _format_alert_out(alert)


@router.patch(
    "/mark-all-read",
    response_model=UnreadCountOut,
    summary="Mark all unread alerts as read"
)
def mark_all_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    alert_service.mark_all_alerts_as_read(db)
    return UnreadCountOut(unread_count=0)
