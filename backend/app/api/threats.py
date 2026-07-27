from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.threat import (
    ThreatRecordOut, ThreatRecordUpdateStatus, ThreatStatsOut
)
from app.services import threat_service, usb_scan_service


router = APIRouter(prefix="/threats", tags=["Threat Detection Engine"])


@router.get(
    "",
    response_model=List[ThreatRecordOut],
    status_code=status.HTTP_200_OK,
    summary="List threat records",
    description="Retrieves recorded threats detected by the Threat Detection Engine with filtering and pagination."
)
def list_threats(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, RESOLVED, FALSE_POSITIVE, QUARANTINED)"),
    usb_event_id: Optional[UUID] = Query(None, description="Filter by USB event ID"),
    device_id: Optional[UUID] = Query(None, description="Filter by device ID"),
    search: Optional[str] = Query(None, description="Search by file name, threat name, or SHA-256"),
    db: Session = Depends(get_db)
):
    """Retrieve list of threat records."""
    return threat_service.get_threat_records(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        threat_type=threat_type,
        status=status_filter,
        usb_event_id=usb_event_id,
        device_id=device_id,
        search=search
    )


@router.get(
    "/summary",
    response_model=ThreatStatsOut,
    status_code=status.HTTP_200_OK,
    summary="Get threat detection metrics summary",
    description="Returns aggregate metrics including severity distribution, status counts, and threat type counts."
)
def get_threat_summary(
    db: Session = Depends(get_db)
):
    """Retrieve threat statistics and summary metrics."""
    return threat_service.get_threat_stats(db=db)


@router.get(
    "/{id}",
    response_model=ThreatRecordOut,
    status_code=status.HTTP_200_OK,
    summary="Get threat record detail",
    description="Retrieves a single threat record by unique ID."
)
def get_threat_detail(
    id: UUID,
    db: Session = Depends(get_db)
):
    """Retrieve single threat record by ID."""
    threat = threat_service.get_threat_record_by_id(db=db, threat_id=id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat record with ID '{id}' was not found."
        )
    return threat


@router.patch(
    "/{id}",
    response_model=ThreatRecordOut,
    status_code=status.HTTP_200_OK,
    summary="Update threat status / remediation",
    description="Updates the status (NEW, ACKNOWLEDGED, RESOLVED) and optional remediation details."
)
@router.patch(
    "/{id}/status",
    response_model=ThreatRecordOut,
    status_code=status.HTTP_200_OK,
    summary="Update threat status",
    description="Updates the status of a threat record."
)
def update_threat_status(
    id: UUID,
    status_in: ThreatRecordUpdateStatus,
    db: Session = Depends(get_db)
):
    """Update threat status and resolution details."""
    updated = threat_service.update_threat_status(db=db, threat_id=id, status_in=status_in)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat record with ID '{id}' was not found."
        )
    return updated


@router.post(
    "/analyze/{usb_event_id}",
    response_model=List[ThreatRecordOut],
    status_code=status.HTTP_200_OK,
    summary="Run threat engine on USB event scan results",
    description="Re-analyzes all scan results associated with a USB Event ID and creates any newly discovered threat records."
)
def analyze_usb_event_scans(
    usb_event_id: UUID,
    db: Session = Depends(get_db)
):
    """Re-run threat analysis on scan results for a specific USB event."""
    scans = usb_scan_service.get_usb_scans(db=db, usb_event_id=usb_event_id, limit=1000)
    if not scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan results found for USB event ID '{usb_event_id}'."
        )
    threat_service.analyze_and_record_threats(db=db, scan_results=scans)
    # Return all threat records associated with this USB event
    all_threats = threat_service.get_threat_records(db=db, usb_event_id=usb_event_id, limit=1000)
    return all_threats
