from typing import List, Optional, Union
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.models.usb_event import USBEventType
from app.schemas.usb_event import USBEventCreate, USBEventOut
from app.schemas.usb_scan import (
    USBScanResultCreate, USBScanBatchCreate, USBScanResultOut
)
from app.services import usb_event_service, device_service, usb_scan_service

router = APIRouter(prefix="/usb", tags=["USB Events & Scans"])


# ==================== USB EVENTS ====================

@router.post(
    "/events",
    response_model=USBEventOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a USB event",
    description="Records a USB insert or remove event sent by an EDR agent."
)
def create_usb_event(
    event_in: USBEventCreate,
    db: Session = Depends(get_db)
):
    """
    Record a new USB event for a registered device.
    """
    device = device_service.get_device_by_id(db=db, device_id=event_in.device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{event_in.device_id}' was not found."
        )

    try:
        return usb_event_service.create_usb_event(db=db, event_in=event_in)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to record USB event: {str(e)}"
        )


@router.get(
    "/events",
    response_model=List[USBEventOut],
    status_code=status.HTTP_200_OK,
    summary="List USB events",
    description="Retrieves a list of recorded USB events with support for pagination and filtering."
)
def list_usb_events(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
    device_id: Optional[UUID] = Query(None, description="Filter by device ID"),
    event_type: Optional[USBEventType] = Query(None, description="Filter by event type (INSERT, REMOVE)"),
    db: Session = Depends(get_db)
):
    """
    Retrieve list of USB events.
    """
    return usb_event_service.get_usb_events(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        event_type=event_type
    )


@router.get(
    "/events/{id}",
    response_model=USBEventOut,
    status_code=status.HTTP_200_OK,
    summary="Get USB event detail",
    description="Retrieves detailed information for a specific USB event by its unique ID."
)
def get_usb_event(
    id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieve single USB event by ID.
    """
    event = usb_event_service.get_usb_event_by_id(db=db, event_id=id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"USB event with ID '{id}' was not found."
        )
    return event


# ==================== USB SCANS ====================

@router.post(
    "/scans",
    response_model=Union[List[USBScanResultOut], USBScanResultOut],
    status_code=status.HTTP_201_CREATED,
    summary="Upload USB scan results",
    description="Agent uploads scanned files metadata for a specific USB event."
)
def create_usb_scans(
    payload: Union[USBScanBatchCreate, List[USBScanResultCreate], USBScanResultCreate],
    db: Session = Depends(get_db)
):
    """
    Records file scan results for a USB event. Supports single item, list of items, or batch payload.
    """
    if isinstance(payload, USBScanBatchCreate):
        scans_list = payload.files
    elif isinstance(payload, list):
        scans_list = payload
    else:
        scans_list = [payload]

    if not scans_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan payload cannot be empty."
        )

    # Validate associated usb_event_id
    sample_event_id = scans_list[0].usb_event_id
    usb_event = usb_event_service.get_usb_event_by_id(db=db, event_id=sample_event_id)
    if not usb_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"USB Event with ID '{sample_event_id}' was not found."
        )

    try:
        if isinstance(payload, USBScanResultCreate):
            return usb_scan_service.create_usb_scan_result(db=db, scan_in=payload)
        else:
            return usb_scan_service.create_usb_scan_results_bulk(db=db, scans_in=scans_list)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to record USB scan results: {str(e)}"
        )


@router.get(
    "/scans",
    response_model=List[USBScanResultOut],
    status_code=status.HTTP_200_OK,
    summary="List USB scan results",
    description="Retrieves a list of USB scan file results with filtering (usb_event_id, extension, is_hidden, search) and pagination."
)
def list_usb_scans(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
    usb_event_id: Optional[UUID] = Query(None, description="Filter by USB event ID"),
    extension: Optional[str] = Query(None, description="Filter by file extension (e.g. .exe)"),
    is_hidden: Optional[bool] = Query(None, description="Filter by hidden files (true/false)"),
    search: Optional[str] = Query(None, description="Search by file name"),
    db: Session = Depends(get_db)
):
    """
    Retrieve list of USB scan results.
    """
    return usb_scan_service.get_usb_scans(
        db=db,
        skip=skip,
        limit=limit,
        usb_event_id=usb_event_id,
        extension=extension,
        is_hidden=is_hidden,
        search=search
    )


@router.get(
    "/scans/{id}",
    response_model=USBScanResultOut,
    status_code=status.HTTP_200_OK,
    summary="Get USB scan result detail",
    description="Retrieves detailed information for a specific USB scan result file by its unique ID."
)
def get_usb_scan(
    id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieve single USB scan result by ID.
    """
    scan_result = usb_scan_service.get_usb_scan_by_id(db=db, scan_id=id)
    if not scan_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"USB scan result with ID '{id}' was not found."
        )
    return scan_result
