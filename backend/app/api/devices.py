from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.models.device import DeviceStatus, OSType
from app.schemas.device import (
    DeviceCreate, DeviceOut,
    DeviceHeartbeatRequest, DeviceHeartbeatResponse
)
from app.schemas.process import (
    ProcessInfoOut, ProcessBatchIngestRequest,
    ProcessEventDiffPayload, ProcessEventSummaryResponse
)
from app.schemas.network import (
    NetworkConnectionOut, NetworkConnectionBatchIngestRequest,
    NetworkEventDiffPayload, NetworkEventSummaryResponse
)
from app.services import device_service, process_service, network_service

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.get(
    "",
    response_model=List[DeviceOut],
    status_code=status.HTTP_200_OK,
    summary="List all registered devices",
    description="Retrieves a list of all registered managed devices with support for pagination and optional filtering by status or OS type."
)
def list_devices(
    skip: int = Query(0, ge=0, description="Number of items to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return"),
    status: Optional[DeviceStatus] = Query(None, description="Filter devices by status (ONLINE, OFFLINE, ISOLATED, UNREGISTERED)"),
    os_type: Optional[OSType] = Query(None, description="Filter devices by OS type (WINDOWS, LINUX, MACOS, OTHER)"),
    db: Session = Depends(get_db)
):
    """
    Retrieve all registered devices.
    """
    return device_service.get_devices(db=db, skip=skip, limit=limit, status=status, os_type=os_type)


@router.get(
    "/{id}",
    response_model=DeviceOut,
    status_code=status.HTTP_200_OK,
    summary="Get device details by ID",
    description="Retrieves detailed information for a specific managed device by its unique UUID."
)
def get_device(
    id: UUID,
    db: Session = Depends(get_db)
):
    """
    Retrieve details for a single device by ID.
    """
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return device


@router.post(
    "/register",
    response_model=DeviceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register an EDR Managed Device",
    description="Validates incoming agent hardware and OS payload, registers or updates the device in PostgreSQL, sets status to ONLINE, and returns the device details with its unique device ID."
)
def register_device(
    device_in: DeviceCreate,
    db: Session = Depends(get_db)
):
    """
    1. Validate incoming device payload (hostname, ip, mac, os_type, etc.)
    2. Prevent duplicate registrations by updating existing record if MAC address/hostname matches
    3. Save device in PostgreSQL database with status ONLINE
    4. Return unique device_id and device profile
    """
    try:
        device = device_service.register_device(db=db, device_in=device_in)
        return device
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to register device: {str(e)}"
        )


@router.post(
    "/heartbeat",
    response_model=DeviceHeartbeatResponse,
    status_code=status.HTTP_200_OK,
    summary="Record Device Heartbeat",
    description="Updates the device's last_seen timestamp and online status in PostgreSQL to track active endpoints."
)
def device_heartbeat(
    heartbeat_in: DeviceHeartbeatRequest,
    db: Session = Depends(get_db)
):
    """
    1. Validate device_id in request payload
    2. Check if device exists in PostgreSQL database
    3. Update last_seen timestamp and status to ONLINE
    4. Return heartbeat confirmation response
    """
    device = device_service.record_heartbeat(db=db, heartbeat_in=heartbeat_in)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found. Please register the endpoint first."
        )
    return {
        "message": "Heartbeat recorded successfully",
        "device_id": device.id,
        "status": device.status,
        "health_status": device.health_status,
        "last_seen": device.last_seen,
        "last_heartbeat": device.last_heartbeat or device.last_seen
    }


@router.post(
    "/{id}/isolate",
    response_model=DeviceOut,
    status_code=status.HTTP_200_OK,
    summary="Isolate managed endpoint device",
    description="Marks endpoint as ISOLATED, preventing further USB events or scan jobs."
)
def isolate_device_endpoint(
    id: UUID,
    db: Session = Depends(get_db)
):
    device = device_service.isolate_device(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return device


@router.post(
    "/{id}/unisolate",
    response_model=DeviceOut,
    status_code=status.HTTP_200_OK,
    summary="Un-isolate managed endpoint device",
    description="Restores an isolated endpoint back to ONLINE status."
)
def unisolate_device_endpoint(
    id: UUID,
    db: Session = Depends(get_db)
):
    device = device_service.unisolate_device(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return device


@router.get(
    "/{id}/processes",
    response_model=List[ProcessInfoOut],
    status_code=status.HTTP_200_OK,
    summary="Get device process inventory",
    description="Retrieves active running process inventory snapshot for a specific managed device."
)
def get_device_processes_endpoint(
    id: UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    name: Optional[str] = Query(None, description="Filter process by executable/binary name"),
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return process_service.get_processes_by_device(
        db=db,
        device_id=id,
        skip=skip,
        limit=limit,
        name=name
    )


@router.post(
    "/{id}/processes",
    response_model=List[ProcessInfoOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest process inventory snapshot for device",
    description="Ingests running process inventory payload from agent for target device."
)
def ingest_device_processes_endpoint(
    id: UUID,
    payload: ProcessBatchIngestRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return process_service.ingest_processes(
        db=db,
        device_id=id,
        processes_in=payload.processes
    )


@router.post(
    "/{id}/processes/events",
    response_model=ProcessEventSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest live process events for device",
    description="Processes real-time process diff events (created, terminated, long-running)."
)
def ingest_device_process_events_endpoint(
    id: UUID,
    payload: ProcessEventDiffPayload,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return process_service.process_live_events(
        db=db,
        device_id=id,
        events=payload
    )


@router.get(
    "/{id}/network",
    response_model=List[NetworkConnectionOut],
    status_code=status.HTTP_200_OK,
    summary="Get device network connections",
    description="Retrieves active network connection telemetry for a specific managed device."
)
def get_device_network_connections_endpoint(
    id: UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    protocol: Optional[str] = Query(None, description="Filter by protocol (TCP/UDP)"),
    state: Optional[str] = Query(None, description="Filter by socket state (ESTABLISHED, LISTEN, etc.)"),
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return network_service.get_device_network_connections(
        db=db,
        device_id=id,
        skip=skip,
        limit=limit,
        protocol=protocol,
        state=state
    )


@router.post(
    "/{id}/network",
    response_model=List[NetworkConnectionOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest network connections for device",
    description="Ingests network connection inventory snapshot payload from agent for target device."
)
def ingest_device_network_connections_endpoint(
    id: UUID,
    payload: NetworkConnectionBatchIngestRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return network_service.ingest_network_connections(
        db=db,
        device_id=id,
        connections_in=payload.connections
    )


@router.post(
    "/{id}/network/events",
    response_model=NetworkEventSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest live network diff events for device",
    description="Processes real-time connection diff events (connected, disconnected, state_changed, long_running)."
)
def ingest_device_network_events_diff_endpoint(
    id: UUID,
    payload: NetworkEventDiffPayload,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{id}' was not found."
        )
    return network_service.process_live_network_events(
        db=db,
        device_id=id,
        events=payload
    )


