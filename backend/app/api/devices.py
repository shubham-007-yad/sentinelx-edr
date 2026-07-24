from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.device import DeviceCreate, DeviceOut
from app.services import device_service

router = APIRouter(prefix="/devices", tags=["Devices"])


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
