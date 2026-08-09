import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_analyst, get_current_viewer
from app.models.user import User
from app.models.telemetry_log import TelemetryCategoryEnum
from app.schemas.telemetry import TelemetryIngestBatchRequest
from app.services import telemetry_service
from app.core.rate_limiter import rate_limit_telemetry

router = APIRouter(prefix="/telemetry", tags=["Standardized Telemetry Engine"])


@router.post(
    "/ingest",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_telemetry)],
    summary="Ingest Telemetry Batch"
)
def ingest_standardized_telemetry(
    batch: TelemetryIngestBatchRequest,
    db: Session = Depends(get_db)
):
    """
    Standardized Telemetry Ingestion Endpoint:
    Receives base telemetry events emitted by agent collectors.
    """
    result = telemetry_service.ingest_telemetry_batch(
        db=db,
        device_id=batch.device_id,
        events=batch.events
    )
    if result.get("status") == "ERROR":
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result


@router.get(
    "/logs",
    status_code=status.HTTP_200_OK,
    summary="Get Telemetry Logs"
)
def get_telemetry_logs(
    device_id: Optional[str] = Query(None, description="Filter by Device UUID"),
    category: Optional[str] = Query(None, description="Filter by Telemetry Category"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_viewer)
):
    """
    Returns standardized unified telemetry audit logs across all collectors.
    """
    dev_uuid = None
    if device_id:
        try:
            dev_uuid = uuid.UUID(device_id)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid device_id format: '{device_id}'")

    cat_enum = None
    if category:
        try:
            cat_enum = TelemetryCategoryEnum(category.upper())
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid category '{category}'. Allowed: USB, FILE_INTEGRITY, PROCESS, NETWORK, SECURITY_EVENT")

    logs = telemetry_service.get_unified_telemetry_logs(
        db=db,
        device_id=dev_uuid,
        category=cat_enum,
        limit=limit
    )

    return [
        {
            "id": str(log.id),
            "device_id": str(log.device_id),
            "category": log.category.value,
            "event_type": log.event_type,
            "source": log.source,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "host_info": log.host_info,
            "payload": log.payload
        }
        for log in logs
    ]
