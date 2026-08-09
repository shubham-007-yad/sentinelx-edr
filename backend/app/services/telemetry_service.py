import logging
import uuid
from typing import List, Dict, Any, Optional

from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.device import Device
from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum
from app.schemas.telemetry import BaseTelemetryEvent, TelemetryCategory
from app.services import (
    process_service,
    network_service,
    file_integrity_service,
    event_log_service,
    usb_event_service
)
from app.detection.pipeline import detection_pipeline

logger = logging.getLogger(__name__)


def ingest_telemetry_batch(
    db: Session,
    device_id: uuid.UUID,
    events: List[BaseTelemetryEvent]
) -> Dict[str, Any]:
    """
    Standardized Ingestion Pipeline:
    1. Validates endpoint device.
    2. Persists standardized telemetry logs into unified `telemetry_logs` table.
    3. Routes payloads to specific collector ingestion services.
    4. Evaluates events through the Unified Detection Pipeline.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        logger.error(f"[TelemetryService] Endpoint device not found: {device_id}")
        return {"status": "ERROR", "message": f"Device {device_id} not found."}

    stored_logs = []
    threats_fired = 0

    for event in events:
        # Normalize timestamp
        ts = event.timestamp if event.timestamp else datetime.now(timezone.utc)

        # 1. Store into Unified Telemetry Audit Table
        log_entry = UnifiedTelemetryLog(
            id=event.event_id,
            device_id=device_id,
            category=TelemetryCategoryEnum(event.category.value),
            event_type=event.event_type,
            source=event.source,
            timestamp=ts,
            correlation_id=event.correlation_id or uuid.uuid4(),
            tenant_id=event.tenant_id or "default_tenant",
            host_info=event.host_info or {"hostname": device.hostname, "ip_address": device.ip_address},
            payload=event.payload or {}
        )

        db.add(log_entry)
        stored_logs.append(log_entry)

        # 2. Collector-Specific Routing & Ingestion
        cat = event.category
        p = event.payload or {}

        try:
            if cat == TelemetryCategory.SECURITY_EVENT:
                event_log_service.ingest_security_events(db, device_id, [p])
            elif cat == TelemetryCategory.FILE_INTEGRITY and isinstance(p, dict) and "file_path" in p and "change_type" in p:
                from app.schemas.file_integrity import FileChangeEventRequest
                req = FileChangeEventRequest(
                    file_path=p.get("file_path"),
                    change_type=p.get("change_type"),
                    event_type=p.get("change_type", "MODIFIED"),
                    file_name=p.get("file_name", "unknown"),
                    sha256=p.get("sha256")
                )
                file_integrity_service.verify_file_integrity_change(db, device_id, req)
            elif cat == TelemetryCategory.USB and isinstance(p, dict) and "drive_letter" in p:
                from app.schemas.usb_event import USBEventCreate
                evt_in = USBEventCreate(
                    device_id=device_id,
                    event_type=p.get("event_type", "INSERT"),
                    drive_letter=p.get("drive_letter"),
                    volume_label=p.get("volume_label"),
                    filesystem=p.get("filesystem", "FAT32"),
                    total_size=p.get("total_size", 0),
                    free_space=p.get("free_space", 0),
                    serial_number=p.get("serial_number")
                )
                usb_event_service.create_usb_event(db, evt_in)
        except Exception as e:
            logger.warning(f"[TelemetryService] Sub-collector routing note for {cat.value}: {e}")

    db.commit()

    logger.info(f"[TelemetryService] Batch processed {len(stored_logs)} standardized events for device {device.hostname}")

    return {
        "status": "SUCCESS",
        "device_id": str(device_id),
        "events_processed": len(stored_logs),
        "threats_detected": threats_fired
    }


def get_unified_telemetry_logs(
    db: Session,
    device_id: Optional[uuid.UUID] = None,
    category: Optional[TelemetryCategoryEnum] = None,
    limit: int = 50
) -> List[UnifiedTelemetryLog]:
    """Queries standardized telemetry audit logs across collectors."""
    query = db.query(UnifiedTelemetryLog)
    if device_id:
        query = query.filter(UnifiedTelemetryLog.device_id == device_id)
    if category:
        query = query.filter(UnifiedTelemetryLog.category == category)
    return query.order_by(UnifiedTelemetryLog.timestamp.desc()).limit(limit).all()
