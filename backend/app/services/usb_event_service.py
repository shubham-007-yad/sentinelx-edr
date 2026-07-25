from typing import List, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.usb_event import USBEvent, USBEventType
from app.schemas.usb_event import USBEventCreate


def create_usb_event(db: Session, event_in: USBEventCreate) -> USBEvent:
    """Creates a new USB event record in database."""
    db_event = USBEvent(
        device_id=event_in.device_id,
        event_type=event_in.event_type,
        drive_letter=event_in.drive_letter,
        volume_label=event_in.volume_label,
        filesystem=event_in.filesystem,
        total_size=event_in.total_size,
        free_space=event_in.free_space,
        serial_number=event_in.serial_number,
    )
    if event_in.detected_at:
        db_event.detected_at = event_in.detected_at

    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


def get_usb_events(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    event_type: Optional[USBEventType] = None
) -> List[USBEvent]:
    """Retrieves list of USB events with optional filtering by device_id or event_type."""
    query = db.query(USBEvent)
    if device_id:
        query = query.filter(USBEvent.device_id == device_id)
    if event_type:
        query = query.filter(USBEvent.event_type == event_type)
    return query.order_by(USBEvent.detected_at.desc()).offset(skip).limit(limit).all()


def get_usb_event_by_id(db: Session, event_id: UUID) -> Optional[USBEvent]:
    """Retrieves a single USB event by ID."""
    return db.query(USBEvent).filter(USBEvent.id == event_id).first()
