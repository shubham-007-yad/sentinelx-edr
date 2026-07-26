from typing import List, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.usb_scan_result import USBScanResult
from app.schemas.usb_scan import USBScanResultCreate


def create_usb_scan_result(db: Session, scan_in: USBScanResultCreate) -> USBScanResult:
    """Creates a single USB scan result record in database."""
    try:
        db_scan = USBScanResult(
            usb_event_id=scan_in.usb_event_id,
            file_name=scan_in.file_name,
            full_path=scan_in.full_path,
            extension=scan_in.extension,
            file_size=scan_in.file_size,
            sha256=scan_in.sha256,
            is_hidden=scan_in.is_hidden,
            created_at=scan_in.created_at,
            modified_at=scan_in.modified_at,
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        return db_scan
    except Exception:
        db.rollback()
        raise


def create_usb_scan_results_bulk(db: Session, scans_in: List[USBScanResultCreate]) -> List[USBScanResult]:
    """Bulk creates USB scan result records in database."""
    if not scans_in:
        return []
    try:
        db_scans = [
            USBScanResult(
                usb_event_id=s.usb_event_id,
                file_name=s.file_name,
                full_path=s.full_path,
                extension=s.extension,
                file_size=s.file_size,
                sha256=s.sha256,
                is_hidden=s.is_hidden,
                created_at=s.created_at,
                modified_at=s.modified_at,
            )
            for s in scans_in
        ]
        db.add_all(db_scans)
        db.commit()
        for s in db_scans:
            db.refresh(s)
        return db_scans
    except Exception:
        db.rollback()
        raise


def get_usb_scans(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    usb_event_id: Optional[UUID] = None,
    extension: Optional[str] = None,
    is_hidden: Optional[bool] = None,
    search: Optional[str] = None,
) -> List[USBScanResult]:
    """Retrieves list of USB scan results with filtering and pagination."""
    query = db.query(USBScanResult)

    if usb_event_id:
        query = query.filter(USBScanResult.usb_event_id == usb_event_id)
    if extension:
        ext_clean = extension if extension.startswith('.') else f".{extension}"
        query = query.filter(USBScanResult.extension.ilike(ext_clean))
    if is_hidden is not None:
        query = query.filter(USBScanResult.is_hidden == is_hidden)
    if search:
        query = query.filter(USBScanResult.file_name.ilike(f"%{search}%"))

    return query.order_by(USBScanResult.scanned_at.desc()).offset(skip).limit(limit).all()


def get_usb_scan_by_id(db: Session, scan_id: UUID) -> Optional[USBScanResult]:
    """Retrieves a single USB scan result by ID."""
    return db.query(USBScanResult).filter(USBScanResult.id == scan_id).first()
