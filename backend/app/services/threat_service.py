from typing import List, Optional, Dict, Any
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.threat import Threat, ThreatSeverity, ThreatType, ThreatStatus
from app.models.usb_scan_result import USBScanResult
from app.models.usb_event import USBEvent
from app.schemas.threat import ThreatRecordCreate, ThreatRecordUpdateStatus, ThreatStatsOut, ThreatSeverityCount
from app.detection.engine import DetectionEngine


engine = DetectionEngine()


def analyze_and_record_threats(db: Session, scan_results: List[USBScanResult]) -> List[Threat]:
    """
    Analyzes a list of USBScanResult records against the DetectionEngine rule plugins.
    Creates Threat entries in database for all detected threats.
    """
    if not scan_results:
        return []

    new_threats: List[Threat] = []

    for scan in scan_results:
        rule_results = engine.evaluate_file(
            file_name=scan.file_name,
            full_path=scan.full_path,
            extension=scan.extension,
            file_size=scan.file_size,
            sha256=scan.sha256,
            is_hidden=scan.is_hidden
        )

        for res in rule_results:
            # Prevent duplicate threat entry for the same scan_result_id and rule_name
            existing = db.query(Threat).filter(
                Threat.scan_result_id == scan.id,
                Threat.rule_name == res.rule_name
            ).first()

            if not existing:
                t_record = Threat(
                    scan_result_id=scan.id,
                    threat_type=res.threat_type,
                    severity=res.severity,
                    rule_name=res.rule_name,
                    description=res.description,
                    status=ThreatStatus.NEW
                )
                db.add(t_record)
                new_threats.append(t_record)

    if new_threats:
        try:
            db.commit()
            for t in new_threats:
                db.refresh(t)
            from app.services.alert_service import create_alerts_for_threats
            create_alerts_for_threats(db, new_threats)
        except Exception:
            db.rollback()
            raise

    return new_threats


def create_threat_record(db: Session, threat_in: ThreatRecordCreate) -> Threat:
    """Creates a single threat record directly in database."""
    try:
        db_threat = Threat(
            scan_result_id=threat_in.scan_result_id,
            threat_type=threat_in.threat_type,
            severity=threat_in.severity,
            rule_name=threat_in.rule_name,
            description=threat_in.description,
            status=threat_in.status or ThreatStatus.NEW
        )
        db.add(db_threat)
        db.commit()
        db.refresh(db_threat)
        from app.services.alert_service import create_alert_from_threat
        create_alert_from_threat(db, db_threat)
        return db_threat
    except Exception:
        db.rollback()
        raise


def get_threat_records(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    status: Optional[str] = None,
    usb_event_id: Optional[UUID] = None,
    device_id: Optional[UUID] = None,
    search: Optional[str] = None
) -> List[Threat]:
    """Retrieves list of threat records with multi-field filtering and pagination."""
    query = db.query(Threat).join(USBScanResult, Threat.scan_result_id == USBScanResult.id).join(USBEvent, USBScanResult.usb_event_id == USBEvent.id)

    if severity:
        query = query.filter(Threat.severity == severity.upper())
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type.upper())
    if status:
        query = query.filter(Threat.status == status.upper())
    if usb_event_id:
        query = query.filter(USBScanResult.usb_event_id == usb_event_id)
    if device_id:
        query = query.filter(USBEvent.device_id == device_id)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            (USBScanResult.file_name.ilike(pattern)) |
            (Threat.rule_name.ilike(pattern)) |
            (USBScanResult.sha256.ilike(pattern))
        )

    return query.order_by(Threat.detected_at.desc()).offset(skip).limit(limit).all()


def get_threat_record_by_id(db: Session, threat_id: UUID) -> Optional[Threat]:
    """Retrieves a single threat record by ID."""
    return db.query(Threat).filter(Threat.id == threat_id).first()


def update_threat_status(db: Session, threat_id: UUID, status_in: ThreatRecordUpdateStatus) -> Optional[Threat]:
    """Updates the status for a threat record."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        return None

    threat.status = status_in.status

    try:
        db.commit()
        db.refresh(threat)
        return threat
    except Exception:
        db.rollback()
        raise


def get_threat_stats(db: Session) -> ThreatStatsOut:
    """Calculates aggregate threat statistics and breakdown metrics."""
    total_threats = db.query(Threat).count()
    new_threats = db.query(Threat).filter(Threat.status == ThreatStatus.NEW).count()
    acknowledged_threats = db.query(Threat).filter(Threat.status == ThreatStatus.ACKNOWLEDGED).count()
    resolved_threats = db.query(Threat.status == ThreatStatus.RESOLVED).count()

    critical_count = db.query(Threat).filter(Threat.severity == ThreatSeverity.CRITICAL).count()
    high_count = db.query(Threat).filter(Threat.severity == ThreatSeverity.HIGH).count()
    medium_count = db.query(Threat).filter(Threat.severity == ThreatSeverity.MEDIUM).count()
    low_count = db.query(Threat).filter(Threat.severity == ThreatSeverity.LOW).count()

    type_counts = db.query(Threat.threat_type, func.count(Threat.id)).group_by(Threat.threat_type).all()
    type_breakdown = {str(t_type): count for t_type, count in type_counts}

    return ThreatStatsOut(
        total_threats=total_threats,
        open_threats=new_threats,
        resolved_threats=resolved_threats,
        false_positives=acknowledged_threats,
        quarantined=0,
        severity_breakdown=ThreatSeverityCount(
            CRITICAL=critical_count,
            HIGH=high_count,
            MEDIUM=medium_count,
            LOW=low_count,
            INFO=0
        ),
        threat_type_breakdown=type_breakdown
    )
