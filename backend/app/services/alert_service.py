from typing import List, Optional, Any
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session, joinedload
from app.models.device import Device
from app.models.threat import Threat
from app.models.usb_scan_result import USBScanResult
from app.models.usb_event import USBEvent
from app.models.alert import Alert, AlertSeverity, AlertStatus


def generate_alert_title(threat: Threat) -> str:
    """Generates a short, descriptive alert title based on threat severity."""
    severity_val = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
    severity_title = severity_val.title()
    return f"{severity_title} Threat Detected"


def generate_alert_message(threat: Threat) -> str:
    """Generates a human-readable description for the alert."""
    file_name = threat.file_name or ""
    if not file_name and threat.scan_result:
        file_name = threat.scan_result.file_name or ""

    if file_name and file_name not in threat.description:
        return f"{threat.description}: {file_name}"
    return threat.description


def create_alert_from_threat(db: Session, threat: Threat) -> Alert:
    """
    Creates a new Alert for a given Threat if one does not already exist.
    Prevents duplicate alerts for the same threat.
    """
    # 1. Prevent duplicate alert for the same threat
    existing_alert = db.query(Alert).filter(Alert.threat_id == threat.id).first()
    if existing_alert:
        return existing_alert

    # 2. Resolve device_id from threat -> scan_result -> usb_event
    device_id = None
    if threat.scan_result and threat.scan_result.usb_event:
        device_id = threat.scan_result.usb_event.device_id
    else:
        scan_res = db.query(USBScanResult).filter(USBScanResult.id == threat.scan_result_id).first()
        if scan_res:
            usb_event = db.query(USBEvent).filter(USBEvent.id == scan_res.usb_event_id).first()
            if usb_event:
                device_id = usb_event.device_id

    if not device_id:
        raise ValueError(f"Could not resolve device_id for threat {threat.id}")

    # 3. Map severity
    severity_val = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
    alert_severity = AlertSeverity(severity_val)

    title = generate_alert_title(threat)
    message = generate_alert_message(threat)

    # 4. Create and save Alert
    alert = Alert(
        threat_id=threat.id,
        device_id=device_id,
        title=title,
        message=message,
        severity=alert_severity,
        status=AlertStatus.UNREAD
    )
    db.add(alert)

    try:
        db.commit()
        db.refresh(alert)

        # 5. Broadcast to real-time WebSocket clients
        try:
            from app.core.websocket_manager import websocket_manager
            
            device_name = str(device_id)
            if threat.scan_result and threat.scan_result.usb_event and threat.scan_result.usb_event.device:
                device_name = threat.scan_result.usb_event.device.hostname

            file_name = threat.file_name or (threat.scan_result.file_name if threat.scan_result else "")
            created_time = alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat()

            alert_payload = {
                "id": str(alert.id),
                "threat_id": str(alert.threat_id),
                "device_id": str(alert.device_id),
                "device": device_name,
                "file": file_name,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
                "created_at": created_time,
                "time": created_time,
            }
            websocket_manager.broadcast_alert_sync(alert_payload)
        except Exception as ws_err:
            pass

        return alert
    except Exception:
        db.rollback()
        raise


def create_alerts_for_threats(db: Session, threats: List[Threat]) -> List[Alert]:
    """Generates alerts for a list of threats, skipping duplicates."""
    alerts = []
    for threat in threats:
        alert = create_alert_from_threat(db, threat)
        alerts.append(alert)
    return alerts


def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[AlertStatus] = None,
    severity: Optional[AlertSeverity] = None,
    device_id: Optional[UUID] = None,
    search: Optional[str] = None
) -> List[Alert]:
    """Retrieves alerts with optional filtering, multi-field search, and pagination."""
    query = db.query(Alert).options(
        joinedload(Alert.device),
        joinedload(Alert.threat).joinedload(Threat.scan_result)
    )
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if device_id:
        query = query.filter(Alert.device_id == device_id)
    if search:
        pattern = f"%{search}%"
        query = query.outerjoin(Device, Alert.device_id == Device.id)
        query = query.filter(
            (Alert.title.ilike(pattern)) |
            (Alert.message.ilike(pattern)) |
            (Device.hostname.ilike(pattern))
        )
    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


def get_alert_by_id(db: Session, alert_id: UUID) -> Optional[Alert]:
    """Retrieves a single alert by ID."""
    return db.query(Alert).filter(Alert.id == alert_id).first()


def mark_alert_as_read(db: Session, alert_id: UUID) -> Optional[Alert]:
    """Marks an alert as READ."""
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        return None
    alert.status = AlertStatus.READ
    alert.read_at = datetime.now(timezone.utc)
    try:
        db.commit()
        db.refresh(alert)
        return alert
    except Exception:
        db.rollback()
        raise


def mark_alert_as_acknowledged(db: Session, alert_id: UUID) -> Optional[Alert]:
    """Marks an alert as ACKNOWLEDGED."""
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        return None
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = datetime.now(timezone.utc)
    try:
        db.commit()
        db.refresh(alert)
        return alert
    except Exception:
        db.rollback()
        raise


def mark_all_alerts_as_read(db: Session) -> int:
    """Marks all UNREAD alerts as READ."""
    now = datetime.now(timezone.utc)
    unread_alerts = db.query(Alert).filter(Alert.status == AlertStatus.UNREAD).all()
    count = len(unread_alerts)
    for alert in unread_alerts:
        alert.status = AlertStatus.READ
        alert.read_at = now
    try:
        db.commit()
        return count
    except Exception:
        db.rollback()
        raise


def bulk_mark_as_read(db: Session, alert_ids: List[UUID]) -> int:
    """Marks a list of alert IDs as READ."""
    if not alert_ids:
        return 0
    now = datetime.now(timezone.utc)
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
    for alert in alerts:
        alert.status = AlertStatus.READ
        alert.read_at = now
    try:
        db.commit()
        return len(alerts)
    except Exception:
        db.rollback()
        raise


def bulk_acknowledge(db: Session, alert_ids: List[UUID]) -> int:
    """Marks a list of alert IDs as ACKNOWLEDGED."""
    if not alert_ids:
        return 0
    now = datetime.now(timezone.utc)
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
    for alert in alerts:
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = now
    try:
        db.commit()
        return len(alerts)
    except Exception:
        db.rollback()
        raise


def get_unread_count(db: Session) -> int:
    """Returns total number of unread alerts."""
    return db.query(Alert).filter(Alert.status == AlertStatus.UNREAD).count()


def create_process_alert(
    db: Session,
    device_id: UUID,
    rule_name: str,
    threat_type: Any,
    severity: Any,
    description: str,
    pid: int,
    process_name: str,
    rule_id: Optional[str] = None,
    mitre_attack: Optional[str] = None,
    confidence: Optional[float] = None
) -> Alert:
    """
    Creates a Threat and an Alert for a behavioral process threat finding.
    """
    sev_str = severity.value if hasattr(severity, "value") else str(severity)
    type_str = threat_type.value if hasattr(threat_type, "value") else str(threat_type)

    from app.models.threat import ThreatSeverity, ThreatType
    threat_sev = ThreatSeverity(sev_str)
    threat_t = ThreatType(type_str)

    mitre_str = f" | MITRE: {mitre_attack}" if mitre_attack else ""
    conf_str = f" | Confidence: {confidence:.0f}%" if confidence else ""
    rule_str = f"[{rule_id}] " if rule_id else ""

    # 1. Create Threat object
    threat = Threat(
        scan_result_id=None,
        threat_type=threat_t,
        severity=threat_sev,
        rule_name=rule_name,
        description=f"{rule_str}[PID {pid} | {process_name}] {description}{mitre_str}{conf_str}"
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)

    # 2. Create Alert object linked to threat.id
    title = f"{sev_str.title()} Process Threat Detected ({process_name})"
    message = f"[PID {pid}] {description}"
    alert_severity = AlertSeverity(sev_str)

    alert = Alert(
        threat_id=threat.id,
        device_id=device_id,
        title=title,
        message=message,
        severity=alert_severity,
        status=AlertStatus.UNREAD
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    try:
        from app.core.websocket_manager import websocket_manager
        created_time = alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat()
        alert_payload = {
            "id": str(alert.id),
            "threat_id": str(threat.id),
            "device_id": str(alert.device_id),
            "device": str(device_id),
            "file": process_name,
            "title": alert.title,
            "message": alert.message,
            "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
            "created_at": created_time,
            "time": created_time,
        }
        websocket_manager.broadcast_alert_sync(alert_payload)
    except Exception:
        pass

    return alert


def create_network_alert(
    db: Session,
    device_id: UUID,
    rule_name: str,
    threat_type: Any,
    severity: Any,
    description: str,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    remote_ip: Optional[str] = None,
    remote_port: Optional[int] = None,
    rule_id: Optional[str] = None,
    mitre_attack: Optional[str] = None,
    confidence: Optional[float] = None
) -> Alert:
    """Creates a Threat and Alert entry for Network Detection Engine findings."""
    sev_str = severity.value if hasattr(severity, "value") else str(severity)
    type_str = threat_type.value if hasattr(threat_type, "value") else str(threat_type)

    from app.models.threat import ThreatSeverity, ThreatType
    threat_sev = ThreatSeverity(sev_str)
    threat_t = ThreatType(type_str)

    mitre_str = f" | MITRE: {mitre_attack}" if mitre_attack else ""
    conf_str = f" | Confidence: {confidence:.0f}%" if confidence else ""
    rule_str = f"[{rule_id}] " if rule_id else ""
    proc_str = f"[PID {pid} | {process_name}] " if process_name else f"[PID {pid}] " if pid else ""
    ip_str = f"[Remote: {remote_ip}:{remote_port}] " if remote_ip else ""

    # 1. Create Threat object
    threat = Threat(
        scan_result_id=None,
        threat_type=threat_t,
        severity=threat_sev,
        rule_name=rule_name,
        description=f"{rule_str}{proc_str}{ip_str}{description}{mitre_str}{conf_str}"
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)

    # 2. Create Alert object linked to threat.id
    target_str = process_name or remote_ip or "Network Socket"
    title = f"{sev_str.title()} Network Threat ({target_str})"
    message = f"{proc_str}{ip_str}{description}"
    alert_severity = AlertSeverity(sev_str)

    alert = Alert(
        threat_id=threat.id,
        device_id=device_id,
        title=title,
        message=message,
        severity=alert_severity,
        status=AlertStatus.UNREAD
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    try:
        from app.core.websocket_manager import websocket_manager
        created_time = alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat()
        alert_payload = {
            "id": str(alert.id),
            "threat_id": str(threat.id),
            "device_id": str(alert.device_id),
            "device": str(device_id),
            "file": target_str,
            "title": alert.title,
            "message": alert.message,
            "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
            "created_at": created_time,
            "time": created_time,
        }
        websocket_manager.broadcast_alert_sync(alert_payload)
    except Exception:
        pass

    return alert


