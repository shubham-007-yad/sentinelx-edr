from typing import List, Optional, Any
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.process_info import ProcessInfo
from app.models.process_audit_log import ProcessAuditLog, ProcessEventType
from app.schemas.process import ProcessInfoCreate
from app.detection.engine import DetectionEngine
from app.services import alert_service

detection_engine = DetectionEngine()


def log_process_audit_event(
    db: Session,
    device_id: UUID,
    pid: int,
    process_name: str,
    event_type: ProcessEventType,
    ppid: Optional[int] = None,
    details: Optional[str] = None
) -> ProcessAuditLog:
    """Logs a process audit event into ProcessAuditLog table."""
    audit_entry = ProcessAuditLog(
        device_id=device_id,
        pid=pid,
        ppid=ppid,
        process_name=process_name,
        event_type=event_type,
        details=details
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry


def get_process_audit_logs(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    event_type: Optional[str] = None,
    pid: Optional[int] = None,
    process_name: Optional[str] = None
) -> List[ProcessAuditLog]:
    """Retrieves process audit event history matching filter parameters."""
    query = db.query(ProcessAuditLog)
    if device_id:
        query = query.filter(ProcessAuditLog.device_id == device_id)
    if event_type:
        query = query.filter(ProcessAuditLog.event_type == event_type)
    if pid:
        query = query.filter(ProcessAuditLog.pid == pid)
    if process_name:
        query = query.filter(ProcessAuditLog.process_name.ilike(f"%{process_name}%"))

    return query.order_by(ProcessAuditLog.timestamp.desc()).offset(skip).limit(limit).all()


def _evaluate_and_alert_process(
    db: Session,
    device_id: UUID,
    proc_data: ProcessInfoCreate,
    parent_name: Optional[str] = None
):
    """Evaluates process telemetry against behavioral rules and generates alerts on match."""
    findings = detection_engine.evaluate_process(
        pid=proc_data.pid,
        name=proc_data.name,
        cmdline=proc_data.cmdline,
        exe_path=proc_data.exe_path,
        username=proc_data.username,
        ppid=proc_data.ppid,
        parent_name=parent_name
    )

    for finding in findings:
        alert_service.create_process_alert(
            db=db,
            device_id=device_id,
            rule_name=finding.rule_name,
            threat_type=finding.threat_type,
            severity=finding.severity,
            description=finding.description,
            pid=finding.pid,
            process_name=finding.process_name,
            rule_id=finding.rule_id,
            mitre_attack=finding.mitre_attack,
            confidence=finding.confidence
        )
        # Log Detection Found Audit Event with Rule ID, MITRE technique, and Confidence
        log_process_audit_event(
            db=db,
            device_id=device_id,
            pid=finding.pid,
            ppid=proc_data.ppid,
            process_name=finding.process_name,
            event_type=ProcessEventType.DETECTION_FOUND,
            details=f"[{finding.rule_id} | {finding.rule_name} | MITRE {finding.mitre_attack} | Confidence {finding.confidence:.0f}%] {finding.description}"
        )


def ingest_processes(
    db: Session,
    device_id: UUID,
    processes_in: List[ProcessInfoCreate],
    clear_existing: bool = True
) -> List[ProcessInfo]:
    """
    Ingests a snapshot of process inventory from an agent.
    If clear_existing is True, removes old process inventory records for the device.
    Evaluates each process against behavioral threat detection rules.
    """
    if clear_existing:
        db.query(ProcessInfo).filter(ProcessInfo.device_id == device_id).delete(synchronize_session=False)

    pid_map = {proc.pid: proc.name for proc in processes_in}

    db_processes = []
    for proc_data in processes_in:
        process_obj = ProcessInfo(
            device_id=device_id,
            pid=proc_data.pid,
            ppid=proc_data.ppid,
            name=proc_data.name,
            exe_path=proc_data.exe_path,
            username=proc_data.username,
            cpu_percent=proc_data.cpu_percent,
            memory_percent=proc_data.memory_percent,
            start_time=proc_data.start_time,
            started_at=proc_data.started_at,
            cmdline=proc_data.cmdline
        )
        db.add(process_obj)
        db_processes.append(process_obj)

        parent_name = pid_map.get(proc_data.ppid) if proc_data.ppid else None
        # Behavioral Rule Evaluation
        _evaluate_and_alert_process(db, device_id, proc_data, parent_name=parent_name)

    db.commit()
    for proc_obj in db_processes:
        db.refresh(proc_obj)

    return db_processes


def get_processes_by_device(
    db: Session,
    device_id: UUID,
    skip: int = 0,
    limit: int = 100,
    name: Optional[str] = None
) -> List[ProcessInfo]:
    """
    Retrieves process inventory for a specific device.
    """
    query = db.query(ProcessInfo).filter(ProcessInfo.device_id == device_id)
    if name:
        query = query.filter(ProcessInfo.name.ilike(f"%{name}%"))
    return query.order_by(ProcessInfo.pid.asc()).offset(skip).limit(limit).all()


def get_all_processes(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    name: Optional[str] = None
) -> List[ProcessInfo]:
    """
    Retrieves process inventory records across all devices.
    """
    query = db.query(ProcessInfo)
    if device_id:
        query = query.filter(ProcessInfo.device_id == device_id)
    if name:
        query = query.filter(ProcessInfo.name.ilike(f"%{name}%"))
    return query.order_by(ProcessInfo.captured_at.desc()).offset(skip).limit(limit).all()


def process_live_events(
    db: Session,
    device_id: UUID,
    events: Any
) -> dict:
    """
    Processes real-time process diff events (created, terminated, long-running).
    Evaluates newly created processes against behavioral threat rules.
    """
    created_pids = []
    terminated_pids = []

    # 1. Process newly created processes
    for proc_data in events.created:
        existing = db.query(ProcessInfo).filter(
            ProcessInfo.device_id == device_id,
            ProcessInfo.pid == proc_data.pid
        ).first()

        if not existing:
            process_obj = ProcessInfo(
                device_id=device_id,
                pid=proc_data.pid,
                ppid=proc_data.ppid,
                name=proc_data.name,
                exe_path=proc_data.exe_path,
                username=proc_data.username,
                cpu_percent=proc_data.cpu_percent,
                memory_percent=proc_data.memory_percent,
                start_time=proc_data.start_time,
                started_at=proc_data.started_at,
                cmdline=proc_data.cmdline
            )
            db.add(process_obj)
            created_pids.append(proc_data.pid)

            # Audit Log Process Started
            log_process_audit_event(
                db=db,
                device_id=device_id,
                pid=proc_data.pid,
                ppid=proc_data.ppid,
                process_name=proc_data.name,
                event_type=ProcessEventType.PROCESS_STARTED,
                details=f"Process '{proc_data.name}' started [User: {proc_data.username or 'N/A'}]"
            )

        # Evaluate newly created process for behavioral threats
        _evaluate_and_alert_process(db, device_id, proc_data)

    # 2. Process terminated processes
    for proc_data in events.terminated:
        db.query(ProcessInfo).filter(
            ProcessInfo.device_id == device_id,
            ProcessInfo.pid == proc_data.pid
        ).delete(synchronize_session=False)
        terminated_pids.append(proc_data.pid)

        # Audit Log Process Terminated
        log_process_audit_event(
            db=db,
            device_id=device_id,
            pid=proc_data.pid,
            ppid=proc_data.ppid,
            process_name=proc_data.name,
            event_type=ProcessEventType.PROCESS_TERMINATED,
            details=f"Process '{proc_data.name}' [PID {proc_data.pid}] terminated."
        )

    db.commit()

    return {
        "message": "Live process events processed successfully",
        "created_count": len(events.created),
        "terminated_count": len(events.terminated),
        "long_running_count": len(events.long_running),
        "total_active": events.total_active
    }


